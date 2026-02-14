use log::{error, info, warn};
use rb2_userspace::{
    btf::fetch_btf,
    config::{self, dropper, systemd, yaml::AppConfig},
    firewall::dispatcher,
    ingest, integrity,
    misc::scans,
    process::process_monitor,
    tty::{self, object_storage::S3Client},
    yara,
};
use std::{env, io};
use tokio::{
    runtime::Runtime,
    signal::unix::{SignalKind, signal},
    sync::watch,
    task::JoinHandle,
};
use yara::yara_scan::full_scan_all;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    config::logger::init();
    let args = env::args().skip(1).peekable();
    for arg in args {
        match arg.as_str() {
            "-c" | "--config" => {
                let path = dropper::write_config("rb2.yaml")?;
                info!("Written config to {:?}", path);
                return Ok(());
            }
            "-s" | "--systemd" => {
                systemd::install_systemd_unit()?;
                info!("Systemd unit installed, exiting");
                return Ok(());
            }
            "-r" | "--rootkit" => {
                info!("Running a singular rootkit scan");
                let rt = Runtime::new().unwrap();
                return rt.block_on(scans::do_singular_scan()).map_err(|e| e.into());
            }
            "-y" | "--yara" => {
                info!("Running a singular full yara scan");
                return Ok(yara_scan()?);
            }
            "-p" | "--integrity" => {
                info!("Running a singular package integrity scan (without conffiles)");
                return Ok(package_integrity_scan(false)?);
            }
            "-pa" | "--integrity_all" => {
                info!("Running a singular package integrity scan (including conffiles)");
                return Ok(package_integrity_scan(true)?);
            }
            "-d" | "--daemonize" => {
                info!("Daemonizing");
                orphan_self()?;
            }
            s => {
                warn!("Unknown arg {s}");
            }
        }
    }

    tokio_main()
}

#[tokio::main]
async fn tokio_main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize config from RB2_CONFIG env var
    let cfg = match config::yaml::get_config() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to initialize config: {}", e);
            std::process::exit(1);
        }
    };

    // now that config is loaded, wire up log4rs rolling-file appenders
    config::logger::add_file_appenders(
        cfg.firewall.as_ref().map(|c| c.log_file.as_path()),
        cfg.process.as_ref().map(|c| c.log_file.as_path()),
        cfg.process.as_ref().map(|c| c.alert_log_file.as_path()),
        cfg.yara.as_ref().map(|c| c.log_file.as_path()),
        cfg.scan.as_ref().map(|c| c.log_file.as_path()),
        cfg.logging.rollover_size_bytes,
        cfg.logging.rollover_count,
    );

    // Try to fetch/locate btf for ebpf
    let btf_file_path = match fetch_btf::get_btf_file() {
        Ok(path) => {
            info!(
                "BTF file loading from: {}",
                path.to_str().unwrap_or("UNKNOWN")
            );
            Some(path)
        }
        Err(e) => {
            warn!(
                "BTF file could not be found/fetched: {}. Disabling all eBPF-dependent features.",
                e
            );
            None
        }
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut handles: Vec<JoinHandle<()>> = Vec::new();

    if let Some(ref btf_path) = btf_file_path {
        handles = spawn_ebpf_tasks(cfg, btf_path, shutdown_rx.clone());
    }

    if let Some(ref yara_cfg) = cfg.yara {
        if let Some(max_bytes) = yara_cfg.max_scan_bytes_per_rule {
            yara::yara_scan::set_max_scan_bytes_per_rule(max_bytes as usize);
        }

        'spawn_s3_forwarder: {
            if !yara_cfg.actions.forward_to_s3 {
                break 'spawn_s3_forwarder;
            }

            let Some(ref os_cfg) = cfg.object_storage else {
                warn!("yara.forward_to_s3 is true but object_storage is not configured");
                break 'spawn_s3_forwarder;
            };

            let base_client = match S3Client::new(os_cfg) {
                Ok(c) => c,
                Err(e) => {
                    error!("Failed to create S3 client for sample forwarding: {e}");
                    break 'spawn_s3_forwarder;
                }
            };

            // Dedicated samples bucket if configured, else fall back to main bucket.
            let samples_client = os_cfg
                .bucket_samples
                .as_deref()
                .and_then(|bucket_name| match base_client.with_bucket(bucket_name) {
                    Ok(c) => Some(c),
                    Err(e) => {
                        error!(
                            "Failed to create S3 client for samples bucket '{}': {e}",
                            bucket_name
                        );
                        None
                    }
                })
                .unwrap_or(base_client);

            let samples_dir = yara_cfg.samples_dir.clone();
            std::thread::spawn(move || {
                yara::s3_samples::run(samples_client, &samples_dir, None);
            });
            info!("YARA S3 sample forwarder spawned");
        }

        if let Err(e) = yara::yara_init_scan(yara_cfg) {
            error!("Yara scanning failed to start {}", e);
        }
    } else {
        info!("YARA feature disabled via config");
    }

    if let Some(ref scan_cfg) = cfg.scan {
        let cfg = scan_cfg.clone();
        tokio::spawn(async move {
            let Err(e) = scans::do_scans(cfg).await;
            error!("misc scans failed {e}");
        });
    } else {
        info!("Misc scans disabled via config");
    }

    if let Some(ref ingestor_cfg) = cfg.ingestor {
        let cfg = ingestor_cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = ingest::run_ingestor(cfg).await {
                error!("Log ingestor failed: {}", e);
            }
        });
    } else {
        info!("Log ingestor disabled via config");
    }

    if under_systemd() {
        sd_ready();
        spawn_systemd_watchdog();
    }

    info!("Waiting for Ctrl-C...");
    shutdown_signal().await;
    info!("Shutdown signal received, ending...");

    let _ = shutdown_tx.send(true);

    for h in handles {
        if let Err(e) = h.await {
            error!("Task join failed: {e}");
        }
    }

    Ok(())
}

async fn shutdown_signal() {
    let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = sigterm.recv() => {}
    }
}

fn spawn_ebpf_tasks(
    cfg: &AppConfig,
    btf_file_path: &std::path::Path,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Vec<JoinHandle<()>> {
    let mut handles = Vec::new();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let _ = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };

    if let Some(ref firewall_cfg) = cfg.firewall {
        let cloned_btf_path = btf_file_path.to_path_buf();
        let cloned_firewall_cfg = firewall_cfg.clone();
        tokio::spawn(async move {
            let Err(e) = dispatcher::run_firewall(cloned_firewall_cfg, cloned_btf_path).await;
            error!("firewall failed {e}");
        });
    } else {
        info!("Firewall feature disabled via config");
    }

    if let Some(ref process_cfg) = cfg.process {
        let cloned_btf_path = btf_file_path.to_path_buf();
        let cloned_process_cfg = process_cfg.clone();
        tokio::spawn(async move {
            let Err(e) = process_monitor::run(cloned_btf_path, cloned_process_cfg).await;
            error!("ebpf process monitor failed {}", e);
        });
    } else {
        info!("Process monitor feature disabled via config");
    }

    if let Some(ref tty_cfg) = cfg.tty {
        let cloned_btf_path = btf_file_path.to_path_buf();
        let cloned_tty_cfg = tty_cfg.clone();
        let cloned_os_cfg = cfg.object_storage.clone();
        let mut shutdown_rx = shutdown_rx.clone();

        handles.push(tokio::spawn(async move {
            let shutdown = async move {
                while !*shutdown_rx.borrow() {
                    if shutdown_rx.changed().await.is_err() {
                        break;
                    }
                }
            };

            if let Err(e) = tty::run(cloned_btf_path, cloned_tty_cfg, cloned_os_cfg, shutdown).await
            {
                error!("ebpf tty session monitor failed {:?}", e);
            }
        }));
    } else {
        info!("Tty session monitor feature disabled via config");
    }

    handles
}

fn orphan_self() -> io::Result<()> {
    use std::ptr;

    use libc::{
        O_RDWR, SIG_IGN, SIGHUP, SIGPIPE, c_int, dup2, fork, open, setsid, signal, waitpid,
    };

    fn cvt(ret: c_int) -> io::Result<c_int> {
        if ret == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(ret)
        }
    }

    // Ignore some signals
    unsafe {
        signal(SIGHUP, SIG_IGN);
        signal(SIGPIPE, SIG_IGN);
    }

    // fork and exit as parent
    let pid = unsafe { fork() };
    cvt(pid)?;
    if pid > 0 {
        unsafe { waitpid(pid, ptr::null_mut(), 0) };
        std::process::exit(0);
    }

    // Become session leader
    cvt(unsafe { setsid() })?;

    // fork a grandchild and exit parent to avoid reacquiring a controlling terminal
    let pid2 = unsafe { fork() };
    cvt(pid2)?;
    if pid2 > 0 {
        std::process::exit(0);
    }

    // Redirect stdio to /dev/null
    let devnull_fd = unsafe { open(c"/dev/null".as_ptr(), O_RDWR) };
    cvt(devnull_fd)?;
    for target in [0, 1, 2] {
        let _ = cvt(unsafe { dup2(devnull_fd, target) });
    }

    Ok(())
}

fn yara_scan() -> anyhow::Result<()> {
    // Build a YaraConfig (either from config, or a sane default)
    let cfg = match config::yaml::get_config() {
        Ok(app) => {
            if let Some(y) = app.yara.as_ref() {
                y.clone()
            } else {
                warn!("yara not present/enabled in config, defaulting to built-in rules");
                crate::config::yaml::YaraConfig {
                    rules_dir: None,
                    log_file: std::path::PathBuf::from("/var/log/rb2/yara"),
                    max_scan_bytes_per_rule: None,
                    poll_interval_secs: None,
                    full_scan_interval_secs: None,
                    disabled_rules: std::collections::HashSet::new(),
                    disable_bundled_rules: false,
                    actions: crate::config::yaml::YaraActions {
                        alert: true,
                        kill: true,
                        move_sample: false,
                        forward_to_s3: false,
                    },
                    samples_dir: std::path::PathBuf::from("/var/lib/rb2/samples"),
                    fanotify_enabled: false,
                }
            }
        }
        Err(e) => {
            warn!(
                "Failed to initialize config, defaulting to built-in rules: {}",
                e
            );
            crate::config::yaml::YaraConfig {
                rules_dir: None,
                log_file: std::path::PathBuf::from("/var/log/rb2/yara"),
                max_scan_bytes_per_rule: None,
                poll_interval_secs: None,
                full_scan_interval_secs: None,
                disabled_rules: std::collections::HashSet::new(),
                disable_bundled_rules: false,
                actions: crate::config::yaml::YaraActions {
                    alert: true,
                    kill: true,
                    move_sample: false,
                    forward_to_s3: false,
                },
                samples_dir: std::path::PathBuf::from("/var/lib/rb2/samples"),
                fanotify_enabled: false,
            }
        }
    };

    let rules = yara::build_rules(cfg.disable_bundled_rules, &cfg.rules_dir)?;
    let mut scanner = yara_x::blocks::Scanner::new(&rules);

    full_scan_all(
        std::process::id() as i32,
        &mut scanner,
        &mut std::collections::HashMap::new(),
        &mut std::collections::HashSet::new(),
        &mut Vec::new(),
        &cfg,
    );

    Ok(())
}

fn package_integrity_scan(scan_conffiles: bool) -> anyhow::Result<()> {
    use anyhow::Context;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building tokio runtime failed")?;

    rt.block_on(integrity::single_scan(scan_conffiles))
        .context("integrity single_scan failed")?;

    Ok(())
}

fn under_systemd() -> bool {
    std::env::var_os("NOTIFY_SOCKET").is_some()
}

fn spawn_systemd_watchdog() {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            interval.tick().await;
            let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Watchdog]);
        }
    });
}

fn sd_ready() {
    let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Ready]);
}
