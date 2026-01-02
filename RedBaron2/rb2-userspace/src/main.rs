use log::{error, info, warn};
use rb2_userspace::{
    btf::fetch_btf,
    config::{self, dropper, systemd},
    firewall::dispatcher,
    ingest,
    misc::scans,
    process::process_monitor,
    yara,
};
use std::{env, io};
use tokio::runtime::Runtime;
use yara::yara_scan::full_scan_all;

#[rustfmt::skip]
use tokio::signal;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    config::logger::init();
    let args = env::args().skip(1).peekable();
    for arg in args {
        match arg.as_str() {
            "-i" | "--install" => {
                systemd::install_systemd_unit()?;
                info!("Systemd unit installed, exiting");
                return Ok(());
            }
            "-s" | "--systemd" => {
                systemd::install_systemd_unit()?;
                info!("Systemd unit installed, exiting");
                return Ok(());
            }
            "-c" | "--config" => {
                info!("Writing config to rb2.yaml");
                dropper::write_config_in_cwd("rb2.yaml")?;
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

    let btf_file_path = fetch_btf::get_btf_file()?;

    info!(
        "BTF file loading from: {}",
        btf_file_path.to_str().unwrap_or("UNKNOWN")
    );

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let _ = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };

    if let Some(ref firewall_cfg) = cfg.firewall {
        let cloned_btf_path = btf_file_path.clone();
        let cloned_firewall_cfg = firewall_cfg.clone();
        tokio::spawn(async move {
            let Err(e) = dispatcher::run_firewall(cloned_firewall_cfg, cloned_btf_path).await;
            error!("firewall failed {e}");
        });
    } else {
        info!("Firewall feature disabled via config");
    }

    if let Some(ref process_cfg) = cfg.process {
        let cloned_btf_path = btf_file_path.clone();
        let cloned_process_cfg = process_cfg.clone();
        tokio::spawn(async move {
            let Err(e) = process_monitor::run(cloned_btf_path, cloned_process_cfg).await;
            error!("ebpf process monitor failed {}", e);
        });
    } else {
        info!("Process monitor feature disabled via config");
    }

    if let Some(ref yara_cfg) = cfg.yara {
        if let Some(max_bytes) = yara_cfg.max_scan_bytes_per_rule {
            yara::yara_scan::set_max_scan_bytes_per_rule(max_bytes as usize);
        }
        let cfg = yara_cfg.clone();
        tokio::task::spawn_blocking(move || {
            if let Err(e) = yara::yara_scan::yara_init_scan(cfg) {
                error!("YARA scanning failed: {}", e);
            }
        });
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

    let ctrl_c = signal::ctrl_c();
    info!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    info!("Exiting...");
    std::process::exit(0);
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
    let cfg = config::yaml::get_config();

    let (rules, log_file) = match cfg.as_ref().ok().and_then(|c| c.yara.as_ref()) {
        Some(y) => (
            yara::yara_scan::build_rules(y.disable_bundled_rules, &y.rules_dir)?,
            y.log_file.as_path(),
        ),
        None => {
            if let Err(e) = &cfg {
                warn!(
                    "Failed to initialize config, defaulting to built-in rules: {}",
                    e
                );
            } else {
                warn!("yara not present/enabled in config, defaulting to built-in rules");
            }

            (
                yara::yara_scan::build_rules(false, &None)?,
                std::path::Path::new("/dev/null"),
            )
        }
    };

    let mut scanner = yara_x::Scanner::new(&rules);

    full_scan_all(
        std::process::id() as i32,
        &mut scanner,
        &mut std::collections::HashMap::new(),
        &mut std::collections::HashSet::new(),
        &[],
        log_file,
    );

    Ok(())
}
