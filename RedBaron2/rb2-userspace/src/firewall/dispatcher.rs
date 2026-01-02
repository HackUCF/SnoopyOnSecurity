use super::common::{EventProducer, EventProducerImpl, FirewallEvent, Handler, HandlerImpl};
use super::event::auditd::AuditdEventProducer;
use super::event::ebpf::EbpfEventProducer;
use super::event::nfq::NfqEventProducer;
use super::handler::kill::KillFirewall;
use super::handler::nfq::NfqFirewall;
use super::sockets;
use crate::config::yaml::{FirewallConfig, HandlerConfig, ProducerConfig};
use crate::log_file;
use anyhow::anyhow;
use log::{debug, error, trace, warn};
use std::collections::HashSet;
use std::convert::Infallible;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs::File;
use tokio::sync::{Mutex, OnceCell, RwLock, mpsc};

pub async fn run_firewall(
    cfg: FirewallConfig,
    btf_file_path: PathBuf,
) -> anyhow::Result<Infallible> {
    let (firewall, producer) = build_firewall(btf_file_path, &cfg)?;
    let firewall: Arc<dyn Handler> = Arc::new(firewall);

    let (tx, rx) = mpsc::channel::<FirewallEvent>(1024);

    clean_active_sockets(&cfg)?;

    let fw_clone = firewall.clone();
    let fw_fut = fw_clone.run();
    let producer_fut = producer.run(tx);
    let dispatch_fut = run_dispatcher(rx, firewall, &cfg);

    #[allow(unreachable_code)]
    tokio::try_join!(fw_fut, producer_fut, dispatch_fut)?;
    unreachable!("Multiple Infallible awaits in try_join");
}

fn build_firewall(
    btf_file_path: PathBuf,
    cfg: &FirewallConfig,
) -> anyhow::Result<(HandlerImpl, EventProducerImpl)> {
    if cfg.producer == ProducerConfig::Nfq && cfg.handler == HandlerConfig::Nfq {
        let nfq_producer = NfqEventProducer::new(btf_file_path, cfg.enforcing);
        let firewall = HandlerImpl::Nfq(NfqFirewall::new(nfq_producer.get_sender()?));
        let producer = EventProducerImpl::Nfq(nfq_producer);
        return Ok((firewall, producer));
    }
    if cfg.producer == ProducerConfig::Nfq && cfg.handler != HandlerConfig::Nfq {
        return Err(anyhow::anyhow!(
            "NFQ producer must be paired with NFQ handler, got {:?}",
            cfg.handler
        ));
    }
    if cfg.handler == HandlerConfig::Nfq && cfg.producer != ProducerConfig::Nfq {
        return Err(anyhow::anyhow!(
            "NFQ handler must be paired with NFQ producer, got {:?}",
            cfg.producer
        ));
    }

    let producer = match &cfg.producer {
        ProducerConfig::Ebpf => EventProducerImpl::Ebpf(EbpfEventProducer { btf_file_path }),
        ProducerConfig::Auditd => {
            EventProducerImpl::Auditd(AuditdEventProducer::with_default_path())
        }
        prod => {
            return Err(anyhow::anyhow!("Unsupported producer: {:?}", prod));
        }
    };
    let handler = match &cfg.handler {
        HandlerConfig::Kill => HandlerImpl::Kill(KillFirewall {}),
        hand => {
            return Err(anyhow::anyhow!("Unsupported handler: {:?}", hand));
        }
    };

    Ok((handler, producer))
}

fn clean_active_sockets(cfg: &FirewallConfig) -> io::Result<()> {
    let paths = &cfg.binary_whitelist;
    sockets::enumerate_udp_sockets(paths, cfg.enforcing)?;
    sockets::enumerate_tcp_sockets(paths, cfg.enforcing)?;
    debug!("Existing sockets parsed by firewall");

    Ok(())
}

/// Will not take into account if the firewall should be enforcing or not here
pub fn make_decision(ev: &FirewallEvent, allow: &HashSet<PathBuf>) -> (bool, Option<PathBuf>) {
    let path = fs::read_link(format!("/proc/{}/exe", ev.pid)).ok();

    let decision = path.as_ref().map(|p| allow.contains(p)).unwrap_or_else(|| {
        warn!("Failed to resolve path for pid {}", ev.pid);
        false
    });

    debug!(
        "Firewall making a decision decision={} on pid={} path={:?} context={}",
        decision,
        ev.pid,
        path,
        ev.context.as_deref().unwrap_or("")
    );

    (decision, path)
}

// dedup duplicate consecutive events in logfile
static EVENT_CACHE: RwLock<Option<(FirewallEvent, Option<PathBuf>)>> = RwLock::const_new(None);

async fn log_event(
    log_file: &Path,
    ev: &FirewallEvent,
    path: Option<PathBuf>,
    dec: bool,
) -> io::Result<()> {
    {
        let e = EVENT_CACHE.read().await;
        if let Some((cached_ev, cached_path)) = e.as_ref()
            && cached_ev == ev
            && cached_path.as_ref() == path.as_ref()
        {
            return Ok(());
        }
    }

    *EVENT_CACHE.write().await = Some((ev.clone(), path.clone()));

    let path_str = path
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "<unknown>".to_string());

    let msg = format!(
        "{} pid={} path={}{}",
        if dec { "ALLOW" } else { "DENY" },
        ev.pid,
        path_str,
        if let Some(context) = &ev.context {
            format!(" context={}", context)
        } else {
            "".to_string()
        },
    );

    trace!("{}", msg);

    // Open file, recreate if needed
    if let Err(e) = write_with_logfile(log_file, &msg).await {
        warn!("Failed to write to log file: {}", e);
    }
    Ok(())
}

static LOG_FD: OnceCell<Mutex<Option<(PathBuf, File)>>> = OnceCell::const_new();

async fn write_with_logfile(log_file: &Path, msg: &str) -> io::Result<()> {
    let lock = LOG_FD.get_or_init(|| async { Mutex::new(None) }).await;
    let mut guard = lock.lock().await;

    let need_open = match guard.as_ref() {
        Some((p, _)) => p.as_path() != log_file,
        None => true,
    };

    if need_open {
        let f = log_file::open_log_file_async(log_file).await?;
        *guard = Some((log_file.to_path_buf(), f));
    }

    let (_, f) = guard.as_mut().expect("just ensured Some");
    log_file::write_log_line_with_timestamp_async(f, log_file, msg).await
}

async fn run_dispatcher(
    mut src: mpsc::Receiver<FirewallEvent>,
    dst_firewall: Arc<dyn Handler>,
    cfg: &FirewallConfig,
) -> anyhow::Result<Infallible> {
    while let Some(ev) = src.recv().await {
        let (dec, path) = make_decision(&ev, &cfg.binary_whitelist);

        let (log_res, handle_res) = tokio::join!(
            log_event(&cfg.log_file, &ev, path, dec),
            dst_firewall.handle_event(&ev, if cfg.enforcing { dec } else { true }),
        );

        if let Err(e) = log_res {
            error!("Unable to log event: {e}");
        }

        if let Err(e) = handle_res {
            error!("Unable to handle firewall event: {e}");
        }
    }

    Err(anyhow!(
        "firewall event producer -> firewall dispatcher closed"
    ))
}
