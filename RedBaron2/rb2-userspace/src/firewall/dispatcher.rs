use super::event::ebpf::EbpfEventProducer;
use super::event::nfq::NfqEventProducer;
use super::handler::kill::KillFirewall;
use super::handler::nfq::NfqFirewall;
use super::sockets;
use super::{EventProducer, EventProducerImpl, FirewallEvent, Handler, HandlerImpl};
use crate::config::yaml::{FirewallConfig, HandlerConfig, ProducerConfig};
use crate::misc::{get_hostname, get_machine_id};
use anyhow::anyhow;
use chrono::SecondsFormat;
use log::{debug, error, info, trace, warn};
use std::collections::HashSet;
use std::convert::Infallible;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc};

pub async fn run_firewall(
    cfg: FirewallConfig,
    btf_file_path: PathBuf,
) -> anyhow::Result<Infallible> {
    let (firewall, producer) = build_firewall(btf_file_path, &cfg)?;
    let firewall: Arc<dyn Handler> = Arc::new(firewall);

    let (tx, rx) = mpsc::channel::<FirewallEvent>(1024);

    clean_active_sockets(&cfg).await;

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
        prod => {
            return Err(anyhow::anyhow!("Unsupported producer: {:?}", prod));
        }
    };
    let handler = match &cfg.handler {
        HandlerConfig::Kill => HandlerImpl::Kill(KillFirewall::default()),
        hand => {
            return Err(anyhow::anyhow!("Unsupported handler: {:?}", hand));
        }
    };

    Ok((handler, producer))
}

async fn clean_active_sockets(cfg: &FirewallConfig) {
    let paths = &cfg.binary_whitelist;

    let mut offenders = match sockets::enumerate_udp_sockets(paths, cfg.enforcing).await {
        Ok(o) => o,
        Err(e) => {
            warn!("Failed to enumerate UDP sockets: {}", e);
            Vec::new()
        }
    };
    match sockets::enumerate_tcp_sockets(paths, cfg.enforcing).await {
        Ok(o) => offenders.extend(o),
        Err(e) => warn!("Failed to enumerate TCP sockets: {}", e),
    }

    for o in offenders {
        let ev = FirewallEvent {
            pid: o.pid,
            comm: None,
            ip: Some(o.ip.to_string()),
            dport: Some(o.port),
            op: Some("existing_socket".to_string()),
        };

        log_event(&ev, Some(PathBuf::from(o.exe_path)), false, cfg.enforcing).await;
    }

    debug!("Existing sockets parsed by firewall");
}

/// Will not take into account if the firewall should be enforcing or not here
pub fn make_decision(ev: &FirewallEvent, allow: &HashSet<PathBuf>) -> (bool, Option<PathBuf>) {
    let path = fs::read_link(format!("/proc/{}/exe", ev.pid)).ok();

    let decision = path.as_ref().map(|p| allow.contains(p)).unwrap_or_else(|| {
        // only make a debug message bc kill handler will be racy with new events
        debug!("Failed to resolve path for pid {}", ev.pid);
        false
    });

    debug!(
        "Firewall making a decision decision={} on pid={} path={:?}",
        decision, ev.pid, path,
    );

    (decision, path)
}

// dedup duplicate consecutive events in logfile
static EVENT_CACHE: RwLock<Option<(FirewallEvent, Option<PathBuf>)>> = RwLock::const_new(None);

async fn log_event(ev: &FirewallEvent, path: Option<PathBuf>, dec: bool, enforcing: bool) {
    // path we'll use for logging + caching.
    let mut saved_path = None;

    {
        let e = EVENT_CACHE.read().await;
        if let Some((cached_ev, cached_path)) = e.as_ref() {
            // dedup event check
            if cached_ev == ev && cached_path.as_ref() == path.as_ref() {
                return;
            }

            // partial match to backfill path when current is None
            if path.is_none() && cached_ev.pid == ev.pid && cached_ev.comm == ev.comm {
                saved_path = cached_path.clone();
            }
        }
    }

    let eff_path = if saved_path.is_some() {
        saved_path
    } else {
        path
    };
    *EVENT_CACHE.write().await = Some((ev.clone(), eff_path.clone()));

    let path_str = eff_path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "<unknown>".to_string());

    let ts = chrono::Local::now().to_rfc3339_opts(SecondsFormat::Millis, true);

    let json = serde_json::json!({
        "timestamp": ts,
        "decision": if dec { "ALLOW" } else { "DENY" },
        "enforcing": enforcing,
        "pid": ev.pid,
        "path": path_str,
        "comm": ev.comm,
        "ip": ev.ip,
        "port": ev.dport,
        "op": ev.op,
        "host_name": get_hostname(),
        "host_id": get_machine_id(),
    });

    trace!(
        "firewall {} pid={} path={} ip={:?} port={:?}",
        if dec { "ALLOW" } else { "DENY" },
        ev.pid,
        path_str,
        ev.ip,
        ev.dport
    );

    info!(target: "rb2_firewall", "{}", json);
}

async fn run_dispatcher(
    mut src: mpsc::Receiver<FirewallEvent>,
    dst_firewall: Arc<dyn Handler>,
    cfg: &FirewallConfig,
) -> anyhow::Result<Infallible> {
    while let Some(ev) = src.recv().await {
        let (dec, path) = make_decision(&ev, &cfg.binary_whitelist);

        let handle_res = dst_firewall.handle_event(&ev, if cfg.enforcing { dec } else { true });

        log_event(&ev, path, dec, cfg.enforcing).await;

        if let Err(e) = handle_res.await {
            error!("Unable to handle firewall event: {e}");
        }
    }

    Err(anyhow!(
        "firewall event producer -> firewall dispatcher closed"
    ))
}
