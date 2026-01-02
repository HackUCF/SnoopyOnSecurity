use super::kmsg::{KernLogReader, KmsgReader};
use super::log::init_logfile;
use super::walk;
use super::{bpf, lkm};
use crate::config::yaml::ScanConfig;
use anyhow::{Context, anyhow};
use log::error;
use std::{convert::Infallible, time::Duration};
use tokio::time::sleep;

async fn scan(
    kmsg: &mut Option<KmsgReader>,
    klog: &mut Option<KernLogReader>,
) -> anyhow::Result<()> {
    let mut errs: Vec<anyhow::Error> = Vec::new();

    macro_rules! step {
        ($label:expr, $expr:expr) => {{
            if let Err(e) = $expr.await.context($label) {
                error!("[scan] {} failed: {:#}", $label, e);
                errs.push(e);
            }
        }};
    }

    if let Some(kmsg) = kmsg {
        step!("kmsg.scan", kmsg.scan());
    }
    if let Some(klog) = klog {
        step!("klog.scan", klog.scan());
    }
    step!("bpf::collect_programs", bpf::collect_programs());
    step!("walk::pid_scan", walk::pid_scan());
    step!("walk::diff_cgroup_vs_proc", walk::diff_cgroup_vs_proc());
    step!("lkm::check_taint", lkm::check_taint());
    step!("lkm::check_sys_module", lkm::check_sys_module());

    if errs.is_empty() {
        Ok(())
    } else {
        Err(anyhow!(
            "scan completed with {} error(s):\n{}",
            errs.len(),
            errs.into_iter()
                .map(|e| format!("  {:#}", e))
                .collect::<Vec<_>>()
                .join("\n")
        ))
    }
}

pub async fn do_singular_scan() -> anyhow::Result<()> {
    let mut kmsg = KmsgReader::new()
        .await
        .inspect_err(|e| error!("Failed to start kmsg reader: {:#}", e))
        .ok();
    let mut klog = KernLogReader::new()
        .await
        .inspect_err(|e| error!("Failed to start kern.log reader: {:#}", e))
        .ok();
    scan(&mut kmsg, &mut klog).await
}

pub async fn do_scans(cfg: ScanConfig) -> anyhow::Result<Infallible> {
    if let Err(e) = init_logfile(&cfg.log_file).await {
        error!(
            "Failed to init scan logfile, continuing without file logging {}",
            e
        );
    }

    let mut kmsg = KmsgReader::new()
        .await
        .inspect_err(|e| error!("Failed to start kmsg reader: {:#}", e))
        .ok();
    let mut klog = KernLogReader::new()
        .await
        .inspect_err(|e| error!("Failed to start kern.log reader: {:#}", e))
        .ok();

    let scan_interval = Duration::from_secs(cfg.poll_interval_secs.unwrap_or(60 * 5));
    loop {
        scan(&mut kmsg, &mut klog).await?;
        sleep(scan_interval).await;
    }
}
