use super::kmsg::{KernLogReader, KmsgReader};
use super::walk;
use super::{bpf, lkm, preload};
use crate::config::yaml::ScanConfig;
use anyhow::{Context, anyhow};
use log::{debug, error};
use std::{convert::Infallible, time::Duration};
use tokio::time::sleep;

async fn scan(
    kmsg: &mut Option<KmsgReader>,
    klog: &mut Option<KernLogReader>,
    check_own_bpf: bool,
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
    if check_own_bpf {
        step!("bpf::own_bpf_correct", bpf::check_own_bpf());
    }
    step!("bpf::collect_programs", bpf::collect_programs());
    step!("walk::pid_scan", walk::pid_scan());
    step!("walk::diff_cgroup_vs_proc", walk::diff_cgroup_vs_proc());
    step!("lkm::check_taint", lkm::check_taint());
    step!("lkm::check_sys_module", lkm::check_sys_module());
    step!("preload::scan", preload::scan());

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
        .inspect_err(|e| debug!("Failed to start kern.log reader: {:#}", e))
        .ok();
    scan(&mut kmsg, &mut klog, false).await
}

pub async fn do_scans(cfg: ScanConfig) -> anyhow::Result<Infallible> {
    let mut kmsg = KmsgReader::new()
        .await
        .inspect_err(|e| error!("Failed to start kmsg reader: {:#}", e))
        .ok();
    let mut klog = KernLogReader::new()
        .await
        .inspect_err(|e| debug!("Failed to start kern.log reader: {:#}", e))
        .ok();

    let scan_interval = Duration::from_secs(cfg.poll_interval_secs.unwrap_or(60 * 5));
    let mut first_scan = true;
    loop {
        scan(&mut kmsg, &mut klog, !first_scan).await?;
        first_scan = false;
        sleep(scan_interval).await;
    }
}
