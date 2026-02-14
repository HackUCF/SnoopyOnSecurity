mod openobserve;
mod reader;

use async_trait::async_trait;

pub use openobserve::OpenObserveIngestor;
pub use reader::{LogRecord, read_logs};

#[async_trait]
pub trait Ingestor: Send + Sync {
    async fn ingest(&self, records: &[LogRecord]) -> anyhow::Result<()>;
    fn name(&self) -> &str;
}

pub async fn run_ingestor(cfg: crate::config::yaml::IngestorConfig) -> anyhow::Result<()> {
    use crate::config::yaml;
    use log::{error, info, warn};
    use std::sync::Arc;
    use std::time::Instant;
    use tokio::time::{Duration, sleep};

    let ingestor: Arc<dyn Ingestor> = match cfg.ingestor_type.as_str() {
        "openobserve" => {
            let openobserve_cfg = cfg
                .openobserve
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("openobserve config missing"))?;
            Arc::new(OpenObserveIngestor::new(openobserve_cfg.clone())?)
        }
        other => {
            return Err(anyhow::anyhow!("Unknown ingestor type: {}", other));
        }
    };

    info!("Starting log ingestor: {}", ingestor.name());

    let poll_interval = Duration::from_secs(cfg.poll_interval_secs);
    let rollover_size = cfg.log_rollover_size_mb.saturating_mul(1024 * 1024); // Convert MB to bytes

    // Get log file paths from config
    let cfg_ref = yaml::get_config().map_err(|e| anyhow::anyhow!("Failed to get config: {}", e))?;
    let mut log_files = Vec::new();

    if let Some(ref firewall_cfg) = cfg_ref.firewall {
        log_files.push(("firewall".to_string(), firewall_cfg.log_file.clone()));
    }
    if let Some(ref process_cfg) = cfg_ref.process {
        log_files.push(("process".to_string(), process_cfg.log_file.clone()));
    }
    if let Some(ref yara_cfg) = cfg_ref.yara {
        log_files.push(("yara".to_string(), yara_cfg.log_file.clone()));
    }
    if let Some(ref scan_cfg) = cfg_ref.scan {
        log_files.push(("scan".to_string(), scan_cfg.log_file.clone()));
    }
    if let Some(ref process_cfg) = cfg_ref.process {
        log_files.push(("alerts".to_string(), process_cfg.alert_log_file.clone()));
    }

    let mut all_records = Vec::new();
    let mut records_sent_this_interval: u64 = 0;
    let mut last_stats_log = Instant::now();
    let stats_interval = Duration::from_secs(cfg.stats_interval_secs);

    loop {
        for (log_type, log_path) in &log_files {
            if let Err(e) = read_logs(log_path, log_type, rollover_size, &mut all_records).await {
                warn!(
                    "Failed to read logs for ingestor from {}: {}",
                    log_path.display(),
                    e
                );
            }
        }

        if !all_records.is_empty()
            && let Err(e) = ingestor.ingest(&all_records).await
        {
            error!("Failed to ingest logs: {}", e);
            if all_records.len() > 4096 {
                error!(
                    "SOME LOGS WILL NOT BE SENT, (clear offset file and restart to resend all logs)"
                );
                all_records.clear();
            }
        } else {
            if !all_records.is_empty() {
                records_sent_this_interval += all_records.len() as u64;
            }
            all_records.clear();
        }

        if cfg.stats_interval_secs > 0 && last_stats_log.elapsed() >= stats_interval {
            if records_sent_this_interval > 0 {
                info!(
                    "Ingested {} records to {} in the last {}s",
                    records_sent_this_interval,
                    ingestor.name(),
                    cfg.stats_interval_secs
                );
            }
            records_sent_this_interval = 0;
            last_stats_log = Instant::now();
        }

        sleep(poll_interval).await;
    }
}
