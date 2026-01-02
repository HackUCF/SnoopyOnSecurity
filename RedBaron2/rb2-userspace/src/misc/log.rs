use crate::log_file::{open_log_file_async, write_log_line_with_timestamp_async};
use anyhow::Context;
use log::{info, warn};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use tokio::sync::Mutex;

static DETECT_F: OnceLock<Mutex<Option<(tokio::fs::File, PathBuf)>>> = OnceLock::new();

pub async fn init_logfile(path: &Path) -> anyhow::Result<()> {
    let f = open_log_file_async(path)
        .await
        .with_context(|| format!("open detection log {}", path.display()))?;

    if DETECT_F
        .set(Mutex::new(Some((f, path.to_path_buf()))))
        .is_err()
    {
        warn!("Only setup the scan detection log file once!");
    }

    Ok(())
}

/// info logs via log crate
/// logs string to log file if detection log file has been setup
pub async fn log_detection(line: &str) {
    info!("{}", line);
    if let Some(m) = DETECT_F.get() {
        let mut guard = m.lock().await;

        // Try to write, and if it fails, attempt to recreate the file
        // The write function will check if file exists and recreate if needed
        if let Some((f, path)) = guard.as_mut()
            && let Err(e) = write_log_line_with_timestamp_async(f, path, line).await
        {
            warn!("Failed to write to scan log file: {}", e);
            // If write failed, try to recreate the file handle
            match open_log_file_async(path).await {
                Ok(new_file) => {
                    *guard = Some((new_file, path.clone()));
                    // Retry write with new file
                    if let Some((f, path)) = guard.as_mut()
                        && let Err(retry_err) =
                            write_log_line_with_timestamp_async(f, path, line).await
                    {
                        warn!("Failed to write to recreated scan log file: {}", retry_err);
                    }
                }
                Err(recreate_err) => {
                    warn!("Failed to recreate scan log file: {}", recreate_err);
                }
            }
        }
    }
}
