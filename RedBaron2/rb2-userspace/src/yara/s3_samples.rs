//! Background forwarder that uploads collected YARA malware samples to S3.
//!
//! The forwarder periodically scans `<samples_dir>/<hostname>/` for `.raw`
//! sample files (unstripped binaries written by the YARA handler).
//!
//! The `.uploaded` marker is written immediately after raw upload succeeds,
//! so if the sidecar upload fails, the raw will not be re-uploaded next tick
//!
//! S3 key layout:
//!
//! ```text
//! <hostname>/<sha256>            # original (unstripped) binary sample
//! <hostname>/<sha256>.yara.json  # match metadata
//! ```

use crate::misc::get_hostname;
use crate::tty::object_storage::S3Client;

use log::{debug, error, info};
use std::fs;
use std::path::Path;
use std::thread::sleep;
use std::time::Duration;

/// Default poll interval for the sample forwarder (60 seconds).
const DEFAULT_POLL_INTERVAL_SECS: u64 = 60;

/// Run the S3 sample forwarder loop. This function blocks the calling thread
/// and never returns under normal operation.
pub fn run(s3: S3Client, samples_dir: &Path, poll_interval_secs: Option<u64>) {
    let interval = Duration::from_secs(poll_interval_secs.unwrap_or(DEFAULT_POLL_INTERVAL_SECS));
    let hostname = get_hostname().unwrap_or_else(|| "unknown".to_string());
    let host_dir = samples_dir.join(&hostname);

    info!(
        "YARA S3 sample forwarder started (dir={}, interval={}s)",
        host_dir.display(),
        interval.as_secs()
    );

    loop {
        sleep(interval);

        if let Err(e) = forward_once(&s3, &host_dir, &hostname) {
            error!("YARA S3 sample forward tick failed: {e:#}");
        }
    }
}

/// One forward pass: scan the host directory for un-uploaded samples and push
/// them to S3.
fn forward_once(s3: &S3Client, host_dir: &Path, hostname: &str) -> anyhow::Result<()> {
    let entries = match fs::read_dir(host_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Directory doesn't exist yet — nothing to upload.
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();

        // Only consider <sha256>.raw files produced by the YARA handler.
        let hash = match name.strip_suffix(".raw") {
            Some(h) if h.len() == 64 && !h.contains('.') => h.to_string(),
            _ => continue,
        };

        let raw_path = entry.path();
        let sidecar_path = host_dir.join(format!("{hash}.yara.json"));
        let uploaded_marker = host_dir.join(format!("{hash}.uploaded"));

        // Skip if already uploaded. Clean up leftover .raw file if marker exists.
        if uploaded_marker.exists() {
            let _ = fs::remove_file(&raw_path);
            continue;
        }

        let sample_key = format!("{hostname}/{hash}");
        debug!("Uploading sample {hash} to S3 (streaming multipart)");

        // Upload the unstripped binary sample using multipart streaming (bounded memory)
        // with automatic retry handled by S3Client (if implemented there).
        if let Err(e) = s3.put_object_multipart_file(&sample_key, &raw_path) {
            error!("S3 upload failed for sample {hash}: {e:#}; will retry next tick");
            continue;
        }

        // IMPORTANT: Write marker immediately after raw upload succeeds.
        // This prevents duplicate raw uploads if sidecar upload fails later.
        let marker_body = format!("{hash}\n");
        if let Err(e) = fs::write(&uploaded_marker, marker_body.as_bytes()) {
            error!(
                "Failed to write uploaded marker {}: {e}",
                uploaded_marker.display()
            );
            // Don't remove raw if we couldn't persist the marker (otherwise we'd lose retry state).
            continue;
        }

        // Remove the .raw file now that raw upload + marker succeeded.
        if let Err(e) = fs::remove_file(&raw_path) {
            debug!("Failed to remove raw file {}: {e}", raw_path.display());
        }

        info!(
            "Successfully uploaded sample {} to S3 (key={})",
            hash, sample_key
        );

        // Upload the sidecar JSON (small file, plain PutObject with retry).
        // If this fails, next tick will retry only the sidecar because `.uploaded` exists.
        if sidecar_path.exists() {
            let sidecar_data = fs::read(&sidecar_path)?;
            let sidecar_key = format!("{hostname}/{hash}.yara.json");

            if let Err(e) = s3.put_object(&sidecar_key, &sidecar_data) {
                error!(
                    "S3 upload failed for sidecar {hash}.yara.json: {e:#}; will retry next tick"
                );
                continue;
            }

            info!(
                "Successfully uploaded sidecar {}.yara.json to S3 bucket",
                hash
            );
        }
    }

    Ok(())
}
