//! S3/MinIO forwarder for TTY session blobs.

use super::object_storage::S3Client;
use super::sqlite_store::{BlobRow, TtyDb};
use crate::misc::get_hostname;

use log::{debug, error};
use std::collections::HashMap;
use tokio::time::{Duration, interval};

/// Run the S3 forwarding loop. This function never returns under normal operation.
pub async fn run(s3: S3Client, db: TtyDb, interval_secs: u64) {
    debug!("TTY S3 forwarder started (interval={}s)", interval_secs);

    let mut tick = interval(Duration::from_secs(interval_secs));

    loop {
        tick.tick().await;

        if let Err(e) = forward_once(&s3, &db).await {
            error!("TTY S3 forward tick failed: {e:#}");
        }
    }
}

/// One forward pass: read un-forwarded blobs, upload per-session, mark done.
async fn forward_once(s3: &S3Client, db: &TtyDb) -> anyhow::Result<()> {
    let rows = db.unforwarded_blobs().await?;
    if rows.is_empty() {
        return Ok(());
    }

    // Group by session_id.
    let mut grouped: HashMap<String, Vec<BlobRow>> = HashMap::new();
    for row in rows {
        grouped.entry(row.session_id.clone()).or_default().push(row);
    }

    let hostname = get_hostname().unwrap_or_else(|| "unknown".to_string());

    for (session_id, blobs) in &grouped {
        let last_ts = blobs.last().map(|b| b.created_at).unwrap_or(0);

        // Concatenate all blob data for this batch
        let total_size: usize = blobs.iter().map(|b| b.data.len()).sum();
        let mut payload = Vec::with_capacity(total_size);
        for blob in blobs {
            payload.extend_from_slice(&blob.data);
        }

        // S3 key: {hostname}/{session_uuid}/{session_uuid}-{unix_ts}.cast.age
        let key = format!("{hostname}/{session_id}/{session_id}-{last_ts}.cast.age");

        match s3.put_object(&key, &payload) {
            Ok(()) => {
                let ids: Vec<String> = blobs.iter().map(|b| b.blob_id.clone()).collect();
                if let Err(e) = db.mark_forwarded(&ids).await {
                    error!("Failed to mark {} blobs as forwarded: {e:#}", ids.len());
                } else {
                    debug!(
                        "Forwarded {} blobs ({} bytes) for session {} -> s3://{}",
                        ids.len(),
                        payload.len(),
                        session_id,
                        key,
                    );
                }
            }
            Err(e) => {
                error!(
                    "S3 upload failed for session {} (key={key}): {e:#}; will retry next tick",
                    session_id,
                );
            }
        }
    }

    Ok(())
}
