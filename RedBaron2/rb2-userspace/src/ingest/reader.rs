use anyhow::Context;
use chrono::SecondsFormat;
use log::trace;
use serde_json::{Value, json};
use std::io;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};

#[derive(Debug, Clone)]
pub struct LogRecord {
    pub log_type: String,
    pub record: Value,
}

/// Get the offset file path for a log file (hidden dot-file)
/// If log_file has no usable parent component, places it in the CWD
fn offset_path(log_file: &Path) -> PathBuf {
    let parent = log_file
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    let name = log_file
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("log");

    parent.join(format!(".{name}.offset"))
}

/// Read the last offset from the offset file
async fn get_offset(offset_path: &Path) -> io::Result<u64> {
    match fs::read_to_string(offset_path).await {
        Ok(content) => content
            .trim()
            .parse::<u64>()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(e),
    }
}

/// Save the current offset to the offset file
async fn save_offset(offset_path: &Path, offset: u64) -> io::Result<()> {
    fs::write(offset_path, offset.to_string()).await
}

/// Read new log lines from path starting at start_offset, pushing records into all_records
/// Returns the new offset (EOF position).
async fn read_from_offset_into(
    path: &Path,
    log_type: &str,
    start_offset: u64,
    all_records: &mut Vec<LogRecord>,
) -> anyhow::Result<u64> {
    let metadata = fs::metadata(path)
        .await
        .with_context(|| format!("Failed to get metadata for {}", path.display()))?;

    let file_size = metadata.len();
    let mut start = start_offset;

    if start > file_size {
        trace!(
            "Offset {} past file size {} for {}, clamping to 0",
            start,
            file_size,
            path.display()
        );
        start = 0;
    }

    let mut file = fs::File::open(path)
        .await
        .with_context(|| format!("Failed to open {}", path.display()))?;

    file.seek(std::io::SeekFrom::Start(start))
        .await
        .with_context(|| format!("Failed to seek to offset {} in {}", start, path.display()))?;

    let mut reader = BufReader::new(file);
    let mut current_offset = start;
    let mut line = String::new();

    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line).await?;
        if bytes_read == 0 {
            break; // EOF
        }
        current_offset += bytes_read as u64;

        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            continue;
        }

        let record = match log_type {
            "firewall" | "yara" | "process" | "scan" | "alerts" => {
                parse_json_line(trimmed, log_type)
            }
            _ => Some(json!({
                "_timestamp": chrono::Local::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                "log_type": log_type,
                "message": trimmed,
            })),
        };

        if let Some(record) = record {
            all_records.push(LogRecord {
                log_type: log_type.to_string(),
                record,
            });
        }
    }

    Ok(current_offset)
}

/// Parse a log string into json
/// Adds `log_type` and normalises `timestamp` -> `_timestamp`.
fn parse_json_line(line: &str, log_type: &str) -> Option<Value> {
    if let Ok(mut value) = serde_json::from_str::<Value>(line) {
        if let Some(obj) = value.as_object_mut() {
            obj.insert("log_type".to_string(), json!(log_type));

            // Normalise the timestamp key to `_timestamp`
            if !obj.contains_key("_timestamp") {
                if let Some(ts) = obj.remove("timestamp") {
                    obj.insert("_timestamp".to_string(), ts);
                } else {
                    let ts = chrono::Local::now().to_rfc3339_opts(SecondsFormat::Millis, true);
                    obj.insert("_timestamp".to_string(), json!(ts));
                }
            }
        }
        Some(value)
    } else {
        // Fallback: treat as plain text
        Some(json!({
            "_timestamp": chrono::Local::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            "log_type": log_type,
            "message": line,
        }))
    }
}

/// Read new log lines from a file since the last offset into all_records Vec
pub async fn read_logs(
    log_file: &Path,
    log_type: &str,
    _rollover_size: u64,
    all_records: &mut Vec<LogRecord>,
) -> anyhow::Result<()> {
    let offset_file = offset_path(log_file);

    // If log file doesn't exist, delete the offset file and return
    if !log_file.exists() {
        let _ = fs::remove_file(&offset_file).await;
        return Ok(());
    }

    let mut start_offset = get_offset(&offset_file)
        .await
        .with_context(|| format!("Failed to read offset from {}", offset_file.display()))?;

    // When log4rs rotates the file start reading from the beginning again
    let file_metadata = fs::metadata(log_file)
        .await
        .with_context(|| format!("Failed to get metadata for {}", log_file.display()))?;
    let file_size = file_metadata.len();

    if start_offset > file_size {
        trace!("File offset past file size, rebuilding offset file");
        let _ = fs::remove_file(&offset_file).await;
        start_offset = 0;
    }

    // Read current file
    let new_offset = read_from_offset_into(log_file, log_type, start_offset, all_records).await?;

    save_offset(&offset_file, new_offset)
        .await
        .with_context(|| format!("Failed to save offset to {}", offset_file.display()))?;

    Ok(())
}
