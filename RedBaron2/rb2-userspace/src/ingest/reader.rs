use anyhow::Context;
use chrono::SecondsFormat;
use log::trace;
use regex::Regex;
use serde_json::{Value, json};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use tokio::fs::{self, OpenOptions};
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};
use xz2::write::XzEncoder;

#[derive(Debug, Clone)]
pub struct LogRecord {
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

/// Build a rotated filename in the same directory as log_file
/// e.g.: /var/log/app.log -> /var/log/app.log.<timestamp string>
fn rotated_name(log_file: &Path, timestamp: &str) -> anyhow::Result<PathBuf> {
    let parent = log_file
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    let file_name = log_file
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|s| !s.is_empty())
        .context("log_file has no valid file name")?;

    Ok(parent.join(format!("{file_name}.{timestamp}")))
}

/// append .xz to a Path as a new PathBuf
fn with_xz_extension(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.xz", path.display()))
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
            "firewall" => parse_firewall_line(trimmed),
            "yara" => parse_yara_line(trimmed),
            "process" => parse_process_line(trimmed),
            _ => Some(json!({
                "_timestamp": chrono::Local::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                "log_type": log_type,
                "message": trimmed,
            })),
        };

        if let Some(record) = record {
            all_records.push(LogRecord { record });
        }
    }

    Ok(current_offset)
}

/// Rotate if file passes rollover_size
/// rename log_file -> rotated_path
/// create a fresh empty file at log_file
/// read rotated file one last time from old_offset
/// compress rotated file to .xz, then delete rotated plain file
/// reset offset for new file to 0
async fn rotate_and_archive_if_needed(
    log_file: &Path,
    log_type: &str,
    rollover_size: u64,
    offset_file: &Path,
    old_offset: u64,
    all_records: &mut Vec<LogRecord>,
) -> anyhow::Result<Option<u64>> {
    let metadata = match fs::metadata(log_file).await {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };

    if metadata.len() < rollover_size {
        return Ok(None);
    }

    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
    let rotated_path = rotated_name(log_file, &timestamp)?;
    let compressed_path = with_xz_extension(&rotated_path);

    // rename + create new file to minimize racy window
    fs::rename(log_file, &rotated_path).await.with_context(|| {
        format!(
            "Failed to rename {} -> {}",
            log_file.display(),
            rotated_path.display()
        )
    })?;

    // Create a new file where the old one was
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(log_file)
        .await
        .with_context(|| format!("Failed to create fresh log file {}", log_file.display()))?;

    // Read the rotated file one last time from the previous offset
    let final_old_offset =
        read_from_offset_into(&rotated_path, log_type, old_offset, all_records).await?;

    // Compress rotated file
    let content = fs::read(&rotated_path)
        .await
        .with_context(|| format!("Failed to read rotated file {}", rotated_path.display()))?;

    let compressed = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<u8>> {
        let mut encoder = XzEncoder::new(Vec::new(), 6);
        encoder.write_all(&content)?;
        Ok(encoder.finish()?)
    })
    .await
    .context("Compression task join failed")??;

    fs::write(&compressed_path, compressed)
        .await
        .with_context(|| format!("Failed to write {}", compressed_path.display()))?;

    // Remove uncompressed rotated file
    let _ = fs::remove_file(&rotated_path).await;

    save_offset(offset_file, 0)
        .await
        .with_context(|| format!("Failed to reset offset file {}", offset_file.display()))?;

    Ok(Some(final_old_offset))
}

/// Parse a firewall log line
fn parse_firewall_line(line: &str) -> Option<Value> {
    // Format: {timestamp} {ALLOW|DENY} pid={pid} path={path}[ context={context}]
    let parts: Vec<&str> = line.splitn(4, ' ').collect();
    if parts.len() < 4 {
        return None;
    }

    let timestamp = parts[0].to_string();
    let level = parts[1].to_string();
    let pid_part = parts[2];
    let rest = parts[3];

    let pid = pid_part.strip_prefix("pid=")?.parse::<u32>().ok()?;

    let (path_part, context_part) = match rest.split_once(" context=") {
        Some((p, c)) => (p, Some(c)),
        None => (rest, None),
    };

    let path = path_part.strip_prefix("path=")?.to_string();
    let context = context_part
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map(|c| c.to_string());

    let mut obj = serde_json::Map::new();
    obj.insert("_timestamp".to_string(), json!(timestamp));
    obj.insert("log_type".to_string(), json!("firewall"));
    obj.insert("level".to_string(), json!(level));
    obj.insert("pid".to_string(), json!(pid));
    obj.insert("path".to_string(), json!(path));

    if let Some(ctx) = context {
        obj.insert("context".to_string(), json!(ctx));
    }

    Some(Value::Object(obj))
}

static RE: OnceLock<Regex> = OnceLock::new();

/// Parse a yara log line
fn parse_yara_line(line: &str) -> Option<Value> {
    // Format: {timestamp} {path} PID={pid} matched rule '{rule_name}'
    // Or: {timestamp} kill({pid}, SIGKILL) failed: {error}
    if line.contains("kill(") && line.contains("failed:") {
        // Error line format
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        if parts.len() < 3 {
            return None;
        }
        let timestamp = parts[0].to_string();
        let error_msg = parts[2..].join(" ");
        return Some(json!({
            "_timestamp": timestamp,
            "log_type": "yara",
            "error": error_msg,
        }));
    }

    let re = RE.get_or_init(|| {
        Regex::new(r"^(.+?) (.+?) PID=(\d+) matched rule '(.+?)'$").expect("regex must compile")
    });
    let caps = re.captures(line)?;

    let timestamp = caps.get(1)?.as_str().to_string();
    let path = caps.get(2)?.as_str().to_string();
    let pid = caps.get(3)?.as_str().parse::<u32>().ok()?;
    let rule = caps.get(4)?.as_str().to_string();

    Some(json!({
        "_timestamp": timestamp,
        "log_type": "yara",
        "path": path,
        "pid": pid,
        "rule": rule,
    }))
}

/// Parse a process log line (EngineEvent Display format)
fn parse_process_line(line: &str) -> Option<Value> {
    // Process logs are JSON from EngineEvent Display implementation
    // Try to parse as JSON first
    if let Ok(mut value) = serde_json::from_str::<Value>(line) {
        // Add log_type if not present
        if let Some(obj) = value.as_object_mut() {
            obj.insert("log_type".to_string(), json!("process"));
            // Ensure _timestamp field exists
            if !obj.contains_key("_timestamp") && obj.contains_key("timestamp") {
                if let Some(ts) = obj.remove("timestamp") {
                    obj.insert("_timestamp".to_string(), ts);
                }
            } else if !obj.contains_key("_timestamp") {
                // Add current timestamp if missing
                let ts = chrono::Local::now().to_rfc3339_opts(SecondsFormat::Millis, true);
                obj.insert("_timestamp".to_string(), json!(ts));
            }
        }
        return Some(value);
    }

    // Fallback: treat as plain text with timestamp
    let parts: Vec<&str> = line.splitn(2, ' ').collect();
    if parts.len() == 2 {
        Some(json!({
            "_timestamp": parts[0],
            "log_type": "process",
            "message": parts[1],
        }))
    } else {
        Some(json!({
            "_timestamp": chrono::Local::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            "log_type": "process",
            "message": line,
        }))
    }
}

/// Read new log lines from a file since the last offset into all_records Vec
pub async fn read_logs(
    log_file: &Path,
    log_type: &str,
    rollover_size: u64,
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

    // Validate offset against current file size
    let file_metadata = fs::metadata(log_file)
        .await
        .with_context(|| format!("Failed to get metadata for {}", log_file.display()))?;
    let file_size = file_metadata.len();

    if start_offset > file_size {
        trace!("File offset past file size, rebuilding offset file");
        let _ = fs::remove_file(&offset_file).await;
        start_offset = 0;
    }

    // Check for log rotation
    if let Some(_final_old_offset) = rotate_and_archive_if_needed(
        log_file,
        log_type,
        rollover_size,
        &offset_file,
        start_offset,
        all_records,
    )
    .await
    .with_context(|| format!("Failed to rotate/archive {}", log_file.display()))?
    {
        // New file is in place; start_offset must be 0 for the new file
        start_offset = 0;
    }

    // Read current file
    let new_offset = read_from_offset_into(log_file, log_type, start_offset, all_records).await?;

    save_offset(&offset_file, new_offset)
        .await
        .with_context(|| format!("Failed to save offset to {}", offset_file.display()))?;

    Ok(())
}
