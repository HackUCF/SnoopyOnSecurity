use chrono::SecondsFormat;
use log::warn;
use std::io;
use std::path::Path;
use tokio::fs::{self, OpenOptions};
use tokio::io::AsyncWriteExt;

/// Ensure all parent directories of `path` exist
pub async fn ensure_parent_dir_async(path: &Path) -> io::Result<()> {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => fs::create_dir_all(parent).await,
        _ => Ok(()),
    }
}

/// Ensure all parent directories of `path` exist (sync)
pub fn ensure_parent_dir(path: &Path) -> io::Result<()> {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => std::fs::create_dir_all(parent),
        _ => Ok(()),
    }
}

async fn open_append_async(path: &Path) -> io::Result<tokio::fs::File> {
    ensure_parent_dir_async(path).await?;
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
}

fn open_append(path: &Path) -> io::Result<std::fs::File> {
    ensure_parent_dir(path)?;
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
}

pub async fn write_log_line_async(
    file: &mut tokio::fs::File,
    path: &Path,
    line: &str,
) -> io::Result<()> {
    let res = async {
        file.write_all(line.as_bytes()).await?;
        file.write_all(b"\n").await?;
        file.flush().await?;
        Ok::<_, io::Error>(())
    }
    .await;
    if let Err(err) = res {
        warn!("write failed ({}), recreating log file", err);
        *file = open_append_async(path).await?;
        file.write_all(line.as_bytes()).await?;
        file.write_all(b"\n").await?;
        file.flush().await?;
    }
    Ok(())
}

pub fn write_log_line(file: &mut std::fs::File, path: &Path, line: &str) -> io::Result<()> {
    use std::io::Write;

    if let Err(err) = writeln!(file, "{line}") {
        warn!("write failed ({}), recreating log file", err);
        *file = open_append(path)?;
        writeln!(file, "{line}")?;
    }
    Ok(())
}

pub async fn write_log_line_with_timestamp_async(
    file: &mut tokio::fs::File,
    path: &Path,
    line: &str,
) -> io::Result<()> {
    let ts = chrono::Local::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    write_log_line_async(file, path, &format!("{ts} {line}")).await
}

pub fn write_log_line_with_timestamp(
    file: &mut std::fs::File,
    path: &Path,
    line: &str,
) -> io::Result<()> {
    let ts = chrono::Local::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    write_log_line(file, path, &format!("{ts} {line}"))
}

pub async fn open_log_file_async(path: &Path) -> io::Result<tokio::fs::File> {
    open_append_async(path).await
}

pub fn open_log_file(path: &Path) -> io::Result<std::fs::File> {
    open_append(path)
}
