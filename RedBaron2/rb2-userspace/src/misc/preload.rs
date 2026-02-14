use anyhow::{Context, Result};
use serde_json::json;
use std::{
    collections::BTreeMap,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};
use tokio::fs;

use super::log::log_detection;

#[derive(Debug, Clone)]
pub struct Config {
    pub ld_so_preload_path: PathBuf,
    pub allowed_lib_prefixes: Vec<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ld_so_preload_path: PathBuf::from("/etc/ld.so.preload"),
            allowed_lib_prefixes: vec![
                PathBuf::from("/lib"),
                PathBuf::from("/lib64"),
                PathBuf::from("/usr/lib"),
                PathBuf::from("/usr/lib64"),
            ],
        }
    }
}

fn mode_string(mode: u32) -> String {
    format!("{:#06o}", mode & 0o7777)
}

fn is_group_or_world_writable(mode: u32) -> bool {
    (mode & 0o0020) != 0 || (mode & 0o0002) != 0
}

fn is_under_allowed_prefixes(path: &Path, allowed: &[PathBuf]) -> bool {
    allowed.iter().any(|p| path.starts_with(p))
}

pub async fn scan() -> Result<()> {
    let cfg = Config::default();
    scan_ld_so_preload_file(&cfg).await?;
    scan_proc().await?;
    Ok(())
}

async fn scan_ld_so_preload_file(cfg: &Config) -> Result<()> {
    let p = &cfg.ld_so_preload_path;

    let meta = match fs::symlink_metadata(p).await {
        Ok(m) => m,
        Err(e) => {
            // Not present is good
            if e.kind() == std::io::ErrorKind::NotFound {
                return Ok(());
            }
            return Err(e).with_context(|| format!("symlink_metadata {}", p.display()));
        }
    };

    if meta.file_type().is_symlink() {
        log_detection(
            "ld_preload",
            "ld.so.preload exists and is a symlink",
            json!({ "path": p.display().to_string() }),
        )
        .await;
    } else {
        log_detection(
            "ld_preload",
            "ld.so.preload present",
            json!({
                "path": p.display().to_string(),
                "uid": meta.uid(),
                "gid": meta.gid(),
                "mode": mode_string(meta.mode()),
            }),
        )
        .await;

        if is_group_or_world_writable(meta.mode()) {
            log_detection(
                "ld_preload",
                "ld.so.preload is group/world-writable",
                json!({
                    "path": p.display().to_string(),
                    "mode": mode_string(meta.mode()),
                }),
            )
            .await;
        }
    }

    let content = fs::read_to_string(p)
        .await
        .with_context(|| format!("read_to_string {}", p.display()))?;

    for (idx, raw_line) in content.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // support multiple paths per line
        for token in line.split_whitespace() {
            let lib = PathBuf::from(token);

            match fs::symlink_metadata(&lib).await {
                Ok(m) => {
                    if is_group_or_world_writable(m.mode()) {
                        log_detection(
                            "ld_preload",
                            "preload library is group/world-writable",
                            json!({
                                "lib": lib.display().to_string(),
                                "mode": mode_string(m.mode()),
                                "uid": m.uid(),
                                "gid": m.gid(),
                                "line": idx + 1,
                            }),
                        )
                        .await;
                    }

                    if !is_under_allowed_prefixes(&lib, &cfg.allowed_lib_prefixes) {
                        log_detection(
                            "ld_preload",
                            "preload library path is outside typical library directories",
                            json!({
                                "lib": lib.display().to_string(),
                                "line": idx + 1,
                                "allowed_prefixes": cfg.allowed_lib_prefixes
                                    .iter()
                                    .map(|p| p.display().to_string())
                                    .collect::<Vec<_>>(),
                            }),
                        )
                        .await;
                    }
                }
                Err(e) => {
                    log_detection(
                        "ld_preload",
                        "library referenced by ld.so.preload does not exist",
                        json!({
                            "lib": lib.display().to_string(),
                            "line": idx + 1,
                            "error": e.to_string(),
                        }),
                    )
                    .await;
                }
            }
        }
    }

    Ok(())
}

async fn scan_proc() -> Result<()> {
    let mut rd = fs::read_dir("/proc").await.context("read_dir /proc")?;

    let mut hits: u64 = 0;

    let mut val_counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut sample: Vec<u32> = Vec::new();
    const SAMPLE_LIMIT: usize = 10;

    while let Some(ent) = rd.next_entry().await.context("next_entry /proc")? {
        let pid_str = ent.file_name().to_string_lossy().to_string();
        let pid: u32 = match pid_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        if let Some(val) = read_ld_preload_for_pid(pid).await {
            hits += 1;
            *val_counts.entry(val.clone()).or_insert(0) += 1;

            if sample.len() < SAMPLE_LIMIT {
                sample.push(pid);
            }
        }
    }

    if hits > 0 {
        // take top N values by count
        let mut top_vals: Vec<(String, u64)> = val_counts.into_iter().collect();
        top_vals.sort_by(|a, b| b.1.cmp(&a.1));
        top_vals.truncate(5);

        log_detection(
            "ld_preload",
            "LD_PRELOAD present in process environments",
            json!({
                "hits": hits,
                "unique_values": top_vals.len(),
                "top_values": top_vals.into_iter().map(|(v,c)| json!({"value": v, "count": c})).collect::<Vec<_>>(),
                "sample_pids": sample,
            }),
        )
        .await;
    }

    Ok(())
}

async fn read_ld_preload_for_pid(pid: u32) -> Option<String> {
    let environ_path = format!("/proc/{}/environ", pid);
    let data = fs::read(&environ_path).await.ok()?;

    for kv in data.split(|b| *b == 0) {
        if kv.is_empty() {
            continue;
        }
        let eq = kv.iter().position(|b| *b == b'=')?;
        if &kv[..eq] == b"LD_PRELOAD" {
            return Some(String::from_utf8_lossy(&kv[eq + 1..]).to_string());
        }
    }
    None
}
