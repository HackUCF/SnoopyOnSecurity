use chrono::SecondsFormat;
use libc::{SIGKILL, kill};
use log::{debug, error, info, warn};
use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::io::Write;
use std::path::Path;
use yara_x::Rule;

use crate::config::yaml::YaraActions;
use crate::misc::{get_hostname, get_machine_id};

pub struct YaraMatchResult {
    pub pid_terminated: bool,
}

struct Ctx {
    ts: String,
    hostname: Option<String>,
    host_id: Option<String>,
}

impl Ctx {
    fn new() -> Self {
        Self {
            ts: chrono::Local::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            hostname: get_hostname(),
            host_id: get_machine_id(),
        }
    }
}

fn action_str(actions: &YaraActions, kill_label: &str) -> String {
    let mut parts = Vec::with_capacity(4);

    if actions.alert {
        parts.push("alert");
    }
    if actions.move_sample {
        parts.push("move");
    }
    if actions.forward_to_s3 {
        parts.push("s3_upload");
    }
    if actions.kill {
        parts.push(kill_label);
    }

    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(",")
    }
}

fn log_match_events(
    ctx: &Ctx,
    pid: Option<i32>,
    original_path: &str,
    rule_names: &[String],
    action_taken: &str,
) {
    for rule_name in rule_names {
        info!(
            "Found malware with rule: {} path: {} actions {}",
            rule_name, original_path, action_taken
        );

        let mut json = serde_json::json!({
            "timestamp": ctx.ts,
            "event": "yara_match",
            "host_name": ctx.hostname,
            "host_id": ctx.host_id,
            "path": original_path,
            "rule": rule_name,
            "action_taken": action_taken,
        });

        if let Some(p) = pid {
            json["pid"] = serde_json::json!(p);
        }

        info!(target: "rb2_yara", "{}", json);
    }
}

/// Reusable path+bytes handler (fanotify uses this directly).
/// - `kill_label`: what to print when actions.kill is set (e.g. "kill" vs "deny_exec")
/// - `read_bytes`: only invoked if move_sample or forward_to_s3 is enabled
pub fn handle_yara_path_match<F>(
    pid: Option<i32>,
    original_path: &str,
    rule_names: &[String],
    actions: &YaraActions,
    samples_dir: &Path,
    kill_label: &str,
    read_bytes: F,
) where
    F: FnOnce() -> anyhow::Result<Vec<u8>>,
{
    let ctx = Ctx::new();
    let action_taken = action_str(actions, kill_label);

    if actions.alert {
        log_match_events(&ctx, pid, original_path, rule_names, &action_taken);
    }

    if actions.move_sample || actions.forward_to_s3 {
        match read_bytes() {
            Ok(data) => {
                if let Err(e) = collect_sample_from_bytes(
                    pid,
                    original_path,
                    samples_dir,
                    &ctx,
                    rule_names,
                    &action_taken,
                    actions.move_sample,
                    actions.forward_to_s3,
                    &data,
                ) {
                    error!(
                        "Failed to collect sample: pid={:?} path={} err={:#}",
                        pid, original_path, e
                    );
                }
            }
            Err(e) => {
                error!(
                    "Failed to read bytes for sample collection: pid={:?} path={} err={:#}",
                    pid, original_path, e
                );
            }
        }
    }
}

/// Existing live-process entrypoint stays, but uses the shared handler.
/// Execution order: alert -> move/s3 -> kill(SIGKILL)
pub fn handle_yara_match<'a, I>(
    pid: i32,
    matching: I,
    actions: &YaraActions,
    samples_dir: &Path,
) -> YaraMatchResult
where
    I: IntoIterator<Item = Rule<'a, 'a>>,
{
    let exe_proc_path = format!("/proc/{}/exe", pid);
    let original_path = fs::read_link(&exe_proc_path)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "<unknown>".to_string());

    let rule_names: Vec<String> = matching
        .into_iter()
        .map(|r| r.identifier().to_string())
        .collect();

    handle_yara_path_match(
        Some(pid),
        &original_path,
        &rule_names,
        actions,
        samples_dir,
        "kill",
        || {
            let data = fs::read(&exe_proc_path)
                .map_err(|e| anyhow::anyhow!("reading {}: {}", exe_proc_path, e))?;
            Ok(data)
        },
    );

    let pid_terminated = if actions.kill {
        kill_logging_errors(pid)
    } else {
        false
    };

    YaraMatchResult { pid_terminated }
}

/// Collect from already-read bytes.
/// A `.yara.json` sidecar is always written.
#[allow(clippy::too_many_arguments)]
fn collect_sample_from_bytes(
    pid: Option<i32>,
    original_path: &str,
    samples_dir: &Path,
    ctx: &Ctx,
    rule_names: &[String],
    action_taken: &str,
    write_local: bool,
    write_raw_for_s3: bool,
    data: &[u8],
) -> anyhow::Result<()> {
    let hash = {
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    };

    let host_dir = samples_dir.join(ctx.hostname.as_deref().unwrap_or("unknown"));
    fs::create_dir_all(&host_dir)?;

    let uploaded_marker = host_dir.join(format!("{hash}.uploaded"));
    let already_uploaded = uploaded_marker.exists();

    if write_raw_for_s3 {
        if already_uploaded {
            debug!("Sample {hash} already uploaded to S3, skipping .raw write");
        } else {
            let raw_path = host_dir.join(format!("{hash}.raw"));
            fs::write(&raw_path, data)?;
            debug!(
                "Wrote raw sample for S3 -> {} ({} bytes)",
                raw_path.display(),
                data.len()
            );
        }
    }

    if write_local {
        let sample_path = host_dir.join(&hash);
        if !sample_path.exists() {
            let mut stripped = data.to_vec();
            strip_elf_header(&mut stripped);
            fs::write(&sample_path, &stripped)?;
            debug!(
                "Collected stripped sample -> {} ({} bytes)",
                sample_path.display(),
                stripped.len()
            );
        } else {
            debug!(
                "Stripped sample already exists at {}, skipping write",
                sample_path.display()
            );
        }

        if !original_path.contains("(deleted)") && !original_path.starts_with('<') {
            match fs::remove_file(original_path) {
                Ok(()) => {
                    debug!("Removed malware binary: {}", original_path)
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    debug!("Original binary already gone: {}", original_path)
                }
                Err(e) => warn!("Failed to remove {}: {}", original_path, e),
            }
        }
    }

    let sidecar_path = host_dir.join(format!("{}.yara.json", hash));
    let sidecar_json = serde_json::json!({
        "timestamp": ctx.ts,
        "event": "yara_match",
        "host_name": ctx.hostname,
        "host_id": ctx.host_id,
        "pid": pid,
        "path": original_path,
        "rules": rule_names,
        "sha256": hash,
        "action_taken": action_taken,
    });
    let mut f = fs::File::create(&sidecar_path)?;
    f.write_all(serde_json::to_string_pretty(&sidecar_json)?.as_bytes())?;
    debug!("Wrote sidecar {}", sidecar_path.display());

    Ok(())
}

/// Zero out the ELF header magic
fn strip_elf_header(data: &mut [u8]) {
    const ELF_MAGIC: &[u8] = b"\x7fELF";
    if data.len() >= 4 && data[..4] == *ELF_MAGIC {
        data[0] = 0;
        data[1] = 0;
        data[2] = 0;
        data[3] = 0;
        debug!("Stripped ELF magic from sample");
    }
}

/// Send SIGKILL and log if it fails
fn kill_logging_errors(pid: i32) -> bool {
    match kill_pid(pid) {
        Ok(()) => {
            debug!("PID {} killed", pid);
            true
        }
        Err(e) => {
            warn!("YARA kill failed: pid={} error={}", pid, e);
            false
        }
    }
}

fn kill_pid(pid: i32) -> io::Result<()> {
    let rc = unsafe { kill(pid, SIGKILL) };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
