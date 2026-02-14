use log::{info, warn};
use std::{env, fs, os::unix::fs::OpenOptionsExt, path::PathBuf, process::Command};

use crate::firewall::sockets;

pub fn write_config(filename: &str) -> anyhow::Result<PathBuf> {
    // Get the authorized_keys path for the current user
    let authorized_keys_path = env::var("HOME")
        .map(|home| format!("{}/.ssh/authorized_keys", home))
        .unwrap_or_else(|_| "~/.ssh/authorized_keys".to_string());

    let header_before_whitelist = r#"features:
  firewall: true
  yara: true
  process: true
  tty: true
  scan: true
  ingestor: false

firewall:
  enforcing: false
  producer: ebpf
  handler: kill
  binary_whitelist:
"#;

    let header_after_whitelist = format!(
        r#"
yara:
  rules_dir: # /var/lib/rb2/yara # optional for extra rules
  disable_bundled_rules: false
  disabled_rules: # optional
    #- Multi_EICAR
  actions:
    - kill
    #- move
    #- forward_to_s3
  samples_dir: /var/lib/rb2/samples
  fanotify_enabled: true

tty:
  encrypt: true
  authorized_keys: {authorized_keys_path}
  flush_interval_secs: 10
  storage: sqlite                        # "files" or "sqlite"
  sqlite_path: /var/lib/rb2/tty_sessions.db
  sqlite_max_size_mb: 256                # 0 = unlimited
  forward_to_s3: false
  s3_forward_interval_secs: 60

ingestor:
  # Note: The rb2 binary path must be added to firewall.binary_whitelist for log forwarding to work
  type: openobserve
  poll_interval_secs: 5
  log_rollover_size_mb: 10
  stats_interval_secs: 120   # 0 = disabled
  openobserve:
    url: http://localhost:5080
    org: default
    stream_prefix: rb2-logs
    username: root@example.com
    password: Complexpass#123

object_storage:
  endpoint: "http://minio.local:9000"
  bucket_tty: "rb2-tty"
  bucket_samples: "rb2-samples"
  region: "us-east-1"
  access_key: "minioadmin"
  secret_key: "minioadmin"
  path_style: true

logging:
  log_dir: /var/log/rb2
  rollover_size_mb: 10
  rollover_count: 5

process:
  rhai_enabled: true
  # rhai_rules_dir: /var/lib/rb2/rhai
  disabled_rules: # remove specific rules by name
  #   - bash_c_execution
"#
    );

    let mut paths = sockets::get_active_socket_paths()?;

    // Sudo tries to do network activity
    paths.extend(get_privsec_utils_path());

    paths.extend(get_bta_paths());

    if let Some(p) = get_self_path() {
        paths.push(p);
    }

    let mut yaml = String::with_capacity(
        header_before_whitelist.len() + header_after_whitelist.len() + paths.len() * 64,
    );
    yaml.push_str(header_before_whitelist);

    // Add whitelisted binary paths
    for p in &paths {
        let s = p.to_string_lossy();
        info!("Adding path {s} to binary built allow list");
        yaml.push_str("    - ");
        yaml.push_str(&s);
        yaml.push('\n');
    }

    // Add the rest of the config after the whitelist
    yaml.push_str(&header_after_whitelist);

    // Try /etc, if it fails fall back to CWD
    let etc_path = PathBuf::from("/etc").join(filename);
    match write_file(&etc_path, &yaml) {
        Ok(()) => Ok(etc_path),
        Err(e) => {
            warn!(
                "Failed to write {} ({}), falling back to CWD",
                etc_path.display(),
                e
            );
            let out_path = env::current_dir()?.join(filename);
            write_file(&out_path, &yaml)?;
            Ok(out_path)
        }
    }
}

/// Create with 0600
fn write_file(path: &std::path::Path, contents: &str) -> std::io::Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true).mode(0o600);
    let mut f = opts.open(path)?;
    use std::io::Write;
    f.write_all(contents.as_bytes())?;
    f.sync_all()?;
    Ok(())
}

fn get_self_path() -> Option<PathBuf> {
    std::env::current_exe().ok()
}

fn get_privsec_utils_path() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    let sudo_path = Command::new("which")
        .arg("sudo")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|path| path.trim().to_string());

    let doas_path = Command::new("which")
        .arg("doas")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|path| path.trim().to_string());

    if let Some(path) = sudo_path {
        paths.push(PathBuf::from(path));
    }

    if let Some(path) = doas_path {
        paths.push(PathBuf::from(path));
    }

    paths
}

fn get_bta_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    let bta = PathBuf::from("/usr/sbin/bta");
    if bta.exists() {
        paths.push(bta);
    }

    let sidecar = PathBuf::from("/usr/sbin/bta-sidecar");
    if sidecar.exists() {
        paths.push(sidecar);
    }

    paths
}
