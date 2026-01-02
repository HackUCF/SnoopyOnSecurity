use std::{env, fs, path::PathBuf, process::Command};

use log::info;

use crate::firewall::sockets;

pub fn write_config_in_cwd(filename: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let header_before_whitelist = r#"features:
  firewall: true
  process: true
  yara: true
  scan: true
  ingestor: false

log_dir: /var/log/rb2

process:
  rhai_rules_dir: /tmp/rb2/mockrules

yara:
  # Optional: Additional directory to load custom YARA rules from
  # rules_dir: /var/lib/redbaron/yara
  # Optional: Disable all bundled rules (248 rules embedded in binary)
  # disable_bundled_rules: false
  # Optional: List of specific rule names to disable
  # disabled_rules:
  #   - Multi_EICAR

firewall:
  enforcing: false
  producer: ebpf
  handler: kill
  binary_whitelist:
"#;

    let header_after_whitelist = r#"
ingestor:
  # Note: The rb2 binary path must be added to firewall.binary_whitelist for log forwarding to work
  type: openobserve
  poll_interval_secs: 5
  log_rollover_size_mb: 10
  openobserve:
    url: http://localhost:5080
    org: default
    stream: rb2-logs
    username: root@example.com
    password: Complexpass#123
"#;

    let mut paths = sockets::get_active_socket_paths()?;

    // Add privilege escalation utilities to the whitelist
    paths.extend(get_privsec_utils_path());

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
    yaml.push_str(header_after_whitelist);

    let out_path = env::current_dir()
        .map_err(|e| format!("cwd error: {e}"))?
        .join(filename);
    fs::write(&out_path, yaml).map_err(|e| format!("write error {}: {e}", out_path.display()))?;
    Ok(out_path)
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
