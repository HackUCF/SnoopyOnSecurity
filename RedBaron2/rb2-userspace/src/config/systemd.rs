use log::{error, info, warn};
use std::env;
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

pub fn install_systemd_unit() -> io::Result<()> {
    let exe_path = env::current_exe()?;
    let bin_name = exe_path
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| io::Error::other("Could not determine binary name"))?
        .to_string();

    let unit_path = PathBuf::from(format!("/etc/systemd/system/{}.service", bin_name));

    if unit_path.exists() {
        warn!(
            "Systemd unit already exists at {}. Not overwriting.",
            unit_path.display()
        );
        return Ok(());
    }

    let exec_path = exe_path
        .to_str()
        .ok_or_else(|| io::Error::other("Non-UTF8 path to executable"))?;

    let rust_log = env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    let rb2_config =
        Path::new(&env::var("RB2_CONFIG").unwrap_or_else(|_| "/etc/rb2.yaml".to_string()))
            .canonicalize()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|_| {
                warn!("Unable to canonicalize RB2_CONFIG, using /etc/rb2.yaml instead");
                "/etc/rb2.yaml".to_string()
            });

    let unit_contents = format!(
        r#"[Unit]
Description=Red Baron 2
After=network.target

[Service]
Type=notify
ExecStart="{exec}"
Restart=on-failure
RestartSec=2
Environment="RUST_LOG={rust_log}"
Environment="RB2_CONFIG={rb2_config}"
WatchdogSec=30s

[Install]
WantedBy=multi-user.target
"#,
        exec = exec_path
    );

    // Write atomically: write to a temp file in the same dir, then rename.
    let tmp_path = unit_path.with_extension("service.tmp");
    {
        let mut f = File::create(&tmp_path)?;
        f.write_all(unit_contents.as_bytes())?;
        f.sync_all()?;
        // Set perms like other unit files (0644)
        let mut perms = f.metadata()?.permissions();
        perms.set_mode(0o644);
        fs::set_permissions(&tmp_path, perms)?;
    }
    fs::rename(&tmp_path, &unit_path)?;

    info!("Installed unit to {}", unit_path.display());

    match Command::new("systemctl").arg("daemon-reload").status() {
        Ok(status) if status.success() => {}
        Ok(status) => {
            error!(
                "Warning: 'systemctl daemon-reload' exited with status: {}",
                status
            );
        }
        Err(e) => {
            error!(
                "Warning: Failed to execute 'systemctl daemon-reload': {}",
                e
            );
            return Err(e);
        }
    }

    match Command::new("systemctl")
        .args([
            "--no-block",
            "enable",
            "--now",
            &format!("{}.service", bin_name),
        ])
        .status()
    {
        Ok(status) if status.success() => {}
        Ok(status) => {
            error!(
                "Warning: 'systemctl enable --now {}.service' exited with status: {}",
                bin_name, status
            );
        }
        Err(e) => {
            error!(
                "Warning: Failed to execute 'systemctl enable --now {}.service': {}",
                bin_name, e
            );
            return Err(e);
        }
    }

    Ok(())
}
