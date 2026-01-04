use anyhow::{Result, anyhow};
use chrono::Local;
use log::trace;
use std::fs::OpenOptions;
use std::io::Write;
use std::process::Command;
use yara_x::{MetaValue, Rule};

pub fn notify(name: &str, path: &str, rule: &Rule) -> Result<()> {
    let now = Local::now();

    let mut metadata = String::new();
    for (key, value) in rule.metadata() {
        if key == "threat_name"
            && let MetaValue::String(s) = value
        {
            metadata.push_str(&format!("{}={},", key, s));
        }
        if key == "severity"
            && let MetaValue::Integer(i) = value
        {
            metadata.push_str(&format!("{}={},", key, i));
        }
    }

    let notification = &format!(
        "{} process {} path {} rule {} namespace {} metadata {}",
        now.format("%Y-%m-%d %H:%M:%S"),
        name,
        path,
        rule.identifier(),
        rule.namespace(),
        metadata,
    );

    match write_file(env!("RB_PATH1"), notification) {
        Ok(_) => {}
        Err(e) => return Err(e),
    }
    match write_file(env!("RB_PATH2"), notification) {
        Ok(_) => {}
        Err(e) => return Err(e),
    }
    match run_msg(notification) {
        Ok(_) => {}
        Err(e) => return Err(e),
    }
    Ok(())
}

fn write_file(filename: &str, notification: &str) -> Result<()> {
    let mut opts = OpenOptions::new();
    let mut file = match opts.create(true).write(true).append(true).open(filename) {
        Ok(f) => f,
        Err(e) => {
            return Err(anyhow!(
                "failed to open file '{}' for writing: {}",
                filename,
                e
            ));
        }
    };

    let line = format!("{}\n", notification);

    match file.write(line.as_bytes()) {
        Ok(_) => {}
        Err(e) => return Err(anyhow!("failed to write to file '{}': {}", filename, e)),
    }

    Ok(())
}

fn run_msg(notification: &str) -> Result<()> {
    let msg = "C:\\Windows\\System32\\msg.exe";
    match Command::new(msg).arg("*").arg(notification).output() {
        Ok(_) => {
            trace!("notify succeeded in running: {} * {}", msg, notification)
        }
        Err(e) => return Err(anyhow!("failed to run msg.exe: {}", e)),
    }

    Ok(())
}
