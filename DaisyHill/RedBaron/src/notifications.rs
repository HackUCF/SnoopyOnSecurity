use anyhow::Result;
use chrono::Local;
use std::fs::OpenOptions;
use std::io::Write;
use yara_x::{MetaValue, Rule};
use serde_json::{json, to_string};

const LOG_FILE: &str = "C:\\ProgramData\\redbaron.log";

pub fn notify(name: &str, path: &str, pid: u32, file_matched: bool, rule: &Rule) -> Result<()> {
    let now = Local::now();

    let mut metadata = serde_json::Map::new();
    for (key, value) in rule.metadata() {
        match value {
            MetaValue::String(s) if key == "threat_name" => {
                metadata.insert(key.to_string(), json!(s));
            }
            MetaValue::Integer(i) if key == "severity" => {
                metadata.insert(key.to_string(), json!(i));
            }
            _ => {}
        }
    }

    let notification = json!({
        "timestamp": now.format("%Y-%m-%d %H:%M:%S").to_string(),
        "process": name,
        "path": path,
        "rule": rule.identifier(),
        "namespace": rule.namespace(),
        "metadata": metadata,
        "pid": pid,
        "file_matched": file_matched,
    });

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(LOG_FILE)?;
    
    writeln!(file, "{}", to_string(&notification)?)?;

    Ok(())
}
