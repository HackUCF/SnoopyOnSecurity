use chrono::SecondsFormat;
use log::info;
use serde_json::{Value, json};

use crate::misc::{get_hostname, get_machine_id};

/// Log a scan detection to both the console and to the configured log file
///
/// `fields` is a JSON object to enrich the event message
pub async fn log_detection(event: &str, message: &str, fields: Value) {
    info!("[{}] {}", event, message);

    let ts = chrono::Local::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let mut obj = json!({
        "timestamp": ts,
        "event": event,
        "host_name": get_hostname(),
        "host_id": get_machine_id(),
    });

    // Merge caller-supplied fields into the top-level object
    if let Value::Object(extra) = fields
        && let Some(map) = obj.as_object_mut()
    {
        for (k, v) in extra {
            map.insert(k, v);
        }
    }

    info!(target: "rb2_scan", "{}", obj);
}
