use super::{Ingestor, LogRecord};
use crate::config::yaml::OpenObserveConfig;
use anyhow::Context;
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use flate2::Compression;
use flate2::write::GzEncoder;
use log::{debug, error, warn};
use serde_json::json;
use std::io::Write;
use std::sync::Arc;

pub struct OpenObserveIngestor {
    state: Arc<State>,
}

struct State {
    url: String,
    stream_prefix: String,
    auth_header: String,
    agent: ureq::Agent,
}

impl OpenObserveIngestor {
    pub fn new(cfg: OpenObserveConfig) -> anyhow::Result<Self> {
        let url = format!("{}/api/{}/_bulk", cfg.url, cfg.org);
        let stream_prefix = cfg.stream_prefix.clone();
        let auth_header = basic_auth_header(&cfg.username, &cfg.password);

        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build()
            .into();

        Ok(Self {
            state: Arc::new(State {
                url,
                stream_prefix,
                auth_header,
                agent,
            }),
        })
    }

    fn format_ndjson(&self, records: &[LogRecord]) -> anyhow::Result<String> {
        let mut ndjson = String::new();

        for record in records {
            let stream = format!("{}-{}", self.state.stream_prefix, record.log_type);
            let action = json!({
                "index": { "_index": stream }
            });
            ndjson.push_str(&serde_json::to_string(&action)?);
            ndjson.push('\n');
            ndjson.push_str(&serde_json::to_string(&record.record)?);
            ndjson.push('\n');
        }

        Ok(ndjson)
    }
}

#[async_trait]
impl Ingestor for OpenObserveIngestor {
    async fn ingest(&self, records: &[LogRecord]) -> anyhow::Result<()> {
        if records.is_empty() {
            return Ok(());
        }

        let ndjson = self
            .format_ndjson(records)
            .context("Failed to format records as NDJSON")?;

        debug!(
            "Sending {} records to OpenObserve (stream_prefix: {}, url: {}, payload: {} bytes)",
            records.len(),
            self.state.stream_prefix,
            self.state.url,
            ndjson.len()
        );

        let state = self.state.clone();

        tokio::task::spawn_blocking(move || OpenObserveSend { state, ndjson }.send())
            .await
            .context("Failed to join blocking task for HTTP request")?
            .context("Failed to send logs to OpenObserve")?;

        Ok(())
    }

    fn name(&self) -> &str {
        "openobserve"
    }
}

struct OpenObserveSend {
    state: Arc<State>,
    ndjson: String,
}

impl OpenObserveSend {
    fn gzip_compress(data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder
            .write_all(data)
            .context("Failed to write data to gzip encoder")?;
        encoder
            .finish()
            .context("Failed to finish gzip compression")
    }

    fn send(self) -> anyhow::Result<()> {
        let raw_bytes = self.ndjson.as_bytes();
        let compressed =
            Self::gzip_compress(raw_bytes).context("Failed to gzip compress payload")?;

        debug!(
            "Gzip compressed payload: {} -> {} bytes ({:.0}% reduction)",
            raw_bytes.len(),
            compressed.len(),
            (1.0 - compressed.len() as f64 / raw_bytes.len() as f64) * 100.0
        );

        let mut resp = self
            .state
            .agent
            .post(&self.state.url)
            .header("Authorization", &self.state.auth_header)
            .header("Content-Type", "application/x-ndjson")
            .header("Content-Encoding", "gzip")
            .send(compressed.as_slice())
            .map_err(|e| {
                anyhow::anyhow!(
                    "OpenObserve HTTP request failed: {} (url: {}, stream_prefix: {})",
                    e,
                    self.state.url,
                    self.state.stream_prefix
                )
            })?;

        let status = resp.status();
        let body = resp.body_mut().read_to_string().with_context(|| {
            format!(
                "Failed to read OpenObserve response body (status: {}, url: {})",
                status, self.state.url
            )
        })?;

        if status.is_success() {
            self.handle_success(status, &body);
            return Ok(());
        }

        self.handle_error(status, &body);
        Err(anyhow::anyhow!(
            "OpenObserve returned status {}: {}",
            status,
            body
        ))
    }

    fn handle_success(&self, status: ureq::http::StatusCode, body: &str) {
        debug!("OpenObserve bulk response (status {}): {}", status, body);

        let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else {
            warn!("Failed to parse OpenObserve response as JSON: {}", body);
            return;
        };

        if v.get("errors").and_then(|e| e.as_bool()) == Some(true) {
            warn!("OpenObserve response indicates errors occurred");
        }

        if let Some(items) = v.get("status").and_then(|s| s.as_array()) {
            for (idx, item) in items.iter().enumerate() {
                let failed = item.get("failed").and_then(|f| f.as_u64()).unwrap_or(0);
                if failed == 0 {
                    continue;
                }

                warn!(
                    "OpenObserve reported {} failed records in batch {}",
                    failed, idx
                );

                if let Some(details) = item.get("error") {
                    error!(
                        "OpenObserve batch {} error details: {}",
                        idx,
                        json_string(details)
                    );
                }
            }
        }

        if let Some(top) = v.get("error") {
            error!(
                "OpenObserve returned error in response: {}",
                json_string(top)
            );
        }
    }

    fn handle_error(&self, status: ureq::http::StatusCode, body: &str) {
        error!(
            "OpenObserve returned non-success status {}: {} (url: {}, stream_prefix: {})",
            status, body, self.state.url, self.state.stream_prefix
        );

        let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else {
            return;
        };

        if let Some(err) = v.get("error") {
            error!("OpenObserve error details: {}", json_string(err));
        }
        if let Some(msg) = v.get("message") {
            error!("OpenObserve error message: {}", msg);
        }
    }
}

fn basic_auth_header(username: &str, password: &str) -> String {
    let encoded = STANDARD.encode(format!("{username}:{password}"));
    format!("Basic {encoded}")
}

fn json_string(v: &serde_json::Value) -> String {
    serde_json::to_string(v).unwrap_or_else(|_| "Failed to serialize".to_string())
}
