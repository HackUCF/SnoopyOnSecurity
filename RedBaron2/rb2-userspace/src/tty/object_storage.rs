//! Shared S3-compatible object storage client using `rusty_s3` for signing
//! and `ureq` for HTTP transport.
//!
//! This module is intentionally generic so any feature (TTY forwarding, future
//! log shipping, sample uploads, etc.) can reuse the same client.

use crate::config::yaml::ObjectStorageConfig;
use anyhow::{Context, anyhow};
use log::{debug, warn};
use rusty_s3::actions::{CreateMultipartUpload, ListObjectsV2};
use rusty_s3::{Bucket, Credentials, S3Action, UrlStyle};
use std::sync::Arc;
use std::time::Duration;

/// Pre-sign duration for PutObject URLs.
const PRESIGN_DURATION: Duration = Duration::from_secs(3600);

const MULTIPART_CHUNK_SIZE: usize = 8 * 1024 * 1024; // 8 MiB.

const RETRY_INITIAL_BACKOFF: Duration = Duration::from_secs(2);
const MAX_RETRIES: u32 = 3;

/// A thin wrapper around `rusty_s3` bucket + credentials + `ureq` agent.
#[derive(Clone)]
pub struct S3Client {
    inner: Arc<S3Inner>,
}

struct S3Inner {
    bucket: Bucket,
    credentials: Credentials,
    agent: ureq::Agent,
    endpoint_str: String,
    url_style: UrlStyle,
}

impl S3Client {
    /// Create a new client from the parsed config.
    pub fn new(cfg: &ObjectStorageConfig) -> anyhow::Result<Self> {
        let endpoint = cfg
            .endpoint
            .parse()
            .map_err(|e| anyhow!("invalid object_storage.endpoint URL: {e}"))?;

        let url_style = if cfg.path_style {
            UrlStyle::Path
        } else {
            UrlStyle::VirtualHost
        };

        // Clone strings so Bucket owns them (Bucket takes &str but stores owned).
        let bucket_name = cfg.bucket_tty.clone();
        let region = cfg.region.clone();

        let bucket = Bucket::new(endpoint, url_style, bucket_name, region)
            .map_err(|e| anyhow!("invalid bucket config: {e}"))?;

        let credentials = Credentials::new(cfg.access_key.clone(), cfg.secret_key.clone());

        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build()
            .into();

        Ok(Self {
            inner: Arc::new(S3Inner {
                bucket,
                credentials,
                agent,
                endpoint_str: cfg.endpoint.clone(),
                url_style,
            }),
        })
    }

    /// Return a new `S3Client` pointing at a different bucket but sharing the
    /// same endpoint, credentials, and HTTP agent.
    pub fn with_bucket(&self, bucket_name: &str) -> anyhow::Result<Self> {
        let endpoint = self
            .inner
            .endpoint_str
            .parse()
            .map_err(|e| anyhow!("invalid endpoint URL on re-parse: {e}"))?;

        let bucket = Bucket::new(
            endpoint,
            self.inner.url_style,
            bucket_name.to_string(),
            self.inner.bucket.region().to_string(),
        )
        .map_err(|e| anyhow!("invalid bucket config for '{}': {e}", bucket_name))?;

        Ok(Self {
            inner: Arc::new(S3Inner {
                bucket,
                credentials: self.inner.credentials.clone(),
                agent: self.inner.agent.clone(),
                endpoint_str: self.inner.endpoint_str.clone(),
                url_style: self.inner.url_style,
            }),
        })
    }

    /// Upload `body` to the given object `key`, with automatic retry.
    pub fn put_object(&self, key: &str, body: &[u8]) -> anyhow::Result<()> {
        self.with_retry(key, || self.put_object_once(key, body))
    }

    /// Upload `data` to S3 with automatic retry.  Uses multipart upload for
    /// payloads larger than 8 MiB; smaller payloads use a single PutObject.
    pub fn put_object_multipart(&self, key: &str, data: &[u8]) -> anyhow::Result<()> {
        self.with_retry(key, || self.put_object_multipart_once(key, data))
    }

    /// Retry wrapper: run `op` up to [`MAX_RETRIES`] times with exponential
    /// backoff on failure.
    fn with_retry<F>(&self, key: &str, op: F) -> anyhow::Result<()>
    where
        F: Fn() -> anyhow::Result<()>,
    {
        let mut last_err = None;
        for attempt in 0..MAX_RETRIES {
            match op() {
                Ok(()) => return Ok(()),
                Err(e) => {
                    let delay = RETRY_INITIAL_BACKOFF * 2u32.saturating_pow(attempt);
                    last_err = Some(e);
                    if attempt + 1 < MAX_RETRIES {
                        warn!(
                            "S3 upload attempt {}/{} failed for key {}: {:#}; retrying in {:?}",
                            attempt + 1,
                            MAX_RETRIES,
                            key,
                            last_err.as_ref().unwrap(),
                            delay
                        );
                        std::thread::sleep(delay);
                    }
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("S3 upload failed for key {key}")))
    }

    /// Single-attempt PutObject (no retry).
    fn put_object_once(&self, key: &str, body: &[u8]) -> anyhow::Result<()> {
        let action = self
            .inner
            .bucket
            .put_object(Some(&self.inner.credentials), key);
        let url = action.sign(PRESIGN_DURATION);

        debug!("S3 PutObject {} ({} bytes)", key, body.len());

        let mut resp = self
            .inner
            .agent
            .put(url.as_str())
            .header("Content-Type", "application/octet-stream")
            .send(body)
            .with_context(|| format!("S3 PutObject HTTP request failed for key {key}"))?;

        let status = resp.status();
        if !status.is_success() {
            let body_text = resp.body_mut().read_to_string().unwrap_or_default();
            return Err(anyhow!(
                "S3 PutObject returned status {status} for key {key}: {body_text}"
            ));
        }

        debug!("S3 PutObject {} succeeded (status {})", key, status);
        Ok(())
    }

    /// Single-attempt multipart upload
    fn put_object_multipart_once(&self, key: &str, data: &[u8]) -> anyhow::Result<()> {
        if data.len() <= MULTIPART_CHUNK_SIZE {
            return self.put_object_once(key, data);
        }

        debug!(
            "S3 multipart upload {} ({} bytes, {} parts)",
            key,
            data.len(),
            data.len().div_ceil(MULTIPART_CHUNK_SIZE)
        );

        let upload_id = self.initiate_multipart(key)?;

        // Upload each part, collecting ETags.
        match self.upload_parts(key, &upload_id, data) {
            Ok(etags) => {
                // Complete multipart upload.
                self.complete_multipart(key, &upload_id, &etags)?;
                debug!("S3 multipart upload {} completed successfully", key);
                Ok(())
            }
            Err(e) => {
                // On failure, attempt to abort the multipart upload.
                if let Err(abort_err) = self.abort_multipart(key, &upload_id) {
                    debug!("S3 AbortMultipartUpload also failed: {abort_err:#}");
                }
                Err(e)
            }
        }
    }

    /// POST to initiate multipart upload, return the upload_id.
    fn initiate_multipart(&self, key: &str) -> anyhow::Result<String> {
        let action = self
            .inner
            .bucket
            .create_multipart_upload(Some(&self.inner.credentials), key);
        let url = action.sign(PRESIGN_DURATION);

        let mut resp = self
            .inner
            .agent
            .post(url.as_str())
            .send(&[] as &[u8])
            .with_context(|| format!("S3 CreateMultipartUpload failed for key {key}"))?;

        let status = resp.status();
        if !status.is_success() {
            let body_text = resp.body_mut().read_to_string().unwrap_or_default();
            return Err(anyhow!(
                "S3 CreateMultipartUpload returned {status} for key {key}: {body_text}"
            ));
        }

        let body = resp
            .body_mut()
            .read_to_string()
            .context("reading CreateMultipartUpload response")?;

        let parsed = CreateMultipartUpload::parse_response(&body)
            .map_err(|e| anyhow!("parsing CreateMultipartUpload XML: {e}"))?;

        let upload_id = parsed.upload_id().to_string();
        debug!(
            "S3 CreateMultipartUpload {} -> upload_id={}",
            key, upload_id
        );
        Ok(upload_id)
    }

    /// Upload each 8 MiB chunk, returning a Vec of ETags.
    fn upload_parts(&self, key: &str, upload_id: &str, data: &[u8]) -> anyhow::Result<Vec<String>> {
        let mut etags = Vec::new();

        for (i, chunk) in data.chunks(MULTIPART_CHUNK_SIZE).enumerate() {
            let part_number = (i + 1) as u16;

            let action = self.inner.bucket.upload_part(
                Some(&self.inner.credentials),
                key,
                part_number,
                upload_id,
            );
            let url = action.sign(PRESIGN_DURATION);

            let mut resp = self
                .inner
                .agent
                .put(url.as_str())
                .header("Content-Type", "application/octet-stream")
                .send(chunk)
                .with_context(|| format!("S3 UploadPart {part_number} failed for key {key}"))?;

            let status = resp.status();
            if !status.is_success() {
                let body_text = resp.body_mut().read_to_string().unwrap_or_default();
                return Err(anyhow!(
                    "S3 UploadPart {part_number} returned {status} for key {key}: {body_text}"
                ));
            }

            // The ETag header is required for CompleteMultipartUpload.
            let etag = resp
                .headers()
                .get("etag")
                .ok_or_else(|| anyhow!("S3 UploadPart {part_number} missing ETag header"))?
                .to_str()
                .map_err(|e| anyhow!("S3 UploadPart {part_number} ETag not valid UTF-8: {e}"))?
                .to_string();

            debug!(
                "S3 UploadPart {} part {} ({} bytes) etag={}",
                key,
                part_number,
                chunk.len(),
                etag
            );

            etags.push(etag);
        }

        Ok(etags)
    }

    /// Complete the multipart upload with the collected ETags.
    fn complete_multipart(
        &self,
        key: &str,
        upload_id: &str,
        etags: &[String],
    ) -> anyhow::Result<()> {
        let etag_refs: Vec<&str> = etags.iter().map(|s| s.as_str()).collect();
        let action = self.inner.bucket.complete_multipart_upload(
            Some(&self.inner.credentials),
            key,
            upload_id,
            etag_refs.into_iter(),
        );
        let url = action.sign(PRESIGN_DURATION);
        let body = action.body();

        let mut resp = self
            .inner
            .agent
            .post(url.as_str())
            .header("Content-Type", "application/xml")
            .send(body.as_bytes())
            .with_context(|| format!("S3 CompleteMultipartUpload failed for key {key}"))?;

        let status = resp.status();
        if !status.is_success() {
            let body_text = resp.body_mut().read_to_string().unwrap_or_default();
            return Err(anyhow!(
                "S3 CompleteMultipartUpload returned {status} for key {key}: {body_text}"
            ));
        }

        Ok(())
    }

    /// Abort a multipart upload (best-effort cleanup on failure).
    fn abort_multipart(&self, key: &str, upload_id: &str) -> anyhow::Result<()> {
        let action =
            self.inner
                .bucket
                .abort_multipart_upload(Some(&self.inner.credentials), key, upload_id);
        let url = action.sign(PRESIGN_DURATION);

        debug!("S3 AbortMultipartUpload {} upload_id={}", key, upload_id);

        let mut resp = self
            .inner
            .agent
            .delete(url.as_str())
            .call()
            .with_context(|| format!("S3 AbortMultipartUpload failed for key {key}"))?;

        let status = resp.status();
        if !status.is_success() {
            let body_text = resp.body_mut().read_to_string().unwrap_or_default();
            return Err(anyhow!(
                "S3 AbortMultipartUpload returned {status} for key {key}: {body_text}"
            ));
        }

        Ok(())
    }

    /// Download an object from S3, returning the raw bytes.
    pub fn get_object(&self, key: &str) -> anyhow::Result<Vec<u8>> {
        let action = self
            .inner
            .bucket
            .get_object(Some(&self.inner.credentials), key);
        let url = action.sign(PRESIGN_DURATION);

        debug!("S3 GetObject {}", key);

        let mut resp = self
            .inner
            .agent
            .get(url.as_str())
            .call()
            .with_context(|| format!("S3 GetObject HTTP request failed for key {key}"))?;

        let status = resp.status();
        if !status.is_success() {
            let body_text = resp.body_mut().read_to_string().unwrap_or_default();
            return Err(anyhow!(
                "S3 GetObject returned status {status} for key {key}: {body_text}"
            ));
        }

        let body = resp
            .body_mut()
            .read_to_vec()
            .with_context(|| format!("reading S3 GetObject response for key {key}"))?;

        debug!("S3 GetObject {} succeeded ({} bytes)", key, body.len());
        Ok(body)
    }

    /// List objects in the bucket, optionally filtered by `prefix`.
    ///
    /// Paginates automatically and returns all matching keys.
    pub fn list_objects(&self, prefix: Option<&str>) -> anyhow::Result<Vec<String>> {
        let mut all_keys = Vec::new();
        let mut continuation_token: Option<String> = None;

        loop {
            let mut action = self
                .inner
                .bucket
                .list_objects_v2(Some(&self.inner.credentials));

            if let Some(pfx) = prefix {
                action.with_prefix(pfx);
            }
            if let Some(ref token) = continuation_token {
                action.with_continuation_token(token.as_str());
            }

            let url = action.sign(PRESIGN_DURATION);

            let mut resp = self
                .inner
                .agent
                .get(url.as_str())
                .call()
                .context("S3 ListObjectsV2 HTTP request failed")?;

            let status = resp.status();
            if !status.is_success() {
                let body_text = resp.body_mut().read_to_string().unwrap_or_default();
                return Err(anyhow!(
                    "S3 ListObjectsV2 returned status {status}: {body_text}"
                ));
            }

            let body = resp
                .body_mut()
                .read_to_string()
                .context("reading S3 ListObjectsV2 response body")?;

            let parsed = ListObjectsV2::parse_response(&body)
                .map_err(|e| anyhow!("parsing ListObjectsV2 XML: {e}"))?;

            for obj in &parsed.contents {
                all_keys.push(obj.key.clone());
            }

            match parsed.next_continuation_token {
                Some(token) => continuation_token = Some(token),
                None => break,
            }
        }

        Ok(all_keys)
    }

    /// Stream a local file to S3 using multipart upload
    /// Keeps memory bounded to MULTIPART_CHUNK_SIZE
    pub fn put_object_multipart_file(
        &self,
        key: &str,
        path: &std::path::Path,
    ) -> anyhow::Result<()> {
        use std::fs::File;
        use std::io::Read;

        let mut file = File::open(path)
            .with_context(|| format!("opening file for multipart upload: {}", path.display()))?;

        let upload_id = self.initiate_multipart(key)?;

        let mut part_number: u16 = 1;
        let mut etags = Vec::new();
        let mut buf = vec![0u8; MULTIPART_CHUNK_SIZE];

        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }

            let chunk = &buf[..n];

            let action = self.inner.bucket.upload_part(
                Some(&self.inner.credentials),
                key,
                part_number,
                &upload_id,
            );
            let url = action.sign(PRESIGN_DURATION);

            let mut resp = self
                .inner
                .agent
                .put(url.as_str())
                .header("Content-Type", "application/octet-stream")
                .send(chunk)
                .with_context(|| format!("S3 UploadPart {part_number} failed for key {key}"))?;

            let status = resp.status();
            if !status.is_success() {
                let body_text = resp.body_mut().read_to_string().unwrap_or_default();
                self.abort_multipart(key, &upload_id).ok();
                return Err(anyhow!(
                    "S3 UploadPart {part_number} returned {status} for key {key}: {body_text}"
                ));
            }

            let etag = resp
                .headers()
                .get("etag")
                .ok_or_else(|| anyhow!("S3 UploadPart missing ETag header"))?
                .to_str()
                .map_err(|e| anyhow!("Invalid ETag UTF-8: {e}"))?
                .to_string();

            etags.push(etag);
            part_number += 1;
        }

        self.complete_multipart(key, &upload_id, &etags)?;

        Ok(())
    }
}
