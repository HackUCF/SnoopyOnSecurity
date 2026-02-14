use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use sha1::Digest as Sha1Digest;
use std::io::{Error, ErrorKind, Read};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;

use super::{
    BoxFuture, Finding, FindingKind, ManagerReport, ScanLimits, StreamItem, StreamScanManager,
};

#[derive(Clone, Debug, Default)]
struct ExpectedMeta {
    mode: Option<u32>, // compared against 0o7777
}

#[derive(Clone, Debug)]
struct VerifyJob {
    pkg: Arc<str>,
    path: PathBuf,
    expected_q1_b64: Arc<str>, // "Q1" + base64(sha1(raw))
    expected_meta: ExpectedMeta,
}

/// scans the apk-tools v2 package database
/// TODO: also parse a apk v3 database
pub async fn scan(limits: ScanLimits) -> Result<ManagerReport> {
    let installed_path = Path::new("/lib/apk/db/installed");

    if !fs::try_exists(installed_path).await.unwrap_or(false) {
        return Ok(ManagerReport {
            manager: "apk",
            ..Default::default()
        });
    }

    Ok(super::run_stream_scan::<ApkScanner>(limits).await)
}

struct ApkScanner;

impl StreamScanManager for ApkScanner {
    const MANAGER: &'static str = "apk";
    type Job = VerifyJob;

    fn producer_label() -> &'static str {
        "installed db parse"
    }

    fn producer_error_path() -> Option<PathBuf> {
        Some(PathBuf::from("/lib/apk/db/installed"))
    }

    fn spawn_producer(
        limits: ScanLimits,
        tx: tokio::sync::mpsc::UnboundedSender<StreamItem<Self::Job>>,
    ) -> tokio::task::JoinHandle<anyhow::Result<()>> {
        let installed_path = PathBuf::from("/lib/apk/db/installed");
        let scan_conffiles = limits.scan_conffiles;
        tokio::task::spawn_blocking(move || {
            stream_apk_installed(&installed_path, tx, scan_conffiles)
        })
    }

    fn verify(job: Self::Job, limits: ScanLimits) -> BoxFuture<Option<Finding>> {
        Box::pin(verify_one(job, limits))
    }
}

fn stream_apk_installed(
    installed_path: &Path,
    tx: tokio::sync::mpsc::UnboundedSender<StreamItem<VerifyJob>>,
    scan_conffiles: bool,
) -> Result<()> {
    use std::fs;

    #[derive(Default)]
    struct RecState {
        pkg_name: Option<String>,
        pkg_ver: Option<String>,
        pkg_arch: Option<String>,
        pkg_id: Option<Arc<str>>,
        sent_pkg: bool,

        cur_dir: Option<String>,
        cur_file: Option<String>,
        pending_mode: Option<u32>,
    }

    impl RecState {
        fn reset_record(&mut self) {
            *self = Self::default();
        }

        fn ensure_pkg_id(&mut self) {
            let Some(n) = self.pkg_name.as_ref() else {
                return;
            };
            let Some(v) = self.pkg_ver.as_ref() else {
                return;
            };
            let a = self.pkg_arch.as_deref().unwrap_or("");
            let s = if a.is_empty() {
                format!("{n}-{v}")
            } else {
                format!("{n}-{v}.{a}")
            };
            self.pkg_id = Some(Arc::<str>::from(s));
        }

        fn maybe_send_pkg(
            &mut self,
            tx: &tokio::sync::mpsc::UnboundedSender<StreamItem<VerifyJob>>,
        ) {
            if self.sent_pkg {
                return;
            }
            if self.pkg_id.is_some() {
                let _ = tx.send(StreamItem::Pkg);
                self.sent_pkg = true;
            }
        }
    }

    fn root_join(dir: &str, file: &str) -> PathBuf {
        let dir = dir.trim();
        let d = if dir.is_empty() || dir == "." {
            "/".to_string()
        } else if dir.starts_with('/') {
            dir.to_string()
        } else {
            format!("/{dir}")
        };
        PathBuf::from(d).join(file)
    }

    let data = fs::read_to_string(installed_path).context("read /lib/apk/db/installed")?;

    let mut st = RecState::default();

    for raw in data.lines() {
        let line = raw.trim_end();
        if line.is_empty() {
            st.reset_record();
            continue;
        }

        let (k, v) = match line.split_once(':') {
            Some((k, v)) => (k, v),
            None => continue,
        };
        let v = v.trim();

        match k {
            "P" => {
                st.pkg_name = Some(v.to_string());
                st.ensure_pkg_id();
                st.maybe_send_pkg(&tx);
            }
            "V" => {
                st.pkg_ver = Some(v.to_string());
                st.ensure_pkg_id();
                st.maybe_send_pkg(&tx);
            }
            "A" => {
                st.pkg_arch = Some(v.to_string());
                st.ensure_pkg_id();
                st.maybe_send_pkg(&tx);
            }

            "F" => {
                st.cur_dir = Some(v.to_string());
                st.cur_file = None;
                st.pending_mode = None;
            }
            "R" => {
                st.cur_file = Some(v.to_string());
                st.pending_mode = None;
            }
            "a" => {
                let parts: Vec<&str> = v.split(':').collect();
                if let Some(mode_s) = parts.last()
                    && let Ok(m) = u32::from_str_radix(mode_s.trim(), 8)
                {
                    st.pending_mode = Some(m);
                }
            }
            "Z" => {
                let Some(pkg) = st.pkg_id.clone() else {
                    continue;
                };
                let Some(dir) = st.cur_dir.as_deref() else {
                    continue;
                };
                let Some(file) = st.cur_file.as_deref() else {
                    continue;
                };

                let p = root_join(dir, file);

                // no real conffiles flag in db, so just skip /etc
                if !scan_conffiles && p.starts_with("/etc") {
                    continue;
                }

                let expected = v.trim();
                if expected.is_empty() {
                    continue;
                }

                let expected_meta = ExpectedMeta {
                    mode: st.pending_mode,
                };

                let _ = tx.send(StreamItem::File {
                    job: VerifyJob {
                        pkg,
                        path: p,
                        expected_q1_b64: Arc::<str>::from(expected.to_string()),
                        expected_meta,
                    },
                });
            }

            _ => {}
        }
    }

    Ok(())
}

async fn verify_one(job: VerifyJob, limits: ScanLimits) -> Option<Finding> {
    use std::os::unix::fs::PermissionsExt;

    let VerifyJob {
        pkg,
        path,
        expected_q1_b64,
        expected_meta,
    } = job;

    let meta = match fs::symlink_metadata(&path).await {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Some(Finding {
                manager: "apk",
                package: Some(pkg.to_string()),
                path: Some(path),
                kind: FindingKind::Missing,
                details: "missing file".into(),
            });
        }
        Err(e) => {
            return Some(Finding {
                manager: "apk",
                package: Some(pkg.to_string()),
                path: Some(path),
                kind: FindingKind::Error,
                details: format!("metadata error: {e}"),
            });
        }
    };

    // metadata diffs (regular files only; symlink perms are not meaningful)
    let mut meta_diffs: Vec<String> = Vec::new();
    if !meta.file_type().is_symlink()
        && let Some(exp_mode) = expected_meta.mode
    {
        let actual_mode = meta.permissions().mode() & 0o7777;
        let exp_mode = exp_mode & 0o7777;
        if actual_mode != exp_mode {
            meta_diffs.push(format!("mode {:o} != {:o}", actual_mode, exp_mode));
        }
    }

    // only handle regular files and symlinks
    if !(meta.is_file() || meta.file_type().is_symlink()) {
        return None;
    }

    let permit = match limits.hash_sem.clone().acquire_owned().await {
        Ok(p) => p,
        Err(_) => {
            return Some(Finding {
                manager: "apk",
                package: Some(pkg.to_string()),
                path: Some(path),
                kind: FindingKind::Error,
                details: "hash semaphore closed".into(),
            });
        }
    };

    let path2 = path.clone();
    let expected2 = expected_q1_b64.clone();
    let is_symlink = meta.file_type().is_symlink();

    let actual =
        tokio::task::spawn_blocking(move || q1_sha1_b64_for_path(&path2, &expected2, is_symlink))
            .await;
    drop(permit);

    let actual = match actual {
        Err(e) => {
            return Some(Finding {
                manager: "apk",
                package: Some(pkg.to_string()),
                path: Some(path),
                kind: FindingKind::Error,
                details: format!("hash join error: {e}"),
            });
        }
        Ok(Err(e)) => {
            return Some(Finding {
                manager: "apk",
                package: Some(pkg.to_string()),
                path: Some(path),
                kind: FindingKind::Error,
                details: format!("digest read/hash error: {e}"),
            });
        }
        Ok(Ok(v)) => v,
    };

    if actual != expected_q1_b64.as_ref() {
        return Some(Finding {
            manager: "apk",
            package: Some(pkg.to_string()),
            path: Some(path),
            kind: FindingKind::Modified,
            details: format!(
                "digest mismatch expected={} actual={}",
                expected_q1_b64, actual
            ),
        });
    }

    if !meta_diffs.is_empty() {
        return Some(Finding {
            manager: "apk",
            package: Some(pkg.to_string()),
            path: Some(path),
            kind: FindingKind::MetadataChanged,
            details: meta_diffs.join(", "),
        });
    }

    None
}

fn q1_sha1_b64_for_path(path: &Path, expected: &str, is_symlink: bool) -> std::io::Result<String> {
    if !expected.starts_with("Q1") {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "unsupported apk file checksum encoding: {}",
                expected.chars().take(8).collect::<String>()
            ),
        ));
    }

    let mut h = sha1::Sha1::new();

    if is_symlink {
        // apk audit symlinks: hash the link target string
        let target = std::fs::read_link(path)?;
        h.update(target.as_os_str().as_bytes());
    } else {
        let mut f = std::fs::File::open(path)?;
        let mut buf = [0u8; 131072];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
    }

    Ok(format!("Q1{}", B64.encode(h.finalize())))
}
