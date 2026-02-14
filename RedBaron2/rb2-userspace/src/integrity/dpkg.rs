use anyhow::Result;
use md5::{Context as Md5Ctx, Digest as Md5Digest};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;

use super::{
    BoxFuture, Finding, FindingKind, ManagerReport, ScanLimits, StreamItem, StreamScanManager,
};

#[derive(Clone, Debug)]
struct InstalledPkg {
    name: Arc<str>,
    version: Arc<str>,
    arch: Arc<str>,
    conffiles: Vec<(PathBuf, Md5Digest)>,
}

#[derive(Clone, Debug)]
struct VerifyJob {
    pkg: Arc<str>,
    path: PathBuf,
    expected: Md5Digest,
}

pub async fn scan(limits: ScanLimits) -> Result<ManagerReport> {
    let status_path = Path::new("/var/lib/dpkg/status");
    if !fs::try_exists(status_path).await.unwrap_or(false) {
        return Ok(ManagerReport {
            manager: "dpkg",
            ..Default::default()
        });
    }

    Ok(super::run_stream_scan::<DpkgScanner>(limits).await)
}

struct DpkgScanner;

impl StreamScanManager for DpkgScanner {
    const MANAGER: &'static str = "dpkg";
    type Job = VerifyJob;

    fn producer_label() -> &'static str {
        "dpkg status scan"
    }

    fn producer_error_path() -> Option<PathBuf> {
        Some(PathBuf::from("/var/lib/dpkg/status"))
    }

    fn spawn_producer(
        limits: ScanLimits,
        tx: tokio::sync::mpsc::UnboundedSender<StreamItem<Self::Job>>,
    ) -> tokio::task::JoinHandle<anyhow::Result<()>> {
        let status_path = PathBuf::from("/var/lib/dpkg/status");
        let scan_conffiles = limits.scan_conffiles;
        tokio::spawn(async move { stream_dpkg_entries(status_path, tx, scan_conffiles).await })
    }

    fn verify(job: Self::Job, limits: ScanLimits) -> BoxFuture<Option<Finding>> {
        Box::pin(verify_one(job, limits))
    }
}

/// Streams dpkg verification
/// /var/lib/dpkg/info/*.md5sums manifests for regular files
/// conffiles checksums sourced from /var/lib/dpkg/status
async fn stream_dpkg_entries(
    status_path: PathBuf,
    tx: tokio::sync::mpsc::UnboundedSender<StreamItem<VerifyJob>>,
    scan_conffiles: bool,
) -> Result<()> {
    let installed = parse_dpkg_status(&status_path).await?;

    for pkg in installed {
        let pkg_name = pkg.name.clone();
        let pkg_arch = pkg.arch.clone();
        let pkg_version = pkg.version.clone();

        let _ = tx.send(StreamItem::Pkg);

        let mut seen: HashSet<PathBuf> = HashSet::new();

        // Regular files from .md5sums manifest (when present)
        match find_local_md5sums(&pkg_name, &pkg_arch).await? {
            Some(md5sums_path) => match fs::read(&md5sums_path).await {
                Ok(md5sums_data) => {
                    for (abs_path, expected) in iter_md5sums_entries(&md5sums_data) {
                        if seen.insert(abs_path.clone()) {
                            let _ = tx.send(StreamItem::File {
                                job: VerifyJob {
                                    pkg: pkg_name.clone(),
                                    path: abs_path,
                                    expected,
                                },
                            });
                        }
                    }
                }
                Err(e) => {
                    let _ = tx.send(StreamItem::Finding(Finding {
                        manager: "dpkg",
                        package: Some(pkg_name.to_string()),
                        path: Some(md5sums_path),
                        kind: FindingKind::Error,
                        details: format!("failed reading .md5sums: {e}"),
                    }));
                }
            },
            None => {
                // Not fatal: some packages legitimately have no md5sums manifest.
                // Record the condition, but continue (and still check conffiles below).
                let info = Path::new("/var/lib/dpkg/info");
                let p1 = info.join(format!("{pkg_name}.md5sums"));
                let p2 = if pkg_arch.as_ref() != "all" {
                    Some(info.join(format!("{pkg_name}:{}.md5sums", pkg_arch)))
                } else {
                    None
                };

                let detail = match p2 {
                    Some(p2) => format!(
                        "no local .md5sums for {pkg_name} {pkg_version} (arch={pkg_arch}); tried {} and {}",
                        p1.display(),
                        p2.display()
                    ),
                    None => format!(
                        "no local .md5sums for {pkg_name} {pkg_version} (arch={pkg_arch}); tried {}",
                        p1.display()
                    ),
                };

                let _ = tx.send(StreamItem::Finding(Finding {
                    manager: "dpkg",
                    package: Some(pkg_name.to_string()),
                    path: None,
                    kind: FindingKind::Error,
                    details: detail,
                }));
            }
        }

        // Config files from the status file (optional)
        if scan_conffiles {
            for (path, expected) in pkg.conffiles {
                if seen.insert(path.clone()) {
                    let _ = tx.send(StreamItem::File {
                        job: VerifyJob {
                            pkg: pkg_name.clone(),
                            path,
                            expected,
                        },
                    });
                }
            }
        }
    }

    Ok(())
}

/// Iterate dpkg .md5sums entries from raw bytes with minimal allocation.
/// Format is typically: "<32-hex><space><path>\n"
fn iter_md5sums_entries(data: &[u8]) -> impl Iterator<Item = (PathBuf, Md5Digest)> + '_ {
    data.split(|&b| b == b'\n').filter_map(|line| {
        let line = trim_ascii(line);
        if line.len() < 34 {
            return None;
        }
        // 32 hex + at least one whitespace
        let (hex, rest) = line.split_at(32);
        if !rest.first().is_some_and(|b| b.is_ascii_whitespace()) {
            return None;
        }
        let expected = parse_md5_hex_bytes(hex)?;
        let rel = trim_ascii(rest);

        if rel.is_empty() {
            return None;
        }

        // dpkg md5sums paths are usually relative (no leading '/'); handle both
        let rel_str = std::str::from_utf8(rel).ok()?;
        let abs = if rel_str.starts_with('/') {
            PathBuf::from(rel_str)
        } else {
            Path::new("/").join(rel_str)
        };

        Some((abs, expected))
    })
}

fn trim_ascii(mut s: &[u8]) -> &[u8] {
    while let Some(&b) = s.first() {
        if b.is_ascii_whitespace() {
            s = &s[1..];
        } else {
            break;
        }
    }
    while let Some(&b) = s.last() {
        if b.is_ascii_whitespace() {
            s = &s[..s.len() - 1];
        } else {
            break;
        }
    }
    s
}

fn parse_md5_hex_bytes(hex32: &[u8]) -> Option<Md5Digest> {
    if hex32.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        let hi = from_hex_nibble(hex32[2 * i])?;
        let lo = from_hex_nibble(hex32[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(Md5Digest(out))
}

fn from_hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

async fn parse_dpkg_status(path: &Path) -> Result<Vec<InstalledPkg>> {
    let data = fs::read(path).await?;
    let mut out = Vec::new();

    let mut name: Option<Arc<str>> = None;
    let mut version: Option<Arc<str>> = None;
    let mut arch: Option<Arc<str>> = None;
    let mut installed_ok = false;

    let mut conffiles: Vec<(PathBuf, Md5Digest)> = Vec::new();
    let mut in_conffiles = false;

    let flush = |out: &mut Vec<InstalledPkg>,
                 name: &mut Option<Arc<str>>,
                 version: &mut Option<Arc<str>>,
                 arch: &mut Option<Arc<str>>,
                 installed_ok: &mut bool,
                 conffiles: &mut Vec<(PathBuf, Md5Digest)>,
                 in_conffiles: &mut bool| {
        if *installed_ok
            && let (Some(n), Some(v), Some(a)) = (name.take(), version.take(), arch.take())
        {
            out.push(InstalledPkg {
                name: n,
                version: v,
                arch: a,
                conffiles: std::mem::take(conffiles),
            });
        }
        name.take();
        version.take();
        arch.take();
        *installed_ok = false;
        conffiles.clear();
        *in_conffiles = false;
    };

    for raw_line in data.split(|&b| b == b'\n') {
        let line = trim_ascii(raw_line);

        if line.is_empty() {
            flush(
                &mut out,
                &mut name,
                &mut version,
                &mut arch,
                &mut installed_ok,
                &mut conffiles,
                &mut in_conffiles,
            );
            continue;
        }

        // Keep "in_conffiles" state unless another field begins
        if starts_with_field(line, b"Package:") {
            if let Some(v) = str_value(line, b"Package:") {
                name = Some(v);
            }
            in_conffiles = false;
        } else if starts_with_field(line, b"Version:") {
            if let Some(v) = str_value(line, b"Version:") {
                version = Some(v);
            }
            in_conffiles = false;
        } else if starts_with_field(line, b"Architecture:") {
            if let Some(v) = str_value(line, b"Architecture:") {
                arch = Some(v);
            }
            in_conffiles = false;
        } else if starts_with_field(line, b"Status:") {
            if let Ok(v) = std::str::from_utf8(trim_ascii(&line[b"Status:".len()..]))
                && v.contains("install ok installed")
            {
                installed_ok = true;
            }
            in_conffiles = false;
        } else if line.starts_with(b"Conffiles:") {
            in_conffiles = true;
        } else if in_conffiles {
            if let Some((p, dig)) = parse_conffile_line(line) {
                conffiles.push((p, dig));
            } else {
                // If it doesn't parse, assume conffiles block ended.
                in_conffiles = false;
            }
        }
    }

    // flush last stanza if file doesn't end with blank line
    flush(
        &mut out,
        &mut name,
        &mut version,
        &mut arch,
        &mut installed_ok,
        &mut conffiles,
        &mut in_conffiles,
    );

    Ok(out)
}

fn starts_with_field(line: &[u8], field: &[u8]) -> bool {
    line.len() >= field.len() && &line[..field.len()] == field
}

fn str_value(line: &[u8], field: &[u8]) -> Option<Arc<str>> {
    let v = trim_ascii(&line[field.len()..]);
    let s = std::str::from_utf8(v).ok()?;
    Some(Arc::<str>::from(s))
}

fn parse_conffile_line(line: &[u8]) -> Option<(PathBuf, Md5Digest)> {
    // Expect: "/path" <ws> "<32hex>" [ws ...]
    let mut it = line
        .split(|b| b.is_ascii_whitespace())
        .filter(|p| !p.is_empty());
    let p = it.next()?;
    if p.first()? != &b'/' {
        return None;
    }
    let md5hex = it.next()?;
    if md5hex.len() != 32 {
        return None;
    }
    let dig = parse_md5_hex_bytes(md5hex)?;
    let p_str = std::str::from_utf8(p).ok()?;
    Some((PathBuf::from(p_str), dig))
}

async fn find_local_md5sums(pkg: &str, arch: &str) -> Result<Option<PathBuf>> {
    let info = Path::new("/var/lib/dpkg/info");
    let c1 = info.join(format!("{pkg}.md5sums"));
    if fs::try_exists(&c1).await.unwrap_or(false) {
        return Ok(Some(c1));
    }
    if arch != "all" {
        let c2 = info.join(format!("{pkg}:{arch}.md5sums"));
        if fs::try_exists(&c2).await.unwrap_or(false) {
            return Ok(Some(c2));
        }
    }
    Ok(None)
}

async fn verify_one(job: VerifyJob, limits: ScanLimits) -> Option<Finding> {
    let VerifyJob {
        pkg,
        path,
        expected,
    } = job;
    let meta = match fs::symlink_metadata(&path).await {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Some(Finding {
                manager: "dpkg",
                package: Some(pkg.to_string()),
                path: Some(path),
                kind: FindingKind::Missing,
                details: "missing file".into(),
            });
        }
        Err(e) => {
            return Some(Finding {
                manager: "dpkg",
                package: Some(pkg.to_string()),
                path: Some(path),
                kind: FindingKind::Error,
                details: format!("metadata error: {e}"),
            });
        }
    };

    if meta.file_type().is_symlink() {
        return Some(Finding {
            manager: "dpkg",
            package: Some(pkg.to_string()),
            path: Some(path),
            kind: FindingKind::Modified,
            details: "unexpected symlink (expected regular file)".into(),
        });
    }

    if !meta.is_file() {
        return None;
    }

    let permit = match limits.hash_sem.clone().acquire_owned().await {
        Ok(p) => p,
        Err(_) => {
            return Some(Finding {
                manager: "dpkg",
                package: Some(pkg.to_string()),
                path: Some(path),
                kind: FindingKind::Error,
                details: "hash semaphore closed".into(),
            });
        }
    };

    let path2 = path.clone();
    let actual = tokio::task::spawn_blocking(move || md5_file_blocking(&path2)).await;
    drop(permit);

    let actual = match actual {
        Err(e) => {
            return Some(Finding {
                manager: "dpkg",
                package: Some(pkg.to_string()),
                path: Some(path),
                kind: FindingKind::Error,
                details: format!("hash join error: {e}"),
            });
        }
        Ok(Err(e)) => {
            return Some(Finding {
                manager: "dpkg",
                package: Some(pkg.to_string()),
                path: Some(path),
                kind: FindingKind::Error,
                details: format!("md5 read/hash error: {e}"),
            });
        }
        Ok(Ok(v)) => v,
    };

    if expected != actual {
        return Some(Finding {
            manager: "dpkg",
            package: Some(pkg.to_string()),
            path: Some(path),
            kind: FindingKind::Modified,
            details: format!(
                "md5 mismatch expected={} actual={}",
                digest_to_hex(expected),
                digest_to_hex(actual)
            ),
        });
    }

    None
}

fn digest_to_hex(d: Md5Digest) -> String {
    format!("{:x}", d)
}

fn md5_file_blocking(path: &Path) -> std::io::Result<Md5Digest> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut ctx = Md5Ctx::new();
    let mut buf = [0u8; 131072];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        ctx.consume(&buf[..n]);
    }
    Ok(ctx.finalize())
}
