use anyhow::{Context, Result, anyhow};
use flate2::read::GzDecoder;
use md5::Context as Md5Ctx;
use sha2::{Digest as Sha2Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::{Error, ErrorKind, Read};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;

use super::{
    BoxFuture, Finding, FindingKind, ManagerReport, ScanLimits, StreamItem, StreamScanManager,
};

#[derive(Clone, Debug, Default)]
struct ExpectedMeta {
    mode: Option<u32>,
    size: Option<u64>,
    uid: Option<u32>,
    gid: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExpectedType {
    File,
    Dir,
    Link,
}

#[derive(Clone, Debug)]
struct VerifyJob {
    pkg: Arc<str>,
    path: PathBuf,
    expected_type: ExpectedType,
    expected_sha256_hex: Option<Arc<str>>,
    expected_md5_hex: Option<Arc<str>>,
    expected_link: Option<Arc<str>>,
    expected_meta: ExpectedMeta,
}

/// scans pacman's local database at /var/lib/pacman/local
/// uses the per-package "files" list as the definitive installed path list
/// and filters mtree entries against it to avoid false positives from build artifacts.
pub async fn scan(limits: ScanLimits) -> Result<ManagerReport> {
    let local_root = Path::new("/var/lib/pacman/local");

    if !fs::try_exists(local_root).await.unwrap_or(false) {
        return Ok(ManagerReport {
            manager: "pacman",
            ..Default::default()
        });
    }

    Ok(super::run_stream_scan::<PacmanScanner>(limits).await)
}

struct PacmanScanner;

impl StreamScanManager for PacmanScanner {
    const MANAGER: &'static str = "pacman";
    type Job = VerifyJob;

    fn producer_label() -> &'static str {
        "pacman local db scan"
    }

    fn producer_error_path() -> Option<PathBuf> {
        Some(PathBuf::from("/var/lib/pacman/local"))
    }

    fn spawn_producer(
        limits: ScanLimits,
        tx: tokio::sync::mpsc::UnboundedSender<StreamItem<Self::Job>>,
    ) -> tokio::task::JoinHandle<anyhow::Result<()>> {
        let local_root = PathBuf::from("/var/lib/pacman/local");
        let scan_conffiles = limits.scan_conffiles;
        tokio::task::spawn_blocking(move || {
            stream_pacman_local_entries(&local_root, tx, scan_conffiles)
        })
    }

    fn verify(job: Self::Job, limits: ScanLimits) -> BoxFuture<Option<Finding>> {
        Box::pin(verify_one(job, limits))
    }
}

#[derive(Debug, Default)]
struct PkgMeta {
    name: String,
    version: String,
    arch: String,
    backup_paths: HashSet<String>, // normalized rel paths (no leading /, no trailing /)
}

#[derive(Debug, Default)]
struct PkgFiles {
    installed_paths: HashSet<String>, // normalized rel paths
    backup_paths: HashSet<String>,    // normalized rel paths
}

fn stream_pacman_local_entries(
    local_root: &Path,
    tx: tokio::sync::mpsc::UnboundedSender<StreamItem<VerifyJob>>,
    scan_conffiles: bool,
) -> Result<()> {
    use std::fs;

    let rd = fs::read_dir(local_root).context("read /var/lib/pacman/local")?;

    for ent in rd {
        let ent = ent.context("read_dir entry")?;
        let ft = ent.file_type().context("dir entry file_type")?;
        if !ft.is_dir() {
            continue;
        }

        let pkg_dir = ent.path();

        // required files in each package dir: desc, files, mtree
        let desc_path = pkg_dir.join("desc");
        let files_path = pkg_dir.join("files");
        let mtree_path = pkg_dir.join("mtree");

        if !(desc_path.exists() && files_path.exists()) {
            // ignore odd directories
            continue;
        }

        let meta = parse_desc(&desc_path).with_context(|| format!("parse desc {:?}", desc_path))?;
        let files =
            parse_files(&files_path).with_context(|| format!("parse files {:?}", files_path))?;

        // union backup lists from desc + files
        let mut backup = meta.backup_paths;
        backup.extend(files.backup_paths.into_iter());

        let name = if meta.name.is_empty() {
            "unknown".to_string()
        } else {
            meta.name
        };
        let version = if meta.version.is_empty() {
            "0".to_string()
        } else {
            meta.version
        };
        let arch = meta.arch;

        let pkg_id: Arc<str> = if arch.trim().is_empty() {
            Arc::<str>::from(format!("{name}-{version}"))
        } else {
            Arc::<str>::from(format!("{name}-{version}-{arch}"))
        };

        let _ = tx.send(StreamItem::Pkg);

        // mtree is preferred for metadata/digest; if missing, still do existence checks via files list.
        if !mtree_path.exists() {
            for rel in files.installed_paths.iter() {
                if !scan_conffiles && backup.contains(rel) {
                    continue;
                }
                let abs = PathBuf::from("/").join(rel);
                let _ = tx.send(StreamItem::File {
                    job: VerifyJob {
                        pkg: pkg_id.clone(),
                        path: abs,
                        expected_type: ExpectedType::File, // unknown; treat as file for existence check
                        expected_sha256_hex: None,
                        expected_md5_hex: None,
                        expected_link: None,
                        expected_meta: ExpectedMeta::default(),
                    },
                });
            }
            continue;
        }

        // XXX: prob optimal to stream mtree instead of storing in memory, but prob fine
        let mtree_text = read_pacman_mtree_text(&mtree_path)
            .with_context(|| format!("read mtree {:?}", mtree_path))?;

        parse_mtree_and_send(
            &mtree_text,
            &files.installed_paths,
            &backup,
            scan_conffiles,
            &pkg_id,
            &tx,
        )
        .with_context(|| format!("parse mtree {:?}", mtree_path))?;
    }

    Ok(())
}

fn parse_desc(path: &Path) -> Result<PkgMeta> {
    use std::fs;

    let data = fs::read_to_string(path).with_context(|| format!("read {path:?}"))?;
    let sec = parse_sectioned_kv(&data);

    let mut meta = PkgMeta {
        name: sec
            .get("NAME")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default(),
        version: sec
            .get("VERSION")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default(),
        arch: sec
            .get("ARCH")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default(),
        ..Default::default()
    };

    if let Some(b) = sec.get("BACKUP") {
        for line in b {
            if let Some(p) = parse_backup_line_to_rel(line) {
                meta.backup_paths.insert(p);
            }
        }
    }

    Ok(meta)
}

fn parse_files(path: &Path) -> Result<PkgFiles> {
    use std::fs;

    let data = fs::read_to_string(path).with_context(|| format!("read {path:?}"))?;
    let sec = parse_sectioned_kv(&data);

    let mut out = PkgFiles::default();

    if let Some(v) = sec.get("FILES") {
        for line in v {
            if let Some(rel) = normalize_rel_path(line) {
                out.installed_paths.insert(rel);
            }
        }
    }

    if let Some(v) = sec.get("BACKUP") {
        for line in v {
            if let Some(rel) = parse_backup_line_to_rel(line) {
                out.backup_paths.insert(rel);
            }
        }
    }

    Ok(out)
}

fn parse_sectioned_kv(data: &str) -> HashMap<String, Vec<String>> {
    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    let mut cur: Option<String> = None;

    for raw in data.lines() {
        let line = raw.trim_end();

        if line.starts_with('%') && line.ends_with('%') && line.len() >= 3 {
            let k = line.trim_matches('%').to_string();
            cur = Some(k);
            continue;
        }

        let Some(k) = cur.as_ref() else { continue };
        if line.is_empty() {
            continue;
        }
        out.entry(k.clone()).or_default().push(line.to_string());
    }

    out
}

fn parse_backup_line_to_rel(line: &str) -> Option<String> {
    // usually: "etc/foo.conf\t<md5>"
    let p = match line.split_once('\t') {
        Some((p, _)) => p,
        None => line.split_whitespace().next().unwrap_or(""),
    };
    normalize_rel_path(p)
}

fn read_pacman_mtree_text(path: &Path) -> Result<String> {
    use std::fs;

    let data = fs::read(path).with_context(|| format!("read {path:?}"))?;

    // local db mtree is typically gzip-compressed
    if data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b {
        let mut dec = GzDecoder::new(&data[..]);
        let mut s = String::new();
        dec.read_to_string(&mut s)
            .context("gunzip mtree into string")?;
        Ok(s)
    } else {
        String::from_utf8(data).context("mtree is not valid utf-8")
    }
}

#[derive(Clone, Debug, Default)]
struct MtreeDefaults {
    ty: Option<ExpectedType>,
    uid: Option<u32>,
    gid: Option<u32>,
    mode: Option<u32>,
}

/// XXX: consider skipping things such as usr/share/doc, usr/share/man, and user/share/info
fn parse_mtree_and_send(
    mtree: &str,
    installed: &HashSet<String>,
    backup: &HashSet<String>,
    scan_conffiles: bool,
    pkg: &Arc<str>,
    tx: &tokio::sync::mpsc::UnboundedSender<StreamItem<VerifyJob>>,
) -> Result<()> {
    let mut defs = MtreeDefaults::default();

    for raw in mtree.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // /set or set
        if let Some(rest) = line
            .strip_prefix("/set")
            .or_else(|| line.strip_prefix("set"))
        {
            for tok in rest.split_whitespace() {
                if let Some((k, v)) = tok.split_once('=') {
                    apply_mtree_kv_to_defaults(&mut defs, k, v);
                }
            }
            continue;
        }

        // /unset or unset
        if let Some(rest) = line
            .strip_prefix("/unset")
            .or_else(|| line.strip_prefix("unset"))
        {
            for k in rest.split_whitespace() {
                let k = k.trim().to_ascii_lowercase().replace('_', "");
                match k.as_str() {
                    "type" => defs.ty = None,
                    "uid" => defs.uid = None,
                    "gid" => defs.gid = None,
                    "mode" => defs.mode = None,
                    _ => {}
                }
            }
            continue;
        }

        let mut it = line.split_whitespace();
        let Some(path_tok) = it.next() else { continue };
        let path_tok = mtree_unescape(path_tok);
        let Some(rel) = normalize_rel_path(&path_tok) else {
            continue;
        };

        if !installed.contains(&rel) {
            continue;
        }
        if !scan_conffiles && backup.contains(&rel) {
            continue;
        }

        let mut expected_type = defs.ty;
        let mut expected_meta = ExpectedMeta {
            mode: defs.mode,
            size: None,
            uid: defs.uid,
            gid: defs.gid,
        };
        let mut sha256: Option<Arc<str>> = None;
        let mut md5: Option<Arc<str>> = None;
        let mut link: Option<Arc<str>> = None;

        for tok in it {
            let Some((k0, v0)) = tok.split_once('=') else {
                continue;
            };
            let v = mtree_unescape(v0);
            let k = k0.trim().to_ascii_lowercase().replace('_', "");
            match k.as_str() {
                "type" => expected_type = parse_mtree_type(&v),
                "mode" => expected_meta.mode = parse_mode_octal(&v),
                "size" => expected_meta.size = v.parse::<u64>().ok(),
                "uid" => expected_meta.uid = v.parse::<u32>().ok(),
                "gid" => expected_meta.gid = v.parse::<u32>().ok(),
                "sha256digest" | "sha256" => sha256 = Some(Arc::<str>::from(v)),
                "md5digest" | "md5" => md5 = Some(Arc::<str>::from(v)),
                "link" => link = Some(Arc::<str>::from(v)),
                _ => {}
            }
        }

        let Some(expected_type) = expected_type else {
            // mtree requires type; skip if missing
            continue;
        };

        // file entries should have sha256digest; older ones may have md5digest too.
        // keep both; verifier prefers sha256 if present.
        let abs = PathBuf::from("/").join(&rel);

        let _ = tx.send(StreamItem::File {
            job: VerifyJob {
                pkg: pkg.clone(),
                path: abs,
                expected_type,
                expected_sha256_hex: sha256,
                expected_md5_hex: md5,
                expected_link: link,
                expected_meta,
            },
        });
    }

    Ok(())
}

fn apply_mtree_kv_to_defaults(defs: &mut MtreeDefaults, k0: &str, v0: &str) {
    let k = k0.trim().to_ascii_lowercase().replace('_', "");
    let v = v0.trim();
    match k.as_str() {
        "type" => defs.ty = parse_mtree_type(v),
        "uid" => defs.uid = v.parse::<u32>().ok(),
        "gid" => defs.gid = v.parse::<u32>().ok(),
        "mode" => defs.mode = parse_mode_octal(v),
        _ => {}
    }
}

fn parse_mtree_type(s: &str) -> Option<ExpectedType> {
    match s.trim() {
        "file" => Some(ExpectedType::File),
        "dir" => Some(ExpectedType::Dir),
        "link" => Some(ExpectedType::Link),
        _ => None,
    }
}

fn parse_mode_octal(s: &str) -> Option<u32> {
    let s = s.trim();
    let s = s.strip_prefix("0o").unwrap_or(s);
    u32::from_str_radix(s, 8).ok()
}

fn normalize_rel_path(s: &str) -> Option<String> {
    let mut p = s.trim();
    if p.is_empty() {
        return None;
    }
    while let Some(rest) = p.strip_prefix("./") {
        p = rest;
    }
    if let Some(rest) = p.strip_prefix('/') {
        p = rest;
    }
    p = p.trim_end_matches('/');
    if p.is_empty() || p == "." {
        return None;
    }
    Some(p.to_string())
}

fn mtree_unescape(s: &str) -> String {
    // mtree uses octal escapes like \040 for spaces
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());

    let mut i = 0usize;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() {
            let d1 = b[i + 1];
            let d2 = b[i + 2];
            let d3 = b[i + 3];
            let is_oct = |c: u8| (b'0'..=b'7').contains(&c);
            if is_oct(d1) && is_oct(d2) && is_oct(d3) {
                let v = (d1 - b'0') * 64 + (d2 - b'0') * 8 + (d3 - b'0');
                out.push(v);
                i += 4;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }

    String::from_utf8_lossy(&out).to_string()
}

async fn verify_one(job: VerifyJob, limits: ScanLimits) -> Option<Finding> {
    let VerifyJob {
        pkg,
        path,
        expected_type,
        expected_sha256_hex,
        expected_md5_hex,
        expected_link,
        expected_meta,
    } = job;

    let meta = match fs::symlink_metadata(&path).await {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Some(Finding {
                manager: "pacman",
                package: Some(pkg.to_string()),
                path: Some(path),
                kind: FindingKind::Missing,
                details: "missing path".into(),
            });
        }
        Err(e) => {
            return Some(Finding {
                manager: "pacman",
                package: Some(pkg.to_string()),
                path: Some(path),
                kind: FindingKind::Error,
                details: format!("metadata error: {e}"),
            });
        }
    };

    let ft = meta.file_type();

    // type check
    match expected_type {
        ExpectedType::File if !meta.is_file() => {
            return Some(Finding {
                manager: "pacman",
                package: Some(pkg.to_string()),
                path: Some(path),
                kind: FindingKind::Modified,
                details: "unexpected type (expected file)".to_string(),
            });
        }
        ExpectedType::Dir if !ft.is_dir() => {
            return Some(Finding {
                manager: "pacman",
                package: Some(pkg.to_string()),
                path: Some(path),
                kind: FindingKind::Modified,
                details: "unexpected type (expected dir)".to_string(),
            });
        }
        ExpectedType::Link if !ft.is_symlink() => {
            return Some(Finding {
                manager: "pacman",
                package: Some(pkg.to_string()),
                path: Some(path),
                kind: FindingKind::Modified,
                details: "unexpected type (expected symlink)".to_string(),
            });
        }
        _ => {}
    }

    let mut meta_diffs: Vec<String> = Vec::new();

    // uid/gid + mode checks (symlink perms are not meaningful)
    if !ft.is_symlink()
        && let Some(exp_mode) = expected_meta.mode
    {
        let actual_mode = meta.permissions().mode() & 0o7777;
        let exp_mode = exp_mode & 0o7777;
        if actual_mode != exp_mode {
            meta_diffs.push(format!("mode {:o} != {:o}", actual_mode, exp_mode));
        }
    }

    if let Some(exp_uid) = expected_meta.uid {
        let actual_uid = meta.uid();
        if actual_uid != exp_uid {
            meta_diffs.push(format!("uid {} != {}", actual_uid, exp_uid));
        }
    }
    if let Some(exp_gid) = expected_meta.gid {
        let actual_gid = meta.gid();
        if actual_gid != exp_gid {
            meta_diffs.push(format!("gid {} != {}", actual_gid, exp_gid));
        }
    }

    if expected_type == ExpectedType::File
        && let Some(exp_size) = expected_meta.size
    {
        let actual_size = meta.len();
        if actual_size != exp_size {
            meta_diffs.push(format!("size {} != {}", actual_size, exp_size));
        }
    }

    // symlink target check
    if expected_type == ExpectedType::Link {
        if let Some(exp) = expected_link.as_deref() {
            match fs::read_link(&path).await {
                Ok(t) => {
                    let actual = t.to_string_lossy();
                    if actual.as_ref() != exp {
                        return Some(Finding {
                            manager: "pacman",
                            package: Some(pkg.to_string()),
                            path: Some(path),
                            kind: FindingKind::Modified,
                            details: format!(
                                "symlink target mismatch expected={} actual={}",
                                exp, actual
                            ),
                        });
                    }
                }
                Err(e) => {
                    return Some(Finding {
                        manager: "pacman",
                        package: Some(pkg.to_string()),
                        path: Some(path),
                        kind: FindingKind::Error,
                        details: format!("read_link error: {e}"),
                    });
                }
            }
        }

        if !meta_diffs.is_empty() {
            return Some(Finding {
                manager: "pacman",
                package: Some(pkg.to_string()),
                path: Some(path),
                kind: FindingKind::MetadataChanged,
                details: meta_diffs.join(", "),
            });
        }
        return None;
    }

    // directory: metadata-only
    if expected_type == ExpectedType::Dir {
        if !meta_diffs.is_empty() {
            return Some(Finding {
                manager: "pacman",
                package: Some(pkg.to_string()),
                path: Some(path),
                kind: FindingKind::MetadataChanged,
                details: meta_diffs.join(", "),
            });
        }
        return None;
    }

    // file: optional digest check
    if expected_type == ExpectedType::File {
        let (algo, expected_hex) = if let Some(s) = expected_sha256_hex.as_deref() {
            ("sha256", Some(s))
        } else if let Some(s) = expected_md5_hex.as_deref() {
            ("md5", Some(s))
        } else {
            ("none", None)
        };

        if let Some(expected_hex) = expected_hex {
            let permit = match limits.hash_sem.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => {
                    return Some(Finding {
                        manager: "pacman",
                        package: Some(pkg.to_string()),
                        path: Some(path),
                        kind: FindingKind::Error,
                        details: "hash semaphore closed".into(),
                    });
                }
            };

            let path2 = path.clone();
            let expected2 = expected_hex.to_string();
            let algo2 = algo.to_string();

            let actual_hex = tokio::task::spawn_blocking(move || match algo2.as_str() {
                "sha256" => file_sha256_hex_blocking(&path2),
                "md5" => file_md5_hex_blocking(&path2),
                _ => Err(Error::new(ErrorKind::InvalidData, "no digest algorithm")),
            })
            .await;

            drop(permit);

            let actual_hex = match actual_hex {
                Err(e) => {
                    return Some(Finding {
                        manager: "pacman",
                        package: Some(pkg.to_string()),
                        path: Some(path),
                        kind: FindingKind::Error,
                        details: format!("hash join error: {e}"),
                    });
                }
                Ok(Err(e)) => {
                    return Some(Finding {
                        manager: "pacman",
                        package: Some(pkg.to_string()),
                        path: Some(path),
                        kind: FindingKind::Error,
                        details: format!("digest read/hash error: {e} (algo={algo})"),
                    });
                }
                Ok(Ok(v)) => v,
            };

            if !expected2.eq_ignore_ascii_case(&actual_hex) {
                return Some(Finding {
                    manager: "pacman",
                    package: Some(pkg.to_string()),
                    path: Some(path),
                    kind: FindingKind::Modified,
                    details: format!(
                        "digest mismatch algo={} expected={} actual={}",
                        algo, expected2, actual_hex
                    ),
                });
            }
        }

        if !meta_diffs.is_empty() {
            return Some(Finding {
                manager: "pacman",
                package: Some(pkg.to_string()),
                path: Some(path),
                kind: FindingKind::MetadataChanged,
                details: meta_diffs.join(", "),
            });
        }

        return None;
    }

    Some(Finding {
        manager: "pacman",
        package: Some(pkg.to_string()),
        path: Some(path),
        kind: FindingKind::Error,
        details: anyhow!("unreachable state").to_string(),
    })
}

fn file_sha256_hex_blocking(path: &Path) -> std::io::Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut buf = [0u8; 131072];

    let mut h = Sha256::new();
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex_lower(&h.finalize()))
}

fn file_md5_hex_blocking(path: &Path) -> std::io::Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut buf = [0u8; 131072];

    let mut ctx = Md5Ctx::new();
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        ctx.consume(&buf[..n]);
    }
    Ok(format!("{:x}", ctx.finalize()))
}

fn hex_lower(b: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(b.len() * 2);
    for &x in b {
        out.push(LUT[(x >> 4) as usize] as char);
        out.push(LUT[(x & 0x0f) as usize] as char);
    }
    out
}
