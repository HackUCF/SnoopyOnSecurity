use anyhow::{Context, Result, anyhow};
use md5::Context as Md5Ctx;
use sha1::Digest as Sha1Digest;
use sha2::{Sha224, Sha256, Sha384, Sha512};
use sqlx::{Connection as _, Row, SqliteConnection, sqlite::SqliteConnectOptions};
use std::collections::HashMap;
use std::io::{Error, ErrorKind, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;

use super::{
    BoxFuture, Finding, FindingKind, ManagerReport, ScanLimits, StreamItem, StreamScanManager,
};

#[derive(Clone, Debug, Default)]
struct ExpectedMeta {
    mode: Option<u32>, // compared against 0o7777
    size: Option<u64>,
}

#[derive(Clone, Debug)]
struct VerifyJob {
    pkg: Arc<str>,
    algo: u32,
    path: PathBuf,
    expected_hex: Arc<str>,
    expected_meta: ExpectedMeta,
}

pub async fn scan(limits: ScanLimits) -> Result<ManagerReport> {
    let db_path = Path::new("/var/lib/rpm/rpmdb.sqlite");
    if !fs::try_exists(db_path).await.unwrap_or(false) {
        if fs::try_exists("/var/lib/rpm/Packages")
            .await
            .unwrap_or(false)
        {
            return Ok(ManagerReport {
                manager: "rpm",
                checked_packages: 0,
                checked_files: 0,
                findings: vec![Finding {
                    manager: "rpm",
                    package: None,
                    path: Some(PathBuf::from("/var/lib/rpm/Packages")),
                    kind: FindingKind::Error,
                    details: "rpmdb.sqlite missing; BDB rpmdb not implemented".into(),
                }],
            });
        }
        return Ok(ManagerReport {
            manager: "rpm",
            ..Default::default()
        });
    }

    Ok(super::run_stream_scan::<RpmScanner>(limits).await)
}

struct RpmScanner;

impl StreamScanManager for RpmScanner {
    const MANAGER: &'static str = "rpm";
    type Job = VerifyJob;

    fn producer_label() -> &'static str {
        "rpmdb extract"
    }

    fn producer_error_path() -> Option<PathBuf> {
        Some(PathBuf::from("/var/lib/rpm/rpmdb.sqlite"))
    }

    fn spawn_producer(
        limits: ScanLimits,
        tx: tokio::sync::mpsc::UnboundedSender<StreamItem<Self::Job>>,
    ) -> tokio::task::JoinHandle<anyhow::Result<()>> {
        let db_path = PathBuf::from("/var/lib/rpm/rpmdb.sqlite");
        let scan_conffiles = limits.scan_conffiles;

        // Keep producer in blocking pool: parsing lots of blobs is CPU-heavy anyway.
        tokio::task::spawn_blocking(move || stream_rpmdb_entries(&db_path, tx, scan_conffiles))
    }

    fn verify(job: Self::Job, limits: ScanLimits) -> BoxFuture<Option<Finding>> {
        Box::pin(verify_one(job, limits))
    }
}

fn stream_rpmdb_entries(
    db_path: &Path,
    tx: tokio::sync::mpsc::UnboundedSender<StreamItem<VerifyJob>>,
    scan_conffiles: bool,
) -> Result<()> {
    // We're in a blocking thread. Use the *existing* Tokio runtime to block_on sqlx async
    // this is def has some code smell to it, but I don't want to refactor the whole thing
    let handle = tokio::runtime::Handle::current();

    handle.block_on(async move {
        let opts = SqliteConnectOptions::new()
            .filename(db_path)
            .read_only(true);

        let mut conn = SqliteConnection::connect_with(&opts)
            .await
            .context("open rpmdb.sqlite")?;

        // No futures_util: fetch_all and iterate.
        let rows = sqlx::query("SELECT blob FROM Packages")
            .fetch_all(&mut conn)
            .await
            .context("query rpmdb Packages")?;

        for row in rows {
            let blob: Vec<u8> = row.try_get(0).context("read blob")?;
            let hdr = parse_rpm_header(&blob).context("parse rpm header blob")?;

            let algo = hdr.get_u32(5011).unwrap_or(0);

            let dirnames = hdr.get_string_array(1118).unwrap_or_default();
            let basenames = hdr.get_string_array(1117).unwrap_or_default();
            let diridx = hdr.get_i32_array(1116).unwrap_or_default();
            let digests = hdr.get_string_array(1035).unwrap_or_default();

            let fileflags = hdr.get_i32_array(1037).unwrap_or_default(); // RPMTAG_FILEFLAGS
            let filemodes = hdr.get_u16_array(1030).unwrap_or_default(); // RPMTAG_FILEMODES (INT16)
            let filesizes = hdr.get_i32_array(1028).unwrap_or_default(); // RPMTAG_FILESIZES (INT32)

            let name = hdr.get_string(1000).unwrap_or("unknown");
            let ver = hdr.get_string(1001).unwrap_or("0");
            let rel = hdr.get_string(1002).unwrap_or("0");
            let arch = hdr.get_string(1022).unwrap_or("noarch");

            let pkg: Arc<str> = Arc::<str>::from(format!("{name}-{ver}-{rel}.{arch}"));
            let _ = tx.send(StreamItem::Pkg);

            const RPMFILE_CONFIG: i32 = 1 << 0;

            let n = basenames
                .len()
                .min(diridx.len())
                .min(digests.len())
                .min(fileflags.len());

            for i in 0..n {
                if !scan_conffiles && (fileflags[i] & RPMFILE_CONFIG) != 0 {
                    continue;
                }

                let d = diridx[i];
                if d < 0 {
                    continue;
                }
                let d = d as usize;
                if d >= dirnames.len() {
                    continue;
                }

                let expected = digests[i].trim();
                if expected.is_empty() {
                    continue;
                }

                let p = PathBuf::from(&dirnames[d]).join(&basenames[i]);

                let expected_meta = ExpectedMeta {
                    mode: filemodes.get(i).map(|m| *m as u32),
                    size: filesizes.get(i).map(|s| *s as u64),
                };

                let _ = tx.send(StreamItem::File {
                    job: VerifyJob {
                        pkg: pkg.clone(),
                        algo,
                        path: p,
                        expected_hex: Arc::<str>::from(expected.to_string()),
                        expected_meta,
                    },
                });
            }
        }

        Ok::<(), anyhow::Error>(())
    })
}

async fn verify_one(job: VerifyJob, limits: ScanLimits) -> Option<Finding> {
    let VerifyJob {
        pkg,
        algo,
        path,
        expected_hex,
        expected_meta,
    } = job;

    let meta = match fs::symlink_metadata(&path).await {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Some(Finding {
                manager: "rpm",
                package: Some(pkg.to_string()),
                path: Some(path),
                kind: FindingKind::Missing,
                details: "missing file".into(),
            });
        }
        Err(e) => {
            return Some(Finding {
                manager: "rpm",
                package: Some(pkg.to_string()),
                path: Some(path),
                kind: FindingKind::Error,
                details: format!("metadata error: {e}"),
            });
        }
    };

    if meta.file_type().is_symlink() {
        return Some(Finding {
            manager: "rpm",
            package: Some(pkg.to_string()),
            path: Some(path),
            kind: FindingKind::Modified,
            details: "unexpected symlink (expected regular file)".into(),
        });
    }

    if !meta.is_file() {
        return None;
    }

    let mut meta_diffs: Vec<String> = Vec::new();

    if let Some(exp_mode) = expected_meta.mode {
        let actual_mode = meta.permissions().mode() & 0o7777;
        let exp_mode = exp_mode & 0o7777;
        if actual_mode != exp_mode {
            meta_diffs.push(format!("mode {:o} != {:o}", actual_mode, exp_mode));
        }
    }

    if let Some(exp_size) = expected_meta.size {
        let actual_size = meta.len();
        if actual_size != exp_size {
            meta_diffs.push(format!("size {} != {}", actual_size, exp_size));
        }
    }

    // hash gating
    let permit = match limits.hash_sem.clone().acquire_owned().await {
        Ok(p) => p,
        Err(_) => {
            return Some(Finding {
                manager: "rpm",
                package: Some(pkg.to_string()),
                path: Some(path),
                kind: FindingKind::Error,
                details: "hash semaphore closed".into(),
            });
        }
    };

    let path2 = path.clone();
    let actual_hex =
        tokio::task::spawn_blocking(move || file_digest_hex_blocking(&path2, algo)).await;
    drop(permit);

    let actual_hex = match actual_hex {
        Err(e) => {
            return Some(Finding {
                manager: "rpm",
                package: Some(pkg.to_string()),
                path: Some(path),
                kind: FindingKind::Error,
                details: format!("hash join error: {e}"),
            });
        }
        Ok(Err(e)) => {
            return Some(Finding {
                manager: "rpm",
                package: Some(pkg.to_string()),
                path: Some(path),
                kind: FindingKind::Error,
                details: format!("digest read/hash error: {e} (algo={algo})"),
            });
        }
        Ok(Ok(v)) => v,
    };

    if !expected_hex.eq_ignore_ascii_case(&actual_hex) {
        return Some(Finding {
            manager: "rpm",
            package: Some(pkg.to_string()),
            path: Some(path),
            kind: FindingKind::Modified,
            details: format!(
                "digest mismatch expected={} actual={}",
                expected_hex, actual_hex
            ),
        });
    }

    if !meta_diffs.is_empty() {
        return Some(Finding {
            manager: "rpm",
            package: Some(pkg.to_string()),
            path: Some(path),
            kind: FindingKind::MetadataChanged,
            details: meta_diffs.join(", "),
        });
    }

    None
}

fn file_digest_hex_blocking(path: &Path, algo: u32) -> std::io::Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut buf = [0u8; 131072];

    match algo {
        0 | 1 => {
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
        2 => {
            let mut h = sha1::Sha1::new();
            loop {
                let n = f.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
            }
            Ok(hex_lower(&h.finalize()))
        }
        8 => {
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
        9 => {
            let mut h = Sha384::new();
            loop {
                let n = f.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
            }
            Ok(hex_lower(&h.finalize()))
        }
        10 => {
            let mut h = Sha512::new();
            loop {
                let n = f.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
            }
            Ok(hex_lower(&h.finalize()))
        }
        11 => {
            let mut h = Sha224::new();
            loop {
                let n = f.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
            }
            Ok(hex_lower(&h.finalize()))
        }
        _ => Err(Error::new(
            ErrorKind::InvalidData,
            format!("unsupported filedigestalgo={algo}"),
        )),
    }
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

#[derive(Default)]
struct RpmHeader {
    entries: HashMap<u32, (u32, u32, i32)>,
    data: Vec<u8>,
}

impl RpmHeader {
    fn get_string(&self, tag: u32) -> Option<&str> {
        let (ty, count, off) = self.entries.get(&tag).copied()?;
        if ty != 6 || count != 1 || off < 0 {
            return None;
        }
        let off = off as usize;
        let end = self.data[off..].iter().position(|&b| b == 0)?;
        std::str::from_utf8(&self.data[off..off + end]).ok()
    }

    fn get_u32(&self, tag: u32) -> Option<u32> {
        let (ty, count, off) = self.entries.get(&tag).copied()?;
        if ty != 4 || count != 1 || off < 0 {
            return None;
        }
        let off = off as usize;
        if off + 4 > self.data.len() {
            return None;
        }
        Some(u32::from_be_bytes(self.data[off..off + 4].try_into().ok()?))
    }

    fn get_string_array(&self, tag: u32) -> Option<Vec<String>> {
        let (ty, count, off) = self.entries.get(&tag).copied()?;
        if ty != 8 || off < 0 {
            return None;
        }
        let mut out = Vec::with_capacity(count as usize);
        let mut cur = off as usize;
        for _ in 0..count {
            if cur >= self.data.len() {
                return None;
            }
            let end = self.data[cur..].iter().position(|&b| b == 0)?;
            let s = std::str::from_utf8(&self.data[cur..cur + end])
                .ok()?
                .to_string();
            out.push(s);
            cur = cur + end + 1;
        }
        Some(out)
    }

    fn get_i32_array(&self, tag: u32) -> Option<Vec<i32>> {
        let (ty, count, off) = self.entries.get(&tag).copied()?;
        if ty != 4 || off < 0 {
            return None;
        }
        let off = off as usize;
        let need = (count as usize).checked_mul(4)?;
        if off + need > self.data.len() {
            return None;
        }
        let mut out = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            let base = off + i * 4;
            let v = i32::from_be_bytes(self.data[base..base + 4].try_into().ok()?);
            out.push(v);
        }
        Some(out)
    }

    // RPM_INT16_TYPE (ty=3): used for FILEMODES
    fn get_u16_array(&self, tag: u32) -> Option<Vec<u16>> {
        let (ty, count, off) = self.entries.get(&tag).copied()?;
        if ty != 3 || off < 0 {
            return None;
        }
        let off = off as usize;
        let need = (count as usize).checked_mul(2)?;
        if off + need > self.data.len() {
            return None;
        }
        let mut out = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            let base = off + i * 2;
            out.push(u16::from_be_bytes(
                self.data[base..base + 2].try_into().ok()?,
            ));
        }
        Some(out)
    }
}

fn parse_rpm_header(blob: &[u8]) -> Result<RpmHeader> {
    const MAGIC: [u8; 8] = [0x8e, 0xad, 0xe8, 0x01, 0x00, 0x00, 0x00, 0x00];

    let (index_off, index_len, data_len) = if blob.len() >= 16 && blob[0..8] == MAGIC {
        let index_len = u32::from_be_bytes(blob[8..12].try_into().unwrap()) as usize;
        let data_len = u32::from_be_bytes(blob[12..16].try_into().unwrap()) as usize;
        (16usize, index_len, data_len)
    } else {
        if blob.len() < 8 {
            return Err(anyhow!("header too small"));
        }
        let index_len = u32::from_be_bytes(blob[0..4].try_into().unwrap()) as usize;
        let data_len = u32::from_be_bytes(blob[4..8].try_into().unwrap()) as usize;
        (8usize, index_len, data_len)
    };

    let index_bytes = index_len
        .checked_mul(16)
        .ok_or_else(|| anyhow!("index length overflow"))?;
    let data_off = index_off + index_bytes;

    if blob.len() < data_off + data_len {
        return Err(anyhow!("header truncated"));
    }

    let mut hdr = RpmHeader {
        entries: HashMap::new(),
        data: blob[data_off..data_off + data_len].to_vec(),
    };

    for i in 0..index_len {
        let base = index_off + i * 16;
        let tag = u32::from_be_bytes(blob[base..base + 4].try_into().unwrap());
        let ty = u32::from_be_bytes(blob[base + 4..base + 8].try_into().unwrap());
        let off = i32::from_be_bytes(blob[base + 8..base + 12].try_into().unwrap());
        let count = u32::from_be_bytes(blob[base + 12..base + 16].try_into().unwrap());
        hdr.entries.insert(tag, (ty, count, off));
    }

    Ok(hdr)
}
