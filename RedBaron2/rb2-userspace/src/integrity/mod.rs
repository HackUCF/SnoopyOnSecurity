mod apk;
mod dpkg;
mod pacman;
mod rpm;

use anyhow::Result;
use log::{error, info, warn};
use std::{future::Future, path::PathBuf, pin::Pin, sync::Arc};
use tokio::{fs, sync::Semaphore};

// TODO: do online validation of package hashes

#[derive(Clone, Debug)]
enum ManagerType {
    Apk,
    Dpkg,
    Pacman,
    Rpm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingKind {
    Modified,
    Missing,
    Added,
    Deleted,
    MetadataChanged,
    Error,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub manager: &'static str,
    pub package: Option<String>,
    pub path: Option<PathBuf>,
    pub kind: FindingKind,
    pub details: String,
}

#[derive(Debug, Default, Clone)]
pub struct ManagerReport {
    pub manager: &'static str,
    pub checked_packages: u64,
    pub checked_files: u64,
    pub findings: Vec<Finding>,
}

/// Shared scan limits to keep CPU/IO stable across managers.
#[derive(Clone)]
pub(crate) struct ScanLimits {
    /// Limits *hashing* concurrency globally
    pub hash_sem: Arc<Semaphore>,
    /// Limits number of spawned tasks sitting in memory waiting for permits
    pub max_in_flight: usize,

    pub scan_conffiles: bool,
}

impl ScanLimits {
    pub fn new(scan_conffiles: bool) -> Self {
        Self {
            hash_sem: Arc::new(Semaphore::new(8)),
            max_in_flight: 16,
            scan_conffiles,
        }
    }
}

/// Standardized producer output used by all managers.
///
/// We keep this intentionally minimal: a package counter event (`Pkg`), a file
/// verification job (`File`), and an optional out-of-band finding (`Finding`).
#[derive(Debug)]
pub(crate) enum StreamItem<Job> {
    Pkg,
    File { job: Job },
    Finding(Finding),
}

pub(crate) type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

pub(crate) trait StreamScanManager {
    const MANAGER: &'static str;
    type Job: Send + 'static;

    fn producer_label() -> &'static str {
        "producer"
    }

    fn producer_error_path() -> Option<PathBuf> {
        None
    }

    fn spawn_producer(
        limits: ScanLimits,
        tx: tokio::sync::mpsc::UnboundedSender<StreamItem<Self::Job>>,
    ) -> tokio::task::JoinHandle<anyhow::Result<()>>;

    fn verify(job: Self::Job, limits: ScanLimits) -> BoxFuture<Option<Finding>>;
}

/// Shared scan management for all managers
pub(crate) async fn run_stream_scan<M: StreamScanManager>(limits: ScanLimits) -> ManagerReport {
    let manager = M::MANAGER;
    let label = M::producer_label();
    let producer_path = M::producer_error_path();

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<StreamItem<M::Job>>();
    let producer = M::spawn_producer(limits.clone(), tx);

    let mut report = ManagerReport {
        manager,
        checked_packages: 0,
        checked_files: 0,
        findings: Vec::new(),
    };

    let mut set: tokio::task::JoinSet<Option<Finding>> = tokio::task::JoinSet::new();
    let mut in_flight = 0usize;

    while let Some(item) = rx.recv().await {
        match item {
            StreamItem::Pkg => {
                report.checked_packages += 1;
            }
            StreamItem::Finding(f) => {
                report.findings.push(f);
            }
            StreamItem::File { job } => {
                report.checked_files += 1;

                while in_flight >= limits.max_in_flight {
                    match set.join_next().await {
                        None => break,
                        Some(res) => {
                            in_flight = in_flight.saturating_sub(1);
                            match res {
                                Err(e) => report.findings.push(Finding {
                                    manager,
                                    package: None,
                                    path: None,
                                    kind: FindingKind::Error,
                                    details: format!("join error: {e}"),
                                }),
                                Ok(Some(f)) => report.findings.push(f),
                                Ok(None) => {}
                            }
                        }
                    }
                }

                set.spawn(M::verify(job, limits.clone()));
                in_flight += 1;
            }
        }
    }

    while in_flight > 0 {
        match set.join_next().await {
            None => break,
            Some(res) => {
                in_flight = in_flight.saturating_sub(1);
                match res {
                    Err(e) => report.findings.push(Finding {
                        manager,
                        package: None,
                        path: None,
                        kind: FindingKind::Error,
                        details: format!("join error: {e}"),
                    }),
                    Ok(Some(f)) => report.findings.push(f),
                    Ok(None) => {}
                }
            }
        }
    }
    while let Some(res) = set.join_next().await {
        match res {
            Err(e) => report.findings.push(Finding {
                manager,
                package: None,
                path: None,
                kind: FindingKind::Error,
                details: format!("join error: {e}"),
            }),
            Ok(Some(f)) => report.findings.push(f),
            Ok(None) => {}
        }
    }

    match producer.await {
        Err(e) => report.findings.push(Finding {
            manager,
            package: None,
            path: producer_path,
            kind: FindingKind::Error,
            details: format!("{label} join error: {e}"),
        }),
        Ok(Err(e)) => report.findings.push(Finding {
            manager,
            package: None,
            path: producer_path,
            kind: FindingKind::Error,
            details: format!("{label} error: {e:#}"),
        }),
        Ok(Ok(())) => {}
    }

    report
}

async fn detect_managers() -> Vec<ManagerType> {
    let checks: &[(ManagerType, &[&str])] = &[
        (
            ManagerType::Apk,
            &[
                "/sbin/apk",
                "/bin/apk",
                "/usr/bin/apk",
                "/lib/apk/db/installed",
            ],
        ),
        (
            ManagerType::Dpkg,
            &[
                "/usr/bin/dpkg",
                "/bin/dpkg",
                "/var/lib/dpkg/status",
                "/var/lib/dpkg/available",
            ],
        ),
        (
            ManagerType::Pacman,
            &[
                "/usr/bin/pacman",
                "/bin/pacman",
                "/var/lib/pacman/local",
                "/etc/pacman.conf",
            ],
        ),
        (
            ManagerType::Rpm,
            &[
                "/usr/bin/rpm",
                "/bin/rpm",
                "/var/lib/rpm/Packages",
                "/var/lib/rpm/rpmdb.sqlite",
            ],
        ),
    ];

    let mut out = Vec::new();
    for (ty, paths) in checks {
        for p in *paths {
            if fs::try_exists(p).await.unwrap_or(false) {
                out.push(ty.clone());
                break;
            }
        }
    }
    out
}

async fn scan(scan_conffiles: bool, managers: &[ManagerType]) -> Result<()> {
    let limits = ScanLimits::new(scan_conffiles);
    let mut set = tokio::task::JoinSet::new();

    for m in managers.iter().cloned() {
        let limits = limits.clone();
        set.spawn(async move {
            match m {
                ManagerType::Apk => apk::scan(limits).await.map(|r| ("apk", r)),
                ManagerType::Dpkg => dpkg::scan(limits).await.map(|r| ("dpkg", r)),
                ManagerType::Pacman => pacman::scan(limits).await.map(|r| ("pacman", r)),
                ManagerType::Rpm => rpm::scan(limits).await.map(|r| ("rpm", r)),
            }
        });
    }

    while let Some(res) = set.join_next().await {
        match res {
            Err(e) => error!("scan task join error: {e}"),
            Ok(Err(e)) => error!("scan failed: {e:#}"),
            Ok(Ok((name, report))) => {
                if report.findings.is_empty() {
                    info!(
                        "[{name}] ok checked_packages={} checked_files={}",
                        report.checked_packages, report.checked_files
                    );
                } else {
                    warn!(
                        "[{name}] findings={} checked_packages={} checked_files={}",
                        report.findings.len(),
                        report.checked_packages,
                        report.checked_files
                    );
                    for f in report.findings {
                        match f.kind {
                            FindingKind::Error => error!(
                                "[{name}] ERROR pkg={:?} path={:?} {}",
                                f.package, f.path, f.details
                            ),
                            _ => warn!(
                                "[{name}] {:?} path={} pkg={} {}",
                                f.kind,
                                f.path
                                    .as_deref()
                                    .map(|p| p.display().to_string())
                                    .unwrap_or_else(|| "<unknown path>".to_string()),
                                f.package.as_deref().unwrap_or("<unknown pkg>"),
                                f.details
                            ),
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

pub async fn single_scan(scan_conffiles: bool) -> Result<()> {
    let managers = detect_managers().await;
    if managers.is_empty() {
        return Err(anyhow::anyhow!("No package managers detected"));
    }
    scan(scan_conffiles, &managers).await
}
