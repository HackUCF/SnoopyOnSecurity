use std::{
    cmp::min,
    collections::{HashMap, HashSet},
    error::Error,
    fs::{self, File},
    io::{self, BufRead, BufReader, IoSliceMut, Read},
    os::unix::fs::MetadataExt,
    process,
    sync::atomic::{AtomicUsize, Ordering},
    thread::sleep,
    time::{Duration, Instant},
};

use log::{debug, info, trace, warn};
use nix::{
    errno::Errno,
    sys::uio::{RemoteIoVec, process_vm_readv},
    unistd::Pid,
};
use sysinfo::{Pid as SysPid, ProcessRefreshKind, ProcessesToUpdate, System};
use xxhash_rust::xxh3;
use xxhash_rust::xxh3::Xxh3DefaultBuilder;
use yara_x::{Rules, blocks::Scanner};

use crate::config::yaml::YaraConfig;
use crate::yara::handle_yara_match;

/// Default max bytes per YARA scan chunk (10 MiB). Adjustable at runtime.
pub static CHUNK_SIZE_BYTES: AtomicUsize = AtomicUsize::new(10 * 1024 * 1024);

/// Optionally adjust the maximum bytes scanned per rule chunk.
pub fn set_max_scan_bytes_per_rule(bytes: usize) {
    // Prevent absurdly low values which could cause extremely slow scans
    let min_bytes = 1024; // 1 KiB
    let value = if bytes < min_bytes { min_bytes } else { bytes };
    CHUNK_SIZE_BYTES.store(value, Ordering::Relaxed);
}
/// Default full scan interval if not specified in config (5 minutes)
const DEFAULT_FULL_SCAN_INTERVAL_SECS: u64 = 5 * 60;
/// Default polling interval if not specified in config
const DEFAULT_POLL_INTERVAL_SECS: u64 = 1;

fn get_readable_memory_regions(pid: i32) -> Result<impl Iterator<Item = RemoteIoVec>, io::Error> {
    let file = File::open(format!("/proc/{}/maps", pid))?;
    let reader = BufReader::new(file);

    let iter = reader.lines().map_while(|res| res.ok()).filter_map(|line| {
        let mut parts = line.split_whitespace();

        let mut range = parts.next()?.split('-');
        let start = u64::from_str_radix(range.next()?, 16).ok()?;
        let end = u64::from_str_radix(range.next()?, 16).ok()?;
        if start >= end {
            return None;
        }

        let perms = parts.next()?;

        // Only scan readable regions
        if !perms.starts_with('r') {
            return None;
        }

        // skip offset/dev/inode
        parts.next();
        parts.next();
        parts.next();

        if let Some(path) = parts.next()
            && matches!(path, "[vvar]" | "[vsyscall]" | "[vdso]")
        {
            return None;
        }

        Some(RemoteIoVec {
            base: start as usize,
            len: (end - start) as usize,
        })
    });

    Ok(iter)
}

/// Result of scanning a single PID.
enum ScanOutcome {
    /// No YARA rule matched (or the PID was skipped / unreadable).
    NoMatch,
    /// At least one rule matched. `pid_terminated` indicates whether the
    /// process was actually killed by the configured actions
    Matched { pid_terminated: bool },
}

/// Scan a single PID's memory regions with YARA and react
fn scan_pid(
    pid: i32,
    self_pid: i32,
    scanner: &mut Scanner,
    seen_hashes: &mut HashMap<usize, u64, Xxh3DefaultBuilder>,
    scratch: &mut Vec<u8>,
    cfg: &YaraConfig,
) -> Result<ScanOutcome, Box<dyn Error>> {
    if pid == self_pid {
        return Ok(ScanOutcome::NoMatch);
    }

    // Read process name from /proc/<pid>/comm
    let comm_path = format!("/proc/{}/comm", pid);
    let mut comm_s = String::new();
    if let Ok(mut comm_file) = File::open(&comm_path) {
        comm_file.read_to_string(&mut comm_s)?;
    } else {
        return Ok(ScanOutcome::NoMatch);
    }
    let proc_name = comm_s.trim();
    if proc_name.starts_with("kworker") {
        return Ok(ScanOutcome::NoMatch);
    }

    debug!("Starting scan for PID {} ({})", pid, proc_name);

    let mut outcome = ScanOutcome::NoMatch;

    let mut regions_seen: HashSet<usize, Xxh3DefaultBuilder> = Default::default();
    let mut regions_updated = 0;

    let buffer_size = CHUNK_SIZE_BYTES.load(Ordering::Relaxed);
    let max_iovecs = 256;

    scratch.resize(buffer_size, 0);
    let buffer: &mut [u8] = &mut scratch[..];

    let mut xxh3 = Box::new(xxh3::Xxh3::new());

    let mut current_remotes: Vec<RemoteIoVec> = Vec::with_capacity(max_iovecs);
    let mut remaining_remotes = None;

    let Ok(mut regions) = get_readable_memory_regions(pid) else {
        return Ok(ScanOutcome::NoMatch);
    };

    loop {
        current_remotes.clear();

        let mut available_bytes = buffer_size;
        while available_bytes > 0 && current_remotes.len() < max_iovecs {
            if remaining_remotes.is_none() {
                remaining_remotes = regions.next();
            }
            let Some(region) = remaining_remotes else {
                break;
            };

            let usable_bytes = min(available_bytes, region.len);
            available_bytes -= usable_bytes;
            current_remotes.push(RemoteIoVec {
                base: region.base,
                len: usable_bytes,
            });

            if usable_bytes < region.len {
                remaining_remotes = Some(RemoteIoVec {
                    base: region.base + usable_bytes,
                    len: region.len - usable_bytes,
                });
            } else {
                remaining_remotes = None;
            }
        }

        if current_remotes.is_empty() {
            break;
        }

        fn advance_iovecs(
            iovecs: &[RemoteIoVec],
            idx: &mut usize,
            off: &mut usize,
            mut bytes: usize,
        ) {
            while bytes > 0 && *idx < iovecs.len() {
                let avail = iovecs[*idx].len - *off;
                if bytes >= avail {
                    bytes -= avail;
                    *idx += 1;
                    *off = 0;
                } else {
                    *off += bytes;
                    bytes = 0;
                }
            }
        }

        let mut rem_idx: usize = 0;
        let mut rem_off: usize = 0;
        let mut tmp_remotes: Vec<RemoteIoVec> = Vec::with_capacity(max_iovecs);
        let mut offset = 0;
        let read_size = buffer_size - available_bytes;

        while offset < read_size && rem_idx < current_remotes.len() {
            let local_iov = &mut [IoSliceMut::new(&mut buffer[offset..read_size])];

            let remotes: &[RemoteIoVec] = if rem_off == 0 {
                &current_remotes[rem_idx..]
            } else {
                tmp_remotes.clear();
                let cur = &current_remotes[rem_idx];
                tmp_remotes.push(RemoteIoVec {
                    base: cur.base + rem_off,
                    len: cur.len - rem_off,
                });
                tmp_remotes.extend_from_slice(&current_remotes[rem_idx + 1..]);
                &tmp_remotes
            };

            match process_vm_readv(Pid::from_raw(pid), local_iov, remotes) {
                Ok(0) => {
                    warn!("process_vm_readv made no progress (pid {})", pid);
                    break;
                }
                Ok(n) => {
                    trace!("partial read of pid memory, incrementing iovecs");
                    offset += n;
                    advance_iovecs(&current_remotes, &mut rem_idx, &mut rem_off, n);
                }
                Err(Errno::ESRCH) => return Ok(ScanOutcome::NoMatch), // pid terminated
                Err(Errno::EFAULT) => {
                    trace!("Efault, incrementing iovecs by one");
                    let len = current_remotes[rem_idx].len - rem_off;
                    buffer[offset..offset + len].fill(0);
                    offset += len;
                    advance_iovecs(&current_remotes, &mut rem_idx, &mut rem_off, len);

                    if rem_idx == current_remotes.len() - 1 {
                        remaining_remotes = None;
                    }
                }
                Err(e) => {
                    warn!(
                        "process_vm_readv fault after {} bytes (pid {}, {:?})",
                        offset, pid, e
                    );
                    break;
                }
            }
        }

        if offset < read_size {
            buffer[offset..read_size].fill(0);
        }

        let mut buffer_index = 0;
        for region in &current_remotes {
            let region_buffer = &buffer[buffer_index..buffer_index + region.len];
            buffer_index += region.len;

            xxh3.reset();
            xxh3.update(region_buffer);
            let hash = xxh3.digest();
            let key = region.base;

            if seen_hashes.insert(key, hash) != Some(hash) {
                regions_updated += 1;
                scanner.scan(region.base, region_buffer)?;
            }
            regions_seen.insert(key);
        }
    }

    if regions_updated > 0
        && let Ok(results) = scanner.finish()
    {
        let mut matching = results
            .matching_rules()
            .filter(|rule| !cfg.disabled_rules.contains(rule.identifier()))
            .peekable();

        if matching.peek().is_some() {
            let result = handle_yara_match(pid, matching, &cfg.actions, &cfg.samples_dir);
            outcome = ScanOutcome::Matched {
                pid_terminated: result.pid_terminated,
            };
        }
    }

    seen_hashes.retain(|k, _| regions_seen.contains(k));

    let terminated = matches!(
        outcome,
        ScanOutcome::Matched {
            pid_terminated: true
        }
    );
    let matched = matches!(outcome, ScanOutcome::Matched { .. });
    debug!(
        "PID {}: scanned {} regions{}{}",
        pid,
        regions_updated,
        if terminated { " (terminated)" } else { "" },
        if matched && !terminated {
            " (matched, alert-only)"
        } else {
            ""
        },
    );

    Ok(outcome)
}

/// Perform a full pass over every numeric entry in `/proc` and call `scan_pid` on each,
/// but skip any process whose executable (inode) we've already scanned.
pub fn full_scan_all(
    self_pid: i32,
    scanner: &mut Scanner,
    seen_hashes: &mut HashMap<i32, HashMap<usize, u64, Xxh3DefaultBuilder>>,
    scanned_exes: &mut HashSet<u64>,
    scratch: &mut Vec<u8>,
    cfg: &YaraConfig,
) {
    let mut total = 0;
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let file_name = entry.file_name().to_string_lossy().into_owned();
            if let Ok(pid) = file_name.parse::<i32>() {
                total += 1;

                let exe_link = format!("/proc/{}/exe", pid);
                let inode = fs::metadata(&exe_link).map(|md| md.ino()).unwrap_or(0);

                if inode != 0 && scanned_exes.contains(&inode) {
                    debug!("Skipping PID {}: exe inode {} already scanned", pid, inode);
                    continue;
                }

                match scan_pid(
                    pid,
                    self_pid,
                    scanner,
                    seen_hashes.entry(pid).or_default(),
                    scratch,
                    cfg,
                ) {
                    Err(e) => debug!("Error scanning PID {}: {}", pid, e),
                    Ok(ScanOutcome::Matched { .. }) => {
                        debug!("PID {} matched by YARA -> not tracking its inode", pid);
                    }
                    Ok(ScanOutcome::NoMatch) => {
                        if inode != 0 {
                            scanned_exes.insert(inode);
                        }
                    }
                }
            }
        }
    }

    info!(
        "Full scan complete: attempted scanning {} PIDs (exe-inodes tracked: {})",
        total,
        scanned_exes.len()
    );
}

/// Initialize and run the YARA scanning process by polling sysinfo for new processes.
pub fn yara_init_memory_scan(cfg: &YaraConfig, rules: &Rules) -> anyhow::Result<()> {
    // skip self
    let self_pid: i32 = process::id() as i32;

    let poll_interval =
        Duration::from_secs(cfg.poll_interval_secs.unwrap_or(DEFAULT_POLL_INTERVAL_SECS));
    debug!(
        "YARA polling interval set to {} seconds",
        poll_interval.as_secs()
    );

    let full_scan_interval = Duration::from_secs(
        cfg.full_scan_interval_secs
            .unwrap_or(DEFAULT_FULL_SCAN_INTERVAL_SECS),
    );
    debug!(
        "YARA full scan interval set to {} seconds",
        full_scan_interval.as_secs()
    );

    // Track hashes of (pid, offset, length) -> XXH3 hash
    let mut seen_hashes: HashMap<i32, HashMap<usize, u64, Xxh3DefaultBuilder>> = HashMap::new();

    let mut scanner = Scanner::new(rules);

    // Validate disabled_rules against compiled rule identifiers (cfg.disabled_rules is a HashSet)
    if !cfg.disabled_rules.is_empty() {
        let all_rule_names: HashSet<String> = rules
            .iter()
            .map(|rule| rule.identifier().to_string())
            .collect();

        let invalid_disabled: Vec<String> = cfg
            .disabled_rules
            .iter()
            .filter(|name| !all_rule_names.contains(*name))
            .cloned()
            .collect();

        if !invalid_disabled.is_empty() {
            warn!(
                "The following disabled_rules do not match any loaded rules: {:?}",
                invalid_disabled
            );
        } else {
            info!("Disabling {} YARA rules", cfg.disabled_rules.len());
        }
    }

    let mut sys = System::new();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::everything().without_tasks(),
    );

    let mut known_pids: HashSet<i32> = sys
        .processes()
        .keys()
        .map(|pid| pid.as_u32() as i32)
        .collect();

    let mut scanned_exes: HashSet<u64> = HashSet::new();
    let mut last_full_scan = Instant::now();

    let mut scratch: Vec<u8> = Vec::new();

    // initial full scan
    full_scan_all(
        self_pid,
        &mut scanner,
        &mut seen_hashes,
        &mut scanned_exes,
        &mut scratch,
        cfg,
    );

    loop {
        sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::everything().without_tasks(),
        );

        for pid in sys.processes().keys().map(|pid| pid.as_u32() as i32) {
            if !known_pids.insert(pid) {
                continue; // already known
            }

            let exe_link = format!("/proc/{}/exe", pid);
            let inode = fs::metadata(&exe_link).map(|md| md.ino()).unwrap_or(0);

            // Skip if this executable inode was already scanned
            if inode != 0 && scanned_exes.contains(&inode) {
                debug!(
                    "Skipping new PID {}: exe inode {} already scanned",
                    pid, inode
                );
                continue;
            }

            debug!("Detected new PID: {}", pid);

            match scan_pid(
                pid,
                self_pid,
                &mut scanner,
                seen_hashes.entry(pid).or_default(),
                &mut scratch,
                cfg,
            ) {
                Err(e) => {
                    debug!("Error scanning new PID {}: {}", pid, e);
                }
                Ok(ScanOutcome::Matched { .. }) => {
                    // YARA match -> do NOT track its inode
                    debug!("New PID {} matched by YARA -> not tracking its inode", pid);
                }
                Ok(ScanOutcome::NoMatch) => {
                    // No YARA match -> insert inode into scanned_exes
                    if inode != 0 {
                        scanned_exes.insert(inode);
                    }
                }
            }
        }

        // prevent known_pids growing forever
        known_pids.retain(|pid| sys.process(SysPid::from_u32(*pid as u32)).is_some());

        // don't keep large scratch between big scans
        if scratch.is_empty() {
            scratch.truncate(0);
        }

        // Check if it's time for a full rescan
        if last_full_scan.elapsed() >= full_scan_interval {
            info!("Time for full scan of all running processes");

            known_pids.clear();
            seen_hashes.clear();
            scanned_exes.clear();

            full_scan_all(
                self_pid,
                &mut scanner,
                &mut seen_hashes,
                &mut scanned_exes,
                &mut scratch,
                cfg,
            );

            last_full_scan = Instant::now();
        }

        sleep(poll_interval);
    }
}
