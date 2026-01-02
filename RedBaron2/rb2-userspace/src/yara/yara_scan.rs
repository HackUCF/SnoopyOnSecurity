use crate::config::yaml::YaraConfig;
use crate::log_file;
use anyhow::Context;
use libc::{SIGKILL, kill};
use log::{debug, info, warn};
use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Seek, SeekFrom},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process,
    sync::atomic::{AtomicUsize, Ordering},
    thread::sleep,
    time::{Duration, Instant},
};
use sysinfo::System; // refresh_all() replaces refresh_processes()
use xxhash_rust::xxh3::xxh3_64;
use yara_x::{Compiler, Rule, Rules, Scanner};

/// Default max bytes per YARA scan chunk (10 MiB). Adjustable at runtime.
static CHUNK_SIZE_BYTES: AtomicUsize = AtomicUsize::new(10 * 1024 * 1024);

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

/// Scan a single PID's memory regions with YARA. If any rule matches, send SIGKILL.
/// Returns:
///   - Ok(true)  → the pid was terminated due to a YARA match.
///   - Ok(false) → scanned (or skipped) without killing.
///   - Err(_)    → I/O or parsing error.
fn scan_pid(
    pid: i32,
    self_pid: i32,
    scanner: &mut Scanner,
    seen_hashes: &mut HashMap<(i32, usize, usize), u64>,
    disabled_rules: &[String],
    logfile: &Path,
) -> Result<bool, Box<dyn Error>> {
    if pid == self_pid {
        return Ok(false);
    }

    // Read process name from /proc/<pid>/comm
    let comm_path = format!("/proc/{}/comm", pid);
    let mut comm_s = String::new();
    if let Ok(mut comm_file) = File::open(&comm_path) {
        comm_file.read_to_string(&mut comm_s)?;
    } else {
        // Process exited or no permission
        return Ok(false);
    }
    let proc_name = comm_s.trim().to_string();
    if proc_name.starts_with("kworker") {
        // Skip kernel threads
        return Ok(false);
    }

    debug!("Starting scan for PID {} ({})", pid, proc_name);

    // Open /proc/<pid>/maps
    let maps_path = format!("/proc/{}/maps", pid);
    let maps_file = match File::open(&maps_path) {
        Ok(f) => f,
        Err(_) => return Ok(false),
    };
    let reader = BufReader::new(maps_file);

    // Open /proc/<pid>/mem
    let mem_path = format!("/proc/{}/mem", pid);
    let mut mem_file = match OpenOptions::new().read(true).open(&mem_path) {
        Ok(f) => f,
        Err(_) => return Ok(false),
    };

    let mut pid_regions_verified = 0;
    let mut pid_terminated = false;

    'region_loop: for line_res in reader.lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(_) => break,
        };
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let addr_range = parts[0];
        let perms = parts[1];

        // Skip VMAs backed by "..." (kernel, stack, etc.)
        if parts.len() >= 6 {
            let pathname = parts[5];
            if pathname.starts_with('[') {
                continue;
            }
        }
        // Only scan read-able regions
        if !perms.starts_with('r') {
            continue;
        }

        // Parse region start / end
        let addrs: Vec<&str> = addr_range.split('-').collect();
        if addrs.len() != 2 {
            continue;
        }
        let region_start = usize::from_str_radix(addrs[0], 16)?;
        let region_end = usize::from_str_radix(addrs[1], 16)?;
        let region_size = region_end.saturating_sub(region_start);

        pid_regions_verified += 1;

        let mut offset = 0;
        while offset < region_size {
            let chunk_size = CHUNK_SIZE_BYTES.load(Ordering::Relaxed);
            let overlap = chunk_size / 20; // ~5%
            let mut to_read = chunk_size + overlap;
            if offset + to_read > region_size {
                to_read = region_size - offset;
            }
            let abs_offset = region_start + offset;

            let mut buffer = vec![0u8; to_read];
            if mem_file.seek(SeekFrom::Start(abs_offset as u64)).is_err() {
                break;
            }
            if mem_file.read_exact(&mut buffer).is_err() {
                break;
            }

            // Hash the buffer via XXH3_64
            let hash = xxh3_64(&buffer);
            let key = (pid, abs_offset, to_read);

            // Skip unchanged chunks
            if let Some(prev) = seen_hashes.get(&key)
                && *prev == hash
            {
                offset = offset.saturating_add(chunk_size);
                continue;
            }

            // Run YARA on this buffer
            if let Ok(results) = scanner.scan(&buffer) {
                let mut matching = results
                    .matching_rules()
                    .filter(|rule| !disabled_rules.contains(&rule.identifier().to_string()))
                    .peekable();
                if matching.peek().is_some() {
                    pid_terminated = logged_kill(pid, matching, logfile);
                    break 'region_loop;
                }
            }

            // Record this chunk's hash
            seen_hashes.insert(key, hash);
            offset = offset.saturating_add(chunk_size);
        }
    }

    debug!(
        "PID {}: scanned {} regions{}",
        pid,
        pid_regions_verified,
        if pid_terminated { " (terminated)" } else { "" }
    );

    // If we just killed this PID, remove any hashes we may have already stored for it:
    if pid_terminated {
        seen_hashes.retain(|(seen_pid, _, _), _| *seen_pid != pid);
    }
    Ok(pid_terminated)
}

fn logged_kill<'a, I>(pid: i32, matching: I, logfile: &Path) -> bool
where
    I: IntoIterator<Item = Rule<'a, 'a>>,
{
    let path = fs::read_link(format!("/proc/{}/exe", pid))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "<unknown>".to_string());

    let mut log_file_handle = match log_file::open_log_file(logfile) {
        Ok(f) => Some(f),
        Err(e) => {
            warn!("Failed to open yara log file: {}", e);
            None
        }
    };

    // Helper to log to file if Some
    let mut log_to_file = |line: &str| {
        if let Some(ref mut f) = log_file_handle
            && let Err(e) = log_file::write_log_line_with_timestamp(f, logfile, line)
        {
            warn!("Failed to write to yara log file: {}", e);
        }
    };

    for rule in matching {
        let msg = format!("{} PID={} matched rule '{}'", path, pid, rule.identifier());
        info!("{}", msg);
        log_to_file(&msg);
    }

    match kill_pid(pid) {
        Ok(_) => {
            debug!("PID {} killed", pid);
            true
        }
        Err(e) => {
            let msg = format!("kill({}, SIGKILL) failed: {}", pid, e);
            warn!("{}", msg);
            log_to_file(&msg);
            false
        }
    }
}

fn kill_pid(pid: i32) -> io::Result<()> {
    let rc = unsafe { kill(pid, SIGKILL) };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Perform a full pass over every numeric entry in `/proc` and call `scan_pid` on each,
/// but skip any process whose executable (inode) we've already scanned.
pub fn full_scan_all(
    self_pid: i32,
    scanner: &mut Scanner,
    seen_hashes: &mut HashMap<(i32, usize, usize), u64>,
    scanned_exes: &mut HashSet<u64>,
    disabled_rules: &[String],
    logfile: &Path,
) {
    let mut total = 0;
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let file_name = entry.file_name().to_string_lossy().into_owned();
            if let Ok(pid) = file_name.parse::<i32>() {
                total += 1;

                // Determine the inode of /proc/<pid>/exe to identify a unique executable
                let exe_link = format!("/proc/{}/exe", pid);
                let inode = fs::metadata(&exe_link).map(|md| md.ino()).unwrap_or(0);

                // Skip if we've already scanned this executable inode
                if inode != 0 && scanned_exes.contains(&inode) {
                    debug!("Skipping PID {}: exe inode {} already scanned", pid, inode);
                    continue;
                }

                // Scan the process
                match scan_pid(pid, self_pid, scanner, seen_hashes, disabled_rules, logfile) {
                    Err(e) => {
                        debug!("Error scanning PID {}: {}", pid, e);
                    }
                    Ok(true) => {
                        // We just killed a malicious PID; do NOT insert its inode into scanned_exes
                        debug!(
                            "PID {} was terminated by YARA → not tracking its inode",
                            pid
                        );
                    }
                    Ok(false) => {
                        // No YARA match → record this executable's inode so we don't re‐scan duplicates
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

pub fn build_rules(
    disable_bundled_rules: bool,
    rules_dir: &Option<PathBuf>,
) -> anyhow::Result<Rules> {
    let mut compiler = Compiler::new();

    // bundled rules
    if !disable_bundled_rules {
        const EMBEDDED_RULES_COMPRESSED: &[u8] =
            include_bytes!(concat!(env!("OUT_DIR"), "/compiled_yara_rules.xz"));

        debug!("Loading and decompressing embedded YARA rules from build");

        let mut decoder = xz2::read::XzDecoder::new(EMBEDDED_RULES_COMPRESSED);
        let mut embedded_rules = String::new();
        decoder
            .read_to_string(&mut embedded_rules)
            .context("Failed to decompress embedded YARA rules")?;

        if !embedded_rules.is_empty() {
            compiler.add_source(embedded_rules.as_str())?;
        } else {
            info!("No embedded YARA rules found in binary");
        }
    } else {
        info!("Bundled YARA rules disabled via config");
    }

    // extra rules
    if let Some(dir) = rules_dir {
        if dir.exists() {
            info!("Loading additional YARA rules from: {}", dir.display());
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if let Some(ext) = path.extension().and_then(|s| s.to_str())
                    && (ext == "yara" || ext == "yar")
                {
                    let source = fs::read_to_string(&path)?;
                    compiler.add_source(source.as_str())?;
                }
            }
        } else {
            warn!("Rules directory {} does not exist, skipping", dir.display());
        }
    }

    if rules_dir.is_none() && disable_bundled_rules {
        Err(anyhow::anyhow!("No yara rules provided to scan"))
    } else {
        Ok(compiler.build())
    }
}

/// Initialize and run the YARA scanning process by polling sysinfo for new processes.
pub fn yara_init_scan(cfg: YaraConfig) -> anyhow::Result<()> {
    // 1) Determine our own PID so we skip scanning ourselves
    let self_pid: i32 = process::id() as i32;

    // 2) Set up the polling interval
    let poll_interval =
        Duration::from_secs(cfg.poll_interval_secs.unwrap_or(DEFAULT_POLL_INTERVAL_SECS));
    debug!(
        "YARA polling interval set to {} seconds",
        poll_interval.as_secs()
    );

    // 3) Set up the full scan interval
    let full_scan_interval = Duration::from_secs(
        cfg.full_scan_interval_secs
            .unwrap_or(DEFAULT_FULL_SCAN_INTERVAL_SECS),
    );
    debug!(
        "YARA full scan interval set to {} seconds",
        full_scan_interval.as_secs()
    );

    // 4) Track hashes of (pid, offset, length) -> XXH3 hash
    let mut seen_hashes: HashMap<(i32, usize, usize), u64> = HashMap::new();

    // 5) setup rules with scanner
    let rules = build_rules(cfg.disable_bundled_rules, &cfg.rules_dir)?;

    let mut scanner = Scanner::new(&rules);

    // Validate and log disabled rules configuration
    if !cfg.disabled_rules.is_empty() {
        // Get all rule identifiers from compiled rules
        let all_rule_names: HashSet<String> = rules
            .iter()
            .map(|rule| rule.identifier().to_string())
            .collect();

        // Check for invalid rule names
        let mut valid_disabled = Vec::new();
        let mut invalid_disabled = Vec::new();

        for rule_name in &cfg.disabled_rules {
            if all_rule_names.contains(rule_name) {
                valid_disabled.push(rule_name.clone());
            } else {
                invalid_disabled.push(rule_name.clone());
            }
        }

        if !valid_disabled.is_empty() {
            info!(
                "Disabling {} YARA rules: {:?}",
                valid_disabled.len(),
                valid_disabled
            );
        }

        if !invalid_disabled.is_empty() {
            warn!(
                "The following disabled_rules do not match any loaded rules: {:?}",
                invalid_disabled
            );
        }
    }

    // 6) Initialize sysinfo to track processes
    let mut sys = System::new_all();
    sys.refresh_all(); // replacement for refresh_processes()

    // 7) Maintain a set of "known" PIDs so we only scan brand-new processes immediately.
    let mut known_pids: HashSet<i32> = sys
        .processes()
        .keys()
        .map(|pid| pid.as_u32() as i32)
        .collect();

    // 8) Maintain a set of inode values for executables we've scanned, to skip duplicates
    let mut scanned_exes: HashSet<u64> = HashSet::new();

    // 9) Track when we last did a full rescan
    let mut last_full_scan = Instant::now();

    // 10) Immediately perform an initial full scan
    full_scan_all(
        self_pid,
        &mut scanner,
        &mut seen_hashes,
        &mut scanned_exes,
        &cfg.disabled_rules,
        &cfg.log_file,
    );

    loop {
        // 11) Refresh the system's process list
        sys.refresh_all();
        let current_pids: HashSet<i32> = sys
            .processes()
            .keys()
            .map(|pid| pid.as_u32() as i32)
            .collect();

        // 12) Detect newly spawned PIDs = current_pids − known_pids
        for &pid in current_pids.difference(&known_pids) {
            // Determine the inode of /proc/<pid>/exe
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
                &mut seen_hashes,
                &cfg.disabled_rules,
                &cfg.log_file,
            ) {
                Err(e) => {
                    debug!("Error scanning new PID {}: {}", pid, e);
                }
                Ok(true) => {
                    // Malicious process found and killed → do NOT track its inode
                    debug!(
                        "New PID {} was terminated by YARA → not tracking its inode",
                        pid
                    );
                }
                Ok(false) => {
                    // No YARA match → insert inode into scanned_exes
                    if inode != 0 {
                        scanned_exes.insert(inode);
                    }
                }
            }
        }

        // 13) Update the known_pids set
        known_pids = current_pids.clone();

        // 14) Check if it's time for a full rescan
        if last_full_scan.elapsed() >= full_scan_interval {
            info!("Time for full scan of all running processes");
            // Clear all collections before full scan
            known_pids.clear();
            seen_hashes.clear();
            scanned_exes.clear();
            full_scan_all(
                self_pid,
                &mut scanner,
                &mut seen_hashes,
                &mut scanned_exes,
                &cfg.disabled_rules,
                &cfg.log_file,
            );
            last_full_scan = Instant::now();
        }

        // 15) Sleep briefly before polling again
        sleep(poll_interval);
    }
}
