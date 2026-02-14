use super::log::log_detection;
use log::debug;
use serde_json::json;
use std::collections::HashSet;
use std::ffi::OsStr;
use std::io;
use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::time::{Duration, sleep};

fn osstr_to_u32(s: &OsStr) -> Option<u32> {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return None;
    }

    let mut value: u32 = 0;

    for &b in bytes {
        // fast range check for '0'..='9'
        if !b.is_ascii_digit() {
            return None;
        }

        let digit = (b - b'0') as u32;

        // check for overflow
        if value > (u32::MAX - digit) / 10 {
            return None;
        }

        value = value * 10 + digit;
    }

    Some(value)
}

async fn is_real_tgid(pid: u32) -> io::Result<bool> {
    let path = format!("/proc/{}/status", pid);
    let file = match fs::File::open(&path).await {
        Ok(f) => f,
        Err(e) => {
            return Err(e);
        }
    };

    let reader = tokio::io::BufReader::new(file);
    let mut lines = reader.lines();

    while let Some(line) = lines.next_line().await? {
        if let Some(rest) = line.strip_prefix("Tgid:") {
            if let Ok(tgid) = rest.trim().parse::<u32>() {
                return Ok(tgid == pid);
            }
            break;
        }
    }

    Ok(false)
}

/// returns vec of pids that may have been hidden from getdents but could get data about
async fn pid_walk() -> io::Result<Option<HashSet<u32>>> {
    let proc_path = "/proc";
    let mut dir = fs::read_dir(proc_path).await?;
    let meta = fs::metadata(proc_path).await?;
    let nlink = meta.nlink().saturating_sub(2);

    let mut observed = HashSet::new();
    observed.reserve(nlink as usize);
    let mut max = 1;
    while let Some(entry) = dir.next_entry().await? {
        let file_type = entry.file_type().await?;
        if !file_type.is_dir() {
            continue;
        }
        let name = entry.file_name();
        if let Some(pid) = osstr_to_u32(name.as_os_str()) {
            observed.insert(pid);
            if pid > max {
                max = pid;
            }
        }
    }

    let mut unaccounted = HashSet::new();
    let cap = max.saturating_add(100); // too expensive to go to pid max
    let mut path = PathBuf::from("/proc");
    // XXX: path rebuilds probably can be optimized but didn't seem to be performance issue

    for pid in 1..=cap {
        if observed.contains(&pid) {
            continue;
        }

        path.push(pid.to_string());

        if let Ok(meta) = fs::metadata(&path).await
            && meta.is_dir()
            && let Ok(true) = is_real_tgid(pid).await
        {
            unaccounted.insert(pid);
        }

        path.pop();
    }

    if unaccounted.is_empty() {
        Ok(None)
    } else {
        // check getdents again to make sure unaccounted pids aren't just new pids
        let mut dir = fs::read_dir(proc_path).await?;
        while let Some(entry) = dir.next_entry().await? {
            let file_type = entry.file_type().await?;
            if !file_type.is_dir() {
                continue;
            }
            let name = entry.file_name();
            if let Some(pid) = osstr_to_u32(name.as_os_str()) {
                unaccounted.remove(&pid);
            }
        }

        Ok(Some(unaccounted))
    }
}

pub async fn pid_scan() -> io::Result<()> {
    if let Some(unaccounted) = pid_walk().await? {
        for pid in unaccounted.into_iter() {
            let comm_path = format!("/proc/{}/comm", pid);
            let comm = match fs::read_to_string(&comm_path).await {
                Ok(s) => s.trim().to_string(),
                Err(_) => "<unknown>".to_string(),
            };

            let exe_path = format!("/proc/{}/exe", pid);
            let exe = match fs::read_link(&exe_path).await {
                Ok(path) => path.display().to_string(),
                Err(_) => "<unknown>".to_string(),
            };

            log_detection(
                "hidden_pid",
                &format!("pid={} comm={} exe={}", pid, comm, exe),
                json!({ "pid": pid, "comm": comm, "exe": exe }),
            )
            .await;
        }
    } else {
        debug!("No hidden pids found from pid walk");
    }
    Ok(())
}

/// dfs walk /sys/fs/cgroup taking all pids from cgroup.procs
async fn collect_cgroup_pids(root: &Path, out: &mut HashSet<u32>) -> io::Result<()> {
    let mut stack: Vec<PathBuf> = Vec::new();
    stack.push(root.to_path_buf());

    while let Some(path) = stack.pop() {
        let procs_path = path.join("cgroup.procs");
        if let Ok(file) = fs::File::open(&procs_path).await {
            let mut lines = BufReader::new(file).lines();
            while let Some(line) = lines.next_line().await? {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                if let Ok(pid) = line.parse::<u32>() {
                    out.insert(pid);
                }
            }
        }

        // walk subdirs
        let mut dir = match fs::read_dir(&path).await {
            Ok(d) => d,
            Err(e) => {
                if e.kind() == io::ErrorKind::PermissionDenied {
                    // just skip unreadable dirs
                    continue;
                }
                return Err(e);
            }
        };
        while let Some(entry) = dir.next_entry().await? {
            let ft = entry.file_type().await?;
            if !ft.is_dir() {
                continue;
            }
            let name = entry.file_name();
            if name == OsStr::new(".") || name == OsStr::new("..") {
                continue;
            }
            stack.push(entry.path());
        }
    }

    Ok(())
}

/// all PIDs in all cgroup.procs under /sys/fs/cgroup for cgroupv2
async fn cgroup_snapshot() -> io::Result<HashSet<u32>> {
    let mut pids = HashSet::new();
    collect_cgroup_pids(Path::new("/sys/fs/cgroup"), &mut pids).await?;
    Ok(pids)
}

/// like ps -ax PIDs
/// TODO: this shows zombie processes that cgroups do not
async fn proc_snapshot() -> io::Result<HashSet<u32>> {
    let mut pids = HashSet::new();
    let mut dir = fs::read_dir("/proc").await?;

    while let Some(entry) = dir.next_entry().await? {
        let ft = entry.file_type().await?;
        if !ft.is_dir() {
            continue;
        }
        let name = entry.file_name();
        if let Some(pid) = osstr_to_u32(name.as_os_str()) {
            pids.insert(pid);
        }
    }

    Ok(pids)
}

async fn take_pair_snapshot() -> io::Result<(HashSet<u32>, HashSet<u32>)> {
    let (cg, pr) = tokio::try_join!(cgroup_snapshot(), proc_snapshot())?;
    Ok((cg, pr))
}

/// Compare cgls to proc with 2 runs to reduce racy noise
/// diff <(find /sys/fs/cgroup -name "cgroup.procs" -exec cat {} \; | sort -nu) <(ps -o pid -ax | grep -v "PID" | tr -d ' ' | sort -nu)
pub async fn diff_cgroup_vs_proc() -> io::Result<()> {
    let (cg1, pr1) = take_pair_snapshot().await?;

    sleep(Duration::from_millis(20)).await;

    let (cg2, pr2) = take_pair_snapshot().await?;

    // filter out racy noise
    // only trust PIDs that showed up in both runs
    let stable_cg: HashSet<u32> = cg1.intersection(&cg2).copied().collect();
    let stable_pr: HashSet<u32> = pr1.intersection(&pr2).copied().collect();

    let only_in_cgroup: Vec<u32> = stable_cg.difference(&stable_pr).copied().collect();
    let only_in_proc: Vec<u32> = stable_pr.difference(&stable_cg).copied().collect();

    for pid in &only_in_cgroup {
        log_detection(
            "cgroup_only_pid",
            &format!("PID {} only in cgroup tree", pid),
            json!({ "pid": pid }),
        )
        .await;
    }

    for pid in &only_in_proc {
        log_detection(
            "proc_only_pid",
            &format!("PID {} only in ps tree", pid),
            json!({ "pid": pid }),
        )
        .await;
    }

    if only_in_cgroup.is_empty() && only_in_proc.is_empty() {
        debug!("No hidden pids found from cgroup");
    }

    Ok(())
}
