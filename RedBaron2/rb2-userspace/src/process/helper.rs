use log::warn;
use std::collections::HashMap;
use std::path::{Component, Path};
use std::sync::RwLock;
use std::time::{Duration, Instant};
use std::{fs, io, sync::OnceLock};

static MACHINE_ID: OnceLock<Option<String>> = OnceLock::new();

// uid -> (username, timestamp)
static USER_CACHE: OnceLock<RwLock<HashMap<u32, (String, Instant)>>> = OnceLock::new();
static HOSTNAME_CACHE: OnceLock<RwLock<Option<(String, Instant)>>> = OnceLock::new();
const CACHE_TTL: Duration = Duration::from_secs(30);

fn get_user_cache() -> &'static RwLock<HashMap<u32, (String, Instant)>> {
    USER_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

// Minimal /etc/passwd lookup (no extra deps)
fn read_username_from_passwd(uid: u32) -> Option<String> {
    let content = fs::read_to_string("/etc/passwd").ok()?;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // name:passwd:uid:gid:gecos:home:shell
        let mut parts = line.split(':');
        let name = parts.next()?;
        let _passwd = parts.next();
        let uid_field = parts.next()?;
        if uid_field.parse::<u32>().ok()? == uid {
            return Some(name.to_string());
        }
    }
    None
}

/// Cached lookup with 30s staleness window.
pub fn get_username(uid: u32) -> Option<String> {
    // Fast: get from cache
    {
        let map = get_user_cache().read().unwrap();
        if let Some((val, ts)) = map.get(&uid)
            && ts.elapsed() < CACHE_TTL
        {
            return Some(val.clone());
        }
    }

    // Slow: refresh from /etc/passwd
    if let Some(fresh) = read_username_from_passwd(uid) {
        let mut map = get_user_cache().write().unwrap();
        map.insert(uid, (fresh.clone(), Instant::now()));
        return Some(fresh);
    }

    None
}

fn read_proc_link(pid: u32, name: &str) -> io::Result<String> {
    let link = fs::read_link(format!("/proc/{}/{}", pid, name))?;
    // Linux may append " (deleted)" to exe; strip it for comparison/display.
    let mut s = link.to_string_lossy().into_owned();
    if let Some(stripped) = s.strip_suffix(" (deleted)") {
        s = stripped.to_string();
    }
    Ok(s)
}

pub fn get_proc_exe(pid: u32) -> Option<String> {
    read_proc_link(pid, "exe").ok()
}

pub fn get_proc_cwd(pid: u32) -> Option<String> {
    read_proc_link(pid, "cwd").ok()
}

pub fn get_proc_argv(pid: u32) -> Option<Vec<String>> {
    // /proc/<pid>/cmdline is NUL-separated and may end with a trailing NUL
    let path = format!("/proc/{}/cmdline", pid);
    let bytes = fs::read(path).ok()?;
    let parts = bytes
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    Some(parts)
}

fn split_norm_components(path: &str) -> Vec<String> {
    Path::new(path)
        .components()
        .filter_map(|c| match c {
            Component::RootDir => None,
            Component::CurDir => None,
            Component::ParentDir => None,
            Component::Normal(os) => Some(os.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect()
}

/// Check that `ebpf_tail` (possibly truncated from the left) matches the tail of `proc_full`.
/// If ebpf is empty, we consider it a match (let /proc win).
pub fn path_tail_matches(proc_full: &str, ebpf_tail: &str) -> bool {
    if ebpf_tail.is_empty() {
        return true;
    }
    let full = split_norm_components(proc_full);
    let tail = split_norm_components(ebpf_tail);
    if tail.is_empty() {
        return true;
    }
    if tail.len() > full.len() {
        return false;
    }
    let start = full.len() - tail.len();
    full[start..] == tail
}

/// Verify that the limited eBPF argv prefixes match the /proc argv.
/// Each eBPF arg (possibly truncated) must be a prefix of the corresponding /proc arg.
/// If eBPF argv is empty, we consider it a match (let /proc win).
pub fn argv_prefixes_match(proc_args: &[String], ebpf_args: &[String]) -> bool {
    if ebpf_args.is_empty() {
        return true;
    }
    let n = ebpf_args.len().min(proc_args.len());
    for i in 0..n {
        let eb = &ebpf_args[i];
        if eb.is_empty() {
            continue;
        }
        let pr = &proc_args[i];
        if !pr.starts_with(eb) {
            return false;
        }
    }
    true
}

fn read_hostname_file() -> Option<String> {
    for p in ["/etc/hostname", "/proc/sys/kernel/hostname"] {
        if let Ok(s) = fs::read_to_string(p) {
            let t = s.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }
    None
}

fn get_hostname_cache() -> &'static RwLock<Option<(String, Instant)>> {
    HOSTNAME_CACHE.get_or_init(|| RwLock::new(None))
}

/// Returns a chached hostname
pub fn get_hostname() -> Option<String> {
    {
        let cache = get_hostname_cache().read().unwrap();
        if let Some((val, ts)) = cache.as_ref()
            && ts.elapsed() < CACHE_TTL
        {
            return Some(val.clone());
        }
    }

    // Slow path: read from files
    if let Some(fresh) = read_hostname_file() {
        let mut cache = get_hostname_cache().write().unwrap();
        *cache = Some((fresh.clone(), Instant::now()));
        return Some(fresh);
    }

    None
}

/// Returns the machine-id as Some(String).
/// If /etc/machine-id cannot be read or is empty,
/// logs a warning and returns None
pub fn get_machine_id() -> Option<String> {
    MACHINE_ID
        .get_or_init(|| match fs::read_to_string("/etc/machine-id") {
            Ok(s) => {
                let trimmed = s.trim_end();
                if trimmed.is_empty() {
                    warn!("/etc/machine-id is empty, using fallback \"0\"");
                    None
                } else {
                    Some(trimmed.to_owned())
                }
            }
            Err(e) => {
                warn!("Failed to read /etc/machine-id: {e}");
                None
            }
        })
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_norm_components() {
        assert_eq!(
            split_norm_components("/usr//local/./bin/bash"),
            vec!["usr", "local", "bin", "bash"]
        );
    }

    #[test]
    fn test_path_tail_matches() {
        assert!(path_tail_matches("/usr/bin/bash", "/bin/bash"));
        assert!(path_tail_matches("/usr/bin/bash", ""));
        assert!(path_tail_matches("/usr/sbin/nginx", "/nginx"));
        assert!(!path_tail_matches("/usr/bin/bash", "/sbin/bash"));
        assert!(!path_tail_matches("/usr/bin/bash", "/usr/bin/bash/extra"));
    }

    #[test]
    fn test_argv_prefixes_match() {
        let proc = vec![
            "python3".to_string(),
            "-m".to_string(),
            "http.server".to_string(),
        ];
        let ebpf_good = vec!["py".to_string(), "-".to_string(), "http".to_string()];
        let ebpf_empty: Vec<String> = vec![];
        let ebpf_bad = vec!["ruby".to_string()];

        assert!(argv_prefixes_match(&proc, &ebpf_good));
        assert!(argv_prefixes_match(&proc, &ebpf_empty));
        assert!(!argv_prefixes_match(&proc, &ebpf_bad));
    }
}
