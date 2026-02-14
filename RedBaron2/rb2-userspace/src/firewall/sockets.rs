use crate::firewall::event::nfq::Ipv4Key;
use crate::misc::{get_hostname, get_machine_id};
use chrono::SecondsFormat;
use libc::{SIGKILL, getpid, kill};
use log::{debug, info, warn};
use std::{
    collections::HashSet,
    fs,
    fs::File,
    io::{self, BufRead, BufReader},
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
};

#[derive(Debug, Clone)]
pub struct SocketOffender {
    pub pid: i32,
    pub exe_path: String,
    pub ip: IpAddr,
    pub port: u16,
}

// TODO: enumerate ipv6 at /proc/net/tcp6 or udp6

pub async fn enumerate_udp_sockets(
    allow_paths: &HashSet<PathBuf>,
    enforcing: bool,
) -> io::Result<Vec<SocketOffender>> {
    kill_disallowed_sockets("/proc/net/udp", allow_paths, enforcing).await
}

pub async fn enumerate_tcp_sockets(
    allow_paths: &HashSet<PathBuf>,
    enforcing: bool,
) -> io::Result<Vec<SocketOffender>> {
    kill_disallowed_sockets("/proc/net/tcp", allow_paths, enforcing).await
}

// needed for nfq
// XXX: should I move this?
pub fn socket_exists(key: &Ipv4Key, target_pid: i32) -> bool {
    let k_sport = key.sport;
    let k_dport = key.dport;
    let k_daddr = key.daddr;

    for path in ["/proc/net/tcp", "/proc/net/udp"] {
        if let Ok(file) = File::open(path) {
            let reader = BufReader::new(file);
            for line in reader.lines().skip(1).flatten() {
                let parts: Vec<_> = line.split_whitespace().collect();
                if parts.len() < 10 {
                    continue;
                }

                let local = parts[1]; // local_address:port => sport
                let remote = parts[2]; // remote_address:port => daddr + dport
                let state = parts[3]; // socket state
                let inode_str = parts[9];

                // 01 = TCP_ESTABLISHED, 02 = TCP_SYN_SENT, 03 = TCP_SYN_RECV
                if path.contains("tcp") && !["01", "02", "03"].contains(&state) {
                    continue;
                }

                let (_, sport) = match split_ip_port(local) {
                    Some(v) => v,
                    None => continue,
                };
                let (daddr, dport) = match split_ip_port(remote) {
                    Some(v) => v,
                    None => continue,
                };

                if let Ok(inode) = inode_str.parse::<u64>()
                    && let Some(pid) = find_pid_by_inode(inode)
                {
                    if pid != target_pid {
                        continue;
                    }

                    if daddr == 0 && dport == 0 {
                        // For UDP, remote might be 0:0 until first packet is sent
                        if path.contains("udp") && pid == target_pid && k_sport == sport {
                            return true;
                        }
                        // Skip TCP listening sockets
                        continue;
                    }

                    if path.contains("tcp") && daddr == 0 && dport == 0 {
                        continue;
                    }

                    if pid == target_pid && k_sport == sport && k_dport == dport && k_daddr == daddr
                    {
                        return true;
                    }
                }
            }
        }
    }

    false
}

pub fn get_active_socket_paths() -> anyhow::Result<Vec<PathBuf>> {
    let mut paths = list_active_socket_paths("/proc/net/tcp")?;
    paths.extend(list_active_socket_paths("/proc/net/udp")?);
    paths.sort();
    paths.dedup();
    Ok(paths)
}

/// List executable paths that have at least one active (non-local) socket
fn list_active_socket_paths(socket_table_path: &str) -> anyhow::Result<Vec<PathBuf>> {
    let file = File::open(socket_table_path)?;
    let reader = BufReader::new(file);
    let mut paths: Vec<PathBuf> = Vec::new();

    for line in reader.lines().skip(1) {
        let line = line?;
        let parts: Vec<_> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }

        let local = parts[1];
        let remote = parts[2];
        let inode_str = parts[9];

        let (local_ip, _local_port) = match split_ip_port(local) {
            Some(v) => v,
            None => continue,
        };
        let (remote_ip, _remote_port) = match split_ip_port(remote) {
            Some(v) => v,
            None => continue,
        };

        // Skip sockets where both endpoints are loopback
        if is_local_ip(local_ip) && is_local_ip(remote_ip) {
            continue;
        }

        let inode = match inode_str.parse::<u64>() {
            Ok(v) => v,
            Err(_) => continue,
        };

        let pid = match find_pid_by_inode(inode) {
            Some(pid) => pid,
            None => continue,
        };

        if let Some(exe_path_str) = get_exe_path(pid) {
            paths.push(PathBuf::from(exe_path_str));
        }
    }

    Ok(paths)
}

/// Kills disallowed pre-existing sockets on non-local bindings,
/// and returns the set of offenders so the caller can log DENY
async fn kill_disallowed_sockets(
    socket_table_path: &str,
    allow_paths: &HashSet<PathBuf>,
    enforcing: bool,
) -> io::Result<Vec<SocketOffender>> {
    use tokio::{
        fs::File,
        io::{AsyncBufReadExt, BufReader},
    };
    let file = File::open(socket_table_path).await?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();

    // skip header
    lines.next_line().await?;

    let mut offenders = Vec::new();

    while let Some(line) = lines.next_line().await? {
        let parts: Vec<_> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }

        let local = parts[1];
        let remote = parts[2];
        let inode_str = parts[9];

        let (local_ip_u32, local_port) = match split_ip_port(local) {
            Some(v) => v,
            None => continue,
        };
        let (remote_ip_u32, remote_port) = match split_ip_port(remote) {
            Some(v) => v,
            None => continue,
        };

        if is_local_ip(local_ip_u32) && is_local_ip(remote_ip_u32) {
            continue;
        }

        let inode = match inode_str.parse::<u64>() {
            Ok(v) => v,
            Err(_) => continue,
        };

        let pid = match find_pid_by_inode_async(inode).await {
            Some(pid) => pid,
            None => {
                info!("Could not find pid by inode {}", inode);
                continue;
            }
        };

        let exe_path_str = match get_exe_path_async(pid).await {
            Some(p) => p,
            None => {
                info!("Could not find exe_path_str by pid {}", pid);
                continue;
            }
        };

        let exe_path = Path::new(&exe_path_str);
        let allow = allow_paths.contains(exe_path);

        let local_ip = Ipv4Addr::from(local_ip_u32);
        let remote_ip = Ipv4Addr::from(remote_ip_u32);

        if !allow {
            // unchanged behavior
            if enforcing {
                match kill_pid(pid) {
                    Ok(()) => debug!("Killed pid: {} with active sockets", pid),
                    Err(e) => warn!("Failed to kill pid {} with active sockets: {}", pid, e),
                }
            } else {
                warn!(
                    "Would have killed pid {} if not in enforcing due to active sockets",
                    pid
                );
            }

            let port = if remote_port == 0 && remote_ip.is_unspecified() {
                local_port
            } else {
                remote_port
            };

            offenders.push(SocketOffender {
                pid,
                exe_path: exe_path_str.clone(),
                ip: std::net::IpAddr::V4(remote_ip),
                port,
            });
        }

        let action = if !allow { "DENY" } else { "ALLOW" };

        // Human-readable to stdout
        info!(
            "Existing connection saddr={} sport={} daddr={} dport={} path={} pid={} action={} enforcing={}",
            local_ip, local_port, remote_ip, remote_port, exe_path_str, pid, action, enforcing
        );

        // be less noisy with logging by only logging denies here
        if !allow {
            let ts = chrono::Local::now().to_rfc3339_opts(SecondsFormat::Millis, true);
            let json = serde_json::json!({
                "timestamp": ts,
                "decision": action,
                "enforcing": enforcing,
                "pid": pid,
                "path": exe_path_str,
                "op": "existing_socket",
                "ip": local_ip.to_string(),
                "port": local_port,
                "peer_ip": remote_ip.to_string(),
                "peer_port": remote_port,
                "host_name": get_hostname(),
                "host_id": get_machine_id(),
            });

            info!(target: "rb2_firewall", "{}", json);
        }
    }

    Ok(offenders)
}

fn is_local_ip(ip: u32) -> bool {
    let ip = IpAddr::V4(Ipv4Addr::from(ip));
    ip.is_loopback()
}

pub fn kill_pid(pid: i32) -> io::Result<()> {
    // XXX: this doesn't actually verify that things were killed
    let me: i32 = unsafe { getpid() };

    if pid == me {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "refusing to kill self",
        ));
    }

    let result = unsafe { kill(pid, SIGKILL) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// returns the pid associated with the inode entry
fn find_pid_by_inode(target_inode: u64) -> Option<i32> {
    for entry in fs::read_dir("/proc").ok()? {
        let pid_dir = entry.ok()?.path();
        let pid_str = pid_dir.file_name()?.to_string_lossy();
        let pid: i32 = match pid_str.parse() {
            Ok(n) => n,
            Err(_) => continue, // skip non-numeric directories
        };
        let fd_dir = pid_dir.join("fd");

        let fd_entries = match fs::read_dir(&fd_dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };

        for fd in fd_entries {
            let fd_path = match fd {
                Ok(p) => p.path(),
                Err(_) => continue,
            };

            let link = match fs::read_link(&fd_path) {
                Ok(link) => link.to_string_lossy().to_string(),
                Err(_) => continue,
            };

            if link.starts_with("socket:[")
                && let Some(inode_str) = link
                    .strip_prefix("socket:[")
                    .and_then(|s| s.strip_suffix("]"))
                && let Ok(inode) = inode_str.parse::<u64>()
                && inode == target_inode
            {
                return Some(pid);
            }
        }
    }
    None
}

async fn find_pid_by_inode_async(target_inode: u64) -> Option<i32> {
    if target_inode == 0 {
        return None;
    }

    let mut proc = tokio::fs::read_dir("/proc").await.ok()?;

    loop {
        let entry = match proc.next_entry().await {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(_) => continue,
        };

        let pid_str = entry.file_name().to_string_lossy().to_string();
        let pid: i32 = match pid_str.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };

        let fd_dir = entry.path().join("fd");
        let mut fds = match tokio::fs::read_dir(&fd_dir).await {
            Ok(d) => d,
            Err(_) => continue,
        };

        loop {
            let fd = match fds.next_entry().await {
                Ok(Some(f)) => f,
                Ok(None) => break,
                Err(_) => continue,
            };

            let link = match tokio::fs::read_link(fd.path()).await {
                Ok(l) => l,
                Err(_) => continue,
            };

            let link = link.to_string_lossy();
            if link.starts_with("socket:[")
                && let Some(inode_str) = link
                    .strip_prefix("socket:[")
                    .and_then(|s| s.strip_suffix(']'))
                && let Ok(inode) = inode_str.parse::<u64>()
                && inode == target_inode
            {
                return Some(pid);
            }
        }
    }

    None
}

fn get_exe_path(pid: i32) -> Option<String> {
    fs::read_link(format!("/proc/{}/exe", pid))
        .ok()
        .map(|p| p.to_string_lossy().to_string())
}

async fn get_exe_path_async(pid: i32) -> Option<String> {
    tokio::fs::read_link(format!("/proc/{}/exe", pid))
        .await
        .ok()
        .map(|p| p.to_string_lossy().to_string())
}

fn split_ip_port(field: &str) -> Option<(u32, u16)> {
    let mut parts = field.split(':');
    let ip = parts.next()?;
    let port = parts.next()?;

    let ip_num = parse_hex_u32(ip)?;
    let ip_num = u32::from_be(ip_num);
    let port = parse_hex_u16(port)?;

    Some((ip_num, port))
}

fn parse_hex_u16(s: &str) -> Option<u16> {
    u16::from_str_radix(s, 16).ok()
}

fn parse_hex_u32(s: &str) -> Option<u32> {
    u32::from_str_radix(s, 16).ok()
}
