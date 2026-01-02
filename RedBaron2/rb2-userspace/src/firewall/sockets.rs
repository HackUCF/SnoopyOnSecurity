use std::{
    collections::HashSet,
    fs,
    fs::File,
    io::{self, BufRead, BufReader},
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
};

use libc::{SIGKILL, kill};
use log::{debug, info, warn};

use crate::firewall::event::nfq::Ipv4Key;

pub fn enumerate_udp_sockets(allow_paths: &HashSet<PathBuf>, enforcing: bool) -> io::Result<()> {
    kill_disallowed_sockets("/proc/net/udp", allow_paths, enforcing)?;
    Ok(())
}

pub fn enumerate_tcp_sockets(allow_paths: &HashSet<PathBuf>, enforcing: bool) -> io::Result<()> {
    kill_disallowed_sockets("/proc/net/tcp", allow_paths, enforcing)?;
    Ok(())
}

// needed for nfq
// XXX: should I move this?
pub fn socket_exists(key: &Ipv4Key, target_pid: u64) -> bool {
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

pub fn get_active_socket_paths() -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut paths = list_active_socket_paths("/proc/net/tcp")?;
    paths.extend(list_active_socket_paths("/proc/net/udp")?);
    paths.sort();
    paths.dedup();
    Ok(paths)
}

/// List executable paths that have at least one active (non-local) socket
fn list_active_socket_paths(
    socket_table_path: &str,
) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
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

/// kills disallowed pre-existing sockets on non-local bindings
fn kill_disallowed_sockets(
    socket_table_path: &str,
    allow_paths: &HashSet<PathBuf>,
    enforcing: bool,
) -> io::Result<()> {
    let file = File::open(socket_table_path)?;
    let reader = BufReader::new(file);

    for line in reader.lines().skip(1) {
        let line = line?;
        let parts: Vec<_> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }

        let local = parts[1];
        let remote = parts[2];
        let inode_str = parts[9];

        let (local_ip, local_port) = split_ip_port(local).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "unable to parse local ip/port")
        })?;
        let (remote_ip, remote_port) = split_ip_port(remote).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "unable to parse remote ip/port")
        })?;
        let inode = inode_str.parse::<u64>().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid inode '{}': {}", inode_str, e),
            )
        })?;

        if is_local_ip(local_ip) && is_local_ip(remote_ip) {
            continue;
        }

        let pid = match find_pid_by_inode(inode) {
            Some(pid) => pid,
            None => {
                info!("Could not find pid by inode {}", inode);
                continue;
            }
        };

        let exe_path_str = match get_exe_path(pid) {
            Some(path) => path,
            None => {
                info!("Could not find exe_path_str by pid {}", pid);
                continue;
            }
        };

        let exe_path = Path::new(&exe_path_str);

        let allow = allow_paths.contains(exe_path);

        if !allow {
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
        }

        info!(
            "Found existing connection saddr {} sport {} daddr {} dport {} path {} pid {}{}",
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            exe_path_str,
            pid,
            if !allow { " (kill signal sent)" } else { "" }
        );
    }

    Ok(())
}

fn is_local_ip(ip: u32) -> bool {
    let ip = IpAddr::V4(Ipv4Addr::from(ip));
    ip.is_loopback()
}

pub fn kill_pid(pid: u64) -> io::Result<()> {
    // XXX: this doesn't actually verify that things were killed
    let pid = pid.try_into().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("PID conversion failed: {}", e),
        )
    })?;
    let result = unsafe { kill(pid, SIGKILL) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// returns the pid associated with the inode entry
fn find_pid_by_inode(target_inode: u64) -> Option<u64> {
    for entry in fs::read_dir("/proc").ok()? {
        let pid_dir = entry.ok()?.path();
        let pid_str = pid_dir.file_name()?.to_string_lossy();
        let pid: u64 = match pid_str.parse() {
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

fn get_exe_path(pid: u64) -> Option<String> {
    fs::read_link(format!("/proc/{}/exe", pid))
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
