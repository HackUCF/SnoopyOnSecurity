use crate::firewall::common::{EventProducer, FirewallEvent};
use anyhow::{Context, bail};
use async_trait::async_trait;
use linux_audit_parser::{Common, EventID, Key, MessageType, Number, Parser, Value};
use log::{debug, error, info, trace};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    time::{Duration, Instant},
};
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, AsyncSeekExt, BufReader},
    process::Command,
    sync::mpsc,
    time::sleep,
};

const AUDIT_RULE_KEY: &str = "net_connections";
const EVENT_TIMEOUT: Duration = Duration::from_secs(5);

pub struct AuditdEventProducer {
    audit_log_path: PathBuf,
}

impl AuditdEventProducer {
    #[allow(dead_code)]
    pub fn new(audit_log_path: PathBuf) -> Self {
        Self { audit_log_path }
    }

    pub fn with_default_path() -> Self {
        Self {
            audit_log_path: PathBuf::from("/var/log/audit/audit.log"),
        }
    }
}

#[async_trait]
impl EventProducer for AuditdEventProducer {
    async fn run(&self, tx: mpsc::Sender<FirewallEvent>) -> anyhow::Result<()> {
        ensure_auditd_setup().await?;

        let path = &self.audit_log_path;

        let file = File::open(path)
            .await
            .with_context(|| format!("opening audit log {}", path.display()))?;
        let mut reader = BufReader::new(file);

        // tail file
        reader
            .seek(std::io::SeekFrom::End(0))
            .await
            .context("seek to end of audit log")?;
        // seek to end of last line if reading mid-write
        let mut discard = String::new();
        let _ = reader.read_line(&mut discard).await;

        info!("Starting auditd event producer, tailing {}", path.display());

        let parser = Parser::default();
        let mut pending_events: HashMap<EventID, PendingEvent> = HashMap::new();

        let mut line = String::new();
        loop {
            // XXX: This loop is kinda slow to get new lines
            // Maybe smth like linemux, notify, or fanotify to tail the file async?
            match reader.read_line(&mut line).await {
                Ok(0) => {
                    cleanup_stale_events(&mut pending_events);
                    sleep(Duration::from_millis(50)).await;
                }
                Ok(_) => {
                    if let Some(ev) =
                        process_audit_line(&parser, line.as_bytes(), &mut pending_events)
                    {
                        tx.send(ev)
                            .await
                            .context("Firewall event receiver dropped")?;
                    }
                }
                Err(e) => {
                    error!("Error reading audit log: {e}");
                    sleep(Duration::from_millis(1000)).await;
                }
            }
            line.clear()
        }
    }
}

#[derive(Debug)]
struct PendingEvent {
    pid: Option<u32>,
    comm: Option<String>,
    has_network_addr: bool,
    last_update: Instant,
}

// auditd setup

async fn ensure_auditd_setup() -> anyhow::Result<()> {
    if !is_auditd_running().await? {
        bail!("auditd is not running. Start it with: systemctl start auditd");
    }

    ensure_audit_rule().await?;
    info!("auditd is running and connect rule is configured");
    Ok(())
}

async fn is_auditd_running() -> anyhow::Result<bool> {
    let output = Command::new("systemctl")
        .args(["is-active", "auditd"])
        .output()
        .await
        .context("checking auditd service status")?;

    Ok(output.status.success())
}

async fn ensure_audit_rule() -> anyhow::Result<()> {
    let output = Command::new("auditctl")
        .arg("-l")
        .output()
        .await
        .context("listing audit rules")?;

    if !output.status.success() {
        bail!("Failed to list audit rules. Ensure CAP_AUDIT_CONTROL or run as root");
    }

    let rules = String::from_utf8_lossy(&output.stdout);
    let rule_pattern_k = format!("-S connect -k {}", AUDIT_RULE_KEY);
    let rule_pattern_key = format!("-S connect -F key={}", AUDIT_RULE_KEY);

    if rules.contains(&rule_pattern_k) || rules.contains(&rule_pattern_key) {
        debug!("Audit rule for connect already exists");
        return Ok(());
    }

    trace!("Adding audit rule for network connects");
    let output = Command::new("auditctl")
        .args([
            "-a",
            "exit,always",
            "-F",
            "arch=b64",
            "-S",
            "connect",
            "-k",
            AUDIT_RULE_KEY,
        ])
        .output()
        .await
        .context("adding audit rule")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Failed to add audit rule: {stderr}");
    }

    debug!("Successfully added audit rule");
    Ok(())
}

// parsing / event assembly

fn process_audit_line(
    parser: &Parser,
    line: &[u8],
    pending_events: &mut HashMap<EventID, PendingEvent>,
) -> Option<FirewallEvent> {
    let message = match parser.parse(line) {
        Ok(msg) => msg,
        Err(_) => return None,
    };

    let event_id = message.id;

    match message.ty {
        MessageType::SYSCALL => {
            let mut pid: Option<u32> = None;
            let mut comm: Option<String> = None;
            let mut has_key = false;

            for (key, value) in &message.body {
                match key {
                    Key::Common(Common::Key) => {
                        if let Value::Str(s, _) = value
                            && s.windows(AUDIT_RULE_KEY.len())
                                .any(|w| w == AUDIT_RULE_KEY.as_bytes())
                        {
                            has_key = true;
                        }
                    }
                    Key::Common(Common::Pid) => {
                        if let Value::Number(n) = value {
                            pid = Some(extract_number(n) as u32);
                        }
                    }
                    Key::Common(Common::Comm) => {
                        if let Value::Str(s, _) = value {
                            comm = Some(String::from_utf8_lossy(s).into_owned());
                        }
                    }
                    _ => {}
                }
            }

            if !has_key {
                return None;
            }

            let entry = pending_events
                .entry(event_id)
                .or_insert_with(|| PendingEvent {
                    pid: None,
                    comm: None,
                    has_network_addr: false,
                    last_update: Instant::now(),
                });

            if pid.is_some() {
                entry.pid = pid;
            }
            if comm.is_some() {
                entry.comm = comm;
            }
            entry.last_update = Instant::now();

            None
        }

        MessageType::SOCKADDR => {
            if let Some(entry) = pending_events.get_mut(&event_id) {
                let mut has_network_addr = false;

                for (key, value) in &message.body {
                    if key == "saddr"
                        && let Value::Str(s, _) = value
                        && parse_sockaddr(s).is_some()
                    {
                        has_network_addr = true;
                        break;
                    }
                }

                if has_network_addr {
                    entry.has_network_addr = true;
                    entry.last_update = Instant::now();

                    if let Some(pid) = entry.pid {
                        trace!("Complete network connection event for pid={pid}");
                        let comm = entry.comm.clone();
                        pending_events.remove(&event_id);
                        return Some(FirewallEvent { pid, context: comm });
                    }
                }
            }

            None
        }

        MessageType::EOE => {
            if let Some(entry) = pending_events.remove(&event_id)
                && entry.has_network_addr
                && let Some(pid) = entry.pid
            {
                trace!("Complete network connection event at EOE for pid={pid}");
                return Some(FirewallEvent {
                    pid,
                    context: entry.comm,
                });
            }
            None
        }

        _ => None,
    }
}

fn cleanup_stale_events(pending_events: &mut HashMap<EventID, PendingEvent>) {
    let now = Instant::now();
    pending_events.retain(|_, ev| {
        let stale = now.duration_since(ev.last_update) > EVENT_TIMEOUT;
        if stale {
            trace!("Dropping stale audit event with pid={:?}", ev.pid);
        }
        !stale
    });
}

fn extract_number(n: &Number) -> u64 {
    match n {
        Number::Hex(h) => *h,
        Number::Dec(d) => *d as u64,
        Number::Oct(o) => *o,
    }
}

/// ignores loopback as None
fn parse_sockaddr(saddr: &[u8]) -> Option<SocketAddr> {
    // Need at least family (2) + port (2)
    if saddr.len() < 4 {
        trace!("Invalid socket addr (too short: {})", saddr.len());
        return None;
    }

    // sa_family is little-endian (e.g., 0x02 0x00 for AF_INET)
    let family = u16::from_le_bytes([saddr[0], saddr[1]]);

    match family {
        2 => {
            // AF_INET
            // struct sockaddr_in:
            // u16 family; u16 port; u32 addr; u8 padding[8];
            if saddr.len() < 8 {
                trace!("Invalid ipv4 socket addr (too short: {})", saddr.len());
                return None;
            }

            let port = u16::from_be_bytes([saddr[2], saddr[3]]);
            let addr_bytes: [u8; 4] = saddr[4..8].try_into().ok()?;

            let ip = IpAddr::V4(Ipv4Addr::from(addr_bytes));

            if ip.is_loopback() {
                trace!("Ignoring loopback IPv4 addr: {}", ip);
                return None;
            }

            Some(SocketAddr::new(ip, port))
        }

        10 => {
            // AF_INET6
            // struct sockaddr_in6:
            // u16 family; u16 port; u32 flowinfo; u8 addr[16]; u32 scope_id;
            if saddr.len() < 24 {
                trace!("Invalid ipv6 socket addr (too short: {})", saddr.len());
                return None;
            }

            let port = u16::from_be_bytes([saddr[2], saddr[3]]);

            // Skip family(2) + port(2) + flowinfo(4) => 8 bytes, then 16 bytes addr
            let addr_bytes: [u8; 16] = saddr[8..24].try_into().ok()?;

            let ip = IpAddr::V6(Ipv6Addr::from(addr_bytes));

            if ip.is_loopback() {
                trace!("Ignoring loopback IPv6 addr: {}", ip);
                return None;
            }

            Some(SocketAddr::new(ip, port))
        }

        _ => {
            trace!("Unknown sockaddr family: {}", family);
            None
        }
    }
}
