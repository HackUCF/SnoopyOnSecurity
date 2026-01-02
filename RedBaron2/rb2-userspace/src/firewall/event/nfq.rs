use crate::firewall::common::{EventProducer, FirewallEvent};
use crate::firewall::sockets;
use anyhow::Context;
use anyhow::anyhow;
use async_trait::async_trait;
use aya::maps::{HashMap, MapData, MapError};
use aya::programs::KProbe;
use aya::{Btf, Ebpf, EbpfLoader, Endianness, Pod};
use log::{debug, error, info, trace, warn};
use nfq::{Queue, Verdict};
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};

/*
 *      +--->|userspace|
 *      |          ^V
 * --> |ebpf| --> |nfq| -->
 */

// TODO: build up nft support

pub struct NfqEventProducer {
    pub btf_path: PathBuf,
    pub enforcing: bool,
    receiver: OnceLock<Arc<Mutex<Receiver<Verdict>>>>,
}

impl NfqEventProducer {
    pub fn new(btf_path: PathBuf, enforcing: bool) -> NfqEventProducer {
        NfqEventProducer {
            btf_path,
            enforcing,
            receiver: OnceLock::new(),
        }
    }
    /// this sender must send back processed events for the firewall to work!
    pub fn get_sender(&self) -> anyhow::Result<Sender<Verdict>> {
        let (tx, rx) = tokio::sync::mpsc::channel(1024);
        let rx = Arc::new(Mutex::new(rx));
        self.receiver.set(rx).map_err(|_| {
            anyhow::anyhow!("Unable to set receiver OnceLock. Has get_sender been called twice?")
        })?;
        Ok(tx)
    }
}

#[async_trait]
impl EventProducer for NfqEventProducer {
    async fn run(&self, tx: Sender<FirewallEvent>) -> anyhow::Result<()> {
        let btf_path = self.btf_path.clone();
        let enforcing = self.enforcing;
        let receiver = self
            .receiver
            .get()
            .ok_or(anyhow!("Corresponding nfq event receiver not set up yet"))?
            .clone();

        tokio::task::spawn_blocking(move || {
            if let Err(e) = run_firewall_blocking(btf_path, enforcing, tx, receiver) {
                error!("NFQ firewall thread exited with error: {e}");
            }
        });

        Ok(())
    }
}

fn run_firewall_blocking(
    btf_path: PathBuf,
    enforcing: bool,
    tx: Sender<FirewallEvent>,
    receiver: Arc<Mutex<Receiver<Verdict>>>,
) -> anyhow::Result<()> {
    let mut ebpf = EbpfLoader::new()
        .btf(
            Btf::parse_file(btf_path, Endianness::default())
                .ok()
                .as_ref(),
        )
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/nfq_firewall.bpf.o"
        )))?;

    attach_kprobes(&mut ebpf)?;

    let tcp_raw = ebpf.take_map("tcpMap").unwrap();
    let udp_raw = ebpf.take_map("udpMap").unwrap();

    let mut tcp_map: HashMap<MapData, Ipv4Key, Owner> = HashMap::try_from(tcp_raw)?;
    let mut udp_map: HashMap<MapData, Ipv4Key, Owner> = HashMap::try_from(udp_raw)?;

    let mut queue = Queue::open().context("failed to open nfqueue")?;
    queue.bind(0).context("failed to bind nfqueue 0")?;
    info!("Netfilter queue ready");

    ensure_iptables()?;

    let mut last_cleanup = std::time::Instant::now();

    loop {
        let mut msg = match queue.recv() {
            Ok(m) => m,
            Err(e) => {
                error!("NFQ recv failed: {e}");
                continue;
            }
        };

        let verdict = handle_packet(
            &mut tcp_map,
            &mut udp_map,
            msg.get_payload(),
            &tx,
            &receiver,
        );

        match enforcing {
            true => msg.set_verdict(verdict),
            false => msg.set_verdict(Verdict::Accept),
        }

        if let Err(e) = queue.verdict(msg) {
            error!(
                "Failed to set verdict {} for packet: {e}",
                if verdict == Verdict::Accept {
                    "ALLOW"
                } else {
                    "DENY"
                }
            );
        }

        if last_cleanup.elapsed() >= Duration::from_secs(5) {
            if let Err(e) = delete_old_elements(&mut tcp_map) {
                error!("Failed to clean tcp map: {e}");
            }
            if let Err(e) = delete_old_elements(&mut udp_map) {
                error!("Failed to clean udp map: {e}");
            }
            last_cleanup = std::time::Instant::now();
        }
    }
}

fn handle_packet(
    tcp_map: &mut HashMap<MapData, Ipv4Key, Owner>,
    udp_map: &mut HashMap<MapData, Ipv4Key, Owner>,
    payload: &[u8],
    tx: &Sender<FirewallEvent>,
    receiver: &Arc<Mutex<Receiver<Verdict>>>,
) -> Verdict {
    if payload.is_empty() || (payload[0] >> 4) != 4 {
        warn!("Not parsing non-ipv4 packet");
        return Verdict::Drop;
    }

    let protocol = payload.get(9).copied().unwrap_or(0);

    let key = match parse_ipv4_key(payload) {
        Ok(k) => k,
        Err(e) => {
            error!("Malformed packet: {e}");
            return Verdict::Drop;
        }
    };

    let owner = match protocol {
        0x06 => tcp_map.get(&key, 0).ok(),
        0x11 => udp_map.get(&key, 0).ok(),
        _ => None,
    };

    if let Some(owner) = owner {
        let ev = FirewallEvent {
            pid: owner.pid as u32,
            context: comm_to_string(&owner.comm),
        };
        if let Err(e) = tx.blocking_send(ev) {
            let pid = owner.pid;
            error!(
                "Unable to send off firewall event to dispatcher pid={} {}",
                pid, e,
            );
            return Verdict::Drop;
        }

        let mut rx = match receiver.lock() {
            Ok(guard) => guard,
            Err(_) => {
                error!("Dispatcher receiver mutex poisoned");
                return Verdict::Drop;
            }
        };

        match rx.blocking_recv() {
            Some(v) => v,
            None => {
                error!("Dispatcher receiver closed");
                Verdict::Drop
            }
        }
    } else {
        warn!("Unknown socket connection from nfq");
        Verdict::Drop
    }
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct Ipv4Key {
    pub sport: u16,
    pub daddr: u32,
    pub dport: u16,
}
unsafe impl Pod for Ipv4Key {}

#[allow(dead_code)]
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct Owner {
    pub pid: u64,
    pub comm: [u8; 16],
}
unsafe impl Pod for Owner {}

fn comm_to_string(comm: &[u8; 16]) -> Option<String> {
    let nul = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
    let s = std::str::from_utf8(&comm[..nul]).ok()?.trim();
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

fn delete_old_elements(map: &mut HashMap<MapData, Ipv4Key, Owner>) -> Result<(), MapError> {
    // TODO: also remove sockets that no longer exist (can be a problem for smth like
    // systemd-resolvd which doesn't die but can open several sockets that close
    let keys: Vec<Ipv4Key> = map.keys().filter_map(Result::ok).collect();
    for key in keys {
        if let Ok(decision) = map.get(&key, 0) {
            let pid = decision.pid;
            if !pid_exists(pid) || !sockets::socket_exists(&key, pid) {
                trace!("Removing key for pid: {}", pid);
                map.remove(&key)?;
            }
        }
    }
    Ok(())
}

fn pid_exists(pid: u64) -> bool {
    Path::new(&format!("/proc/{}", pid)).exists()
}

fn parse_ipv4_key(payload: &[u8]) -> io::Result<Ipv4Key> {
    if payload.len() < 24 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Payload too short",
        ));
    }

    let daddr = u32::from_be_bytes(payload[16..20].try_into().unwrap());
    let sport = u16::from_be_bytes(payload[20..22].try_into().unwrap());
    let dport = u16::from_be_bytes(payload[22..24].try_into().unwrap());

    Ok(Ipv4Key {
        sport,
        daddr,
        dport,
    })
}

fn ensure_iptables() -> anyhow::Result<()> {
    match iptables_attached()? {
        true => {
            debug!("iptables rule already exists");
            Ok(())
        }
        false => {
            attach_iptables()?;
            Ok(())
        }
    }
}

fn iptables_attached() -> anyhow::Result<bool> {
    let ipt = iptables::new(false)
        .map_err(|e: Box<dyn Error>| anyhow::anyhow!("{}", e))
        .context("failed to open iptables")?;

    let rules = ipt
        .list("mangle", "OUTPUT")
        .map_err(|e: Box<dyn Error>| anyhow::anyhow!("{}", e))
        .context("failed to list iptables rules on mangle OUTPUT chain")?;

    let target_rule = "-A OUTPUT -m addrtype ! --dst-type LOCAL -m conntrack --ctstate NEW,RELATED -j NFQUEUE --queue-num 0 --queue-bypass";

    for line in &rules {
        if line.trim() == target_rule {
            return Ok(true);
        }
    }

    Ok(false)
}

fn attach_iptables() -> anyhow::Result<()> {
    let ipt = iptables::new(false)
        .map_err(|e: Box<dyn Error>| anyhow::anyhow!("{}", e))
        .context("failed to open iptables")?;

    let rule = "-m addrtype ! --dst-type LOCAL -m conntrack --ctstate NEW,RELATED -j NFQUEUE --queue-num 0 --queue-bypass";

    ipt.insert("mangle", "OUTPUT", rule, 1)
        .map_err(|e: Box<dyn Error>| anyhow::anyhow!("{}", e))
        .context("failed to insert NFQUEUE rule into mangle output at position 1")?;

    info!("Iptables output to the netfilter queue is now set up");

    Ok(())
}

fn attach_kprobes(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let tcpv4_kprobe: &mut KProbe = ebpf
        .program_mut("kprobe__tcp_v4_connect")
        .unwrap()
        .try_into()?;
    tcpv4_kprobe.load()?;
    tcpv4_kprobe.attach("tcp_v4_connect", 0)?;
    let tcpv4_kretprobe: &mut KProbe = ebpf
        .program_mut("kretprobe__tcp_v4_connect")
        .unwrap()
        .try_into()?;
    tcpv4_kretprobe.load()?;
    tcpv4_kretprobe.attach("tcp_v4_connect", 0)?;

    let udpv4_kprobe: &mut KProbe = ebpf
        .program_mut("kprobe__udp_sendmsg")
        .unwrap()
        .try_into()?;
    udpv4_kprobe.load()?;
    udpv4_kprobe.attach("udp_sendmsg", 0)?;

    let icmp_kprobe: &mut KProbe = ebpf
        .program_mut("kprobe__inet_dgram_connect")
        .unwrap()
        .try_into()?;
    icmp_kprobe.load()?;
    icmp_kprobe.attach("inet_dgram_connect", 0)?;
    let icmp_kretprobe: &mut KProbe = ebpf
        .program_mut("kretprobe__inet_dgram_connect")
        .unwrap()
        .try_into()?;
    icmp_kretprobe.load()?;
    icmp_kretprobe.attach("inet_dgram_connect", 0)?;

    let iptunnel_kprobe: &mut KProbe = ebpf
        .program_mut("kprobe__iptunnel_xmit")
        .unwrap()
        .try_into()?;
    iptunnel_kprobe.load()?;
    iptunnel_kprobe.attach("iptunnel_xmit", 0)?;

    debug!("Firewall kprobes attached");

    Ok(())
}
