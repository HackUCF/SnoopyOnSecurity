use crate::firewall::{EventProducer, FirewallEvent};
use async_trait::async_trait;
use aya::maps::perf::AsyncPerfEventArray;
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::{Btf, EbpfLoader, Endianness};
use bytes::BytesMut;
use log::{debug, error, warn};
use std::mem::{MaybeUninit, size_of};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use tokio::sync::mpsc;
use tokio::time::Duration;

pub struct EbpfEventProducer {
    pub btf_file_path: PathBuf,
}

#[async_trait]
impl EventProducer for EbpfEventProducer {
    async fn run(&self, tx: mpsc::Sender<FirewallEvent>) -> anyhow::Result<()> {
        let mut ebpf = EbpfLoader::new()
            .btf(
                Btf::parse_file(&self.btf_file_path, Endianness::default())
                    .ok()
                    .as_ref(),
            )
            .load(aya::include_bytes_aligned!(concat!(
                env!("OUT_DIR"),
                "/firewall_events.bpf.o"
            )))?;

        attach_tp(
            &mut ebpf,
            "tp_sys_enter_connect",
            "syscalls",
            "sys_enter_connect",
        )?;
        attach_tp(&mut ebpf, "tp_sys_enter_bind", "syscalls", "sys_enter_bind")?;

        attach_tp(
            &mut ebpf,
            "tp_sys_enter_accept",
            "syscalls",
            "sys_enter_accept",
        )?;
        attach_tp(
            &mut ebpf,
            "tp_sys_exit_accept",
            "syscalls",
            "sys_exit_accept",
        )?;

        attach_tp(
            &mut ebpf,
            "tp_sys_enter_accept4",
            "syscalls",
            "sys_enter_accept4",
        )?;
        attach_tp(
            &mut ebpf,
            "tp_sys_exit_accept4",
            "syscalls",
            "sys_exit_accept4",
        )?;

        attach_tp(
            &mut ebpf,
            "tp_sys_enter_sendto",
            "syscalls",
            "sys_enter_sendto",
        )?;
        attach_tp(
            &mut ebpf,
            "tp_sys_enter_sendmsg",
            "syscalls",
            "sys_enter_sendmsg",
        )?;
        attach_tp(
            &mut ebpf,
            "tp_sys_enter_sendmmsg",
            "syscalls",
            "sys_enter_sendmmsg",
        )?;

        let events_map = ebpf.take_map("events").ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "events perf array not found")
        })?;

        let mut perf = AsyncPerfEventArray::try_from(events_map)?;

        for cpu_id in online_cpus().map_err(|(_, e)| e)? {
            let mut buf = perf.open(cpu_id, None)?;
            let tx = tx.clone();

            tokio::spawn(async move {
                let mut bufs: Vec<BytesMut> =
                    (0..16).map(|_| BytesMut::with_capacity(1024)).collect();

                loop {
                    let batch = match buf.read_events(&mut bufs).await {
                        Ok(b) => b,
                        Err(err) => {
                            error!("perf read error on cpu {}: {}", cpu_id, err);
                            continue;
                        }
                    };

                    for rec in bufs.iter_mut().take(batch.read) {
                        let ev = match parse_event(rec) {
                            Some(ev) => ev,
                            None => {
                                warn!("failed to parse perf record on cpu {}", cpu_id);
                                rec.clear();
                                continue;
                            }
                        };

                        debug!(
                            "perf firewall_event pid={} op={} fam={} dport={}",
                            ev.pid, ev.op, ev.family, ev.dport
                        );

                        let fev = build_fw_event(&ev);

                        if tx.send(fev).await.is_err() {
                            error!(
                                "firewall event receiver dropped; stopping event recording on cpu {}",
                                cpu_id
                            );
                            return;
                        }

                        rec.clear();
                    }
                }
            });
        }
        drop(tx);

        loop {
            tokio::time::sleep(Duration::from_secs(24 * 60 * 60)).await;
        }
    }
}

fn attach_tp(ebpf: &mut aya::Ebpf, prog_name: &str, cat: &str, tp: &str) -> anyhow::Result<()> {
    let p: &mut TracePoint = ebpf.program_mut(prog_name).unwrap().try_into()?;
    p.load()?;
    p.attach(cat, tp)?;
    Ok(())
}

fn comm_to_string(comm: &[u8; 16]) -> Option<String> {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
    let s = String::from_utf8_lossy(&comm[..end]).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Event {
    pid: i32,
    op: u32,
    family: u16,
    dport: u16,
    comm: [u8; 16],
    addr: [u8; 16], // union size
}

fn parse_event(buf: &[u8]) -> Option<Event> {
    let need = size_of::<Event>();
    if buf.len() < need {
        warn!("perf record too small: got {}, need {}", buf.len(), need);
        return None;
    }

    let mut uninit = MaybeUninit::<Event>::uninit();
    unsafe {
        std::ptr::copy_nonoverlapping(buf.as_ptr(), uninit.as_mut_ptr() as *mut u8, need);
        Some(uninit.assume_init())
    }
}

fn addr_to_string(ev: &Event) -> Option<String> {
    match ev.family as i32 {
        2 => Some(Ipv4Addr::from([ev.addr[0], ev.addr[1], ev.addr[2], ev.addr[3]]).to_string()),
        10 => Some(Ipv6Addr::from(ev.addr).to_string()),
        _ => None,
    }
}

fn op_to_str(op: u32) -> &'static str {
    match op {
        1 => "connect",
        2 => "sendto",
        3 => "sendmsg",
        4 => "sendmmsg",
        5 => "accept",
        6 => "bind",
        _ => "unknown",
    }
}

fn build_fw_event(ev: &Event) -> FirewallEvent {
    FirewallEvent {
        pid: ev.pid,
        comm: comm_to_string(&ev.comm),
        dport: Some(ev.dport),
        ip: addr_to_string(ev),
        op: Some(op_to_str(ev.op).to_string()),
    }
}
