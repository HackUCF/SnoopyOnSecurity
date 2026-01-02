use crate::firewall::common::{EventProducer, FirewallEvent};
use async_trait::async_trait;
use aya::maps::perf::AsyncPerfEventArray;
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::{Btf, EbpfLoader, Endianness};
use bytes::BytesMut;
use log::{debug, error, warn};
use std::mem::{MaybeUninit, size_of};
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

        let prog: &mut TracePoint = ebpf
            .program_mut("tp_sys_enter_connect")
            .unwrap()
            .try_into()?;
        prog.load()?;
        prog.attach("syscalls", "sys_enter_connect")?;

        let prog: &mut TracePoint = ebpf
            .program_mut("tp_sys_enter_sendto")
            .unwrap()
            .try_into()?;
        prog.load()?;
        prog.attach("syscalls", "sys_enter_sendto")?;

        let prog: &mut TracePoint = ebpf
            .program_mut("tp_sys_enter_sendmsg")
            .unwrap()
            .try_into()?;
        prog.load()?;
        prog.attach("syscalls", "sys_enter_sendmsg")?;

        let prog: &mut TracePoint = ebpf
            .program_mut("tp_sys_enter_sendmmsg")
            .unwrap()
            .try_into()?;
        prog.load()?;
        prog.attach("syscalls", "sys_enter_sendmmsg")?;

        let events_map = ebpf.take_map("events").ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "events perf array not found")
        })?;

        let mut perf = AsyncPerfEventArray::try_from(events_map)?;

        // Spawn one task per CPU.
        for cpu_id in online_cpus().map_err(|(_, e)| e)? {
            let mut buf = perf.open(cpu_id, None)?;
            let tx = tx.clone();

            tokio::spawn(async move {
                // Multiple scratch buffers per read to batch events.
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

                        debug!("perf firewall_event pid={}", ev.pid);

                        if tx
                            .send(FirewallEvent {
                                pid: ev.pid,
                                context: comm_to_string(&ev.comm),
                            })
                            .await
                            .is_err()
                        {
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

        // Run forever
        loop {
            tokio::time::sleep(Duration::from_secs(24 * 60 * 60)).await;
        }
    }
}

fn comm_to_string(comm: &[u8; 16]) -> Option<String> {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
    let s = String::from_utf8_lossy(&comm[..end]).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct AllowEvent {
    pid: u32,
    comm: [u8; 16],
}

fn parse_event(buf: &[u8]) -> Option<AllowEvent> {
    let need = size_of::<AllowEvent>();
    if buf.len() < need {
        warn!("perf record too small: got {}, need {}", buf.len(), need);
        return None;
    }

    let mut uninit = MaybeUninit::<AllowEvent>::uninit();
    unsafe {
        let dst = uninit.as_mut_ptr() as *mut u8;
        std::ptr::copy_nonoverlapping(buf.as_ptr(), dst, need);
        Some(uninit.assume_init())
    }
}
