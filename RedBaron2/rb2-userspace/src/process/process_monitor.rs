use crate::{config::yaml, log_file, process::helper};
use aya::maps::AsyncPerfEventArray;
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::{Btf, EbpfLoader, Endianness, Pod};
use bytes::BytesMut;
use chrono::{SecondsFormat, TimeZone};
#[allow(unused_imports)]
use flying_ace_engine::{EcsRhaiEngine, ProcessEvent as EngineEvent};
use log::{debug, error, info, warn};
use std::mem::{MaybeUninit, size_of};
use std::sync::OnceLock;
use std::{convert::Infallible, path::Path};
use std::{fs, io};
use tokio::sync::mpsc;

// Mirror the C headers exactly
const TASK_COMM_LEN: usize = 16;
const MAX_ARG_CHARS: usize = 32;
const MAX_ARGS: usize = 8;
const MAX_PATH_COMPONENT_SIZE: usize = 32;
const MAX_PATH_COMPONENTS: usize = 8;

static BTIME: OnceLock<u64> = OnceLock::new();

/// get time in unix epoch seconds since last boot
/// OnceLock fails over to 0 with a warning message
fn get_btime() -> &'static u64 {
    BTIME.get_or_init(|| match stat_btime() {
        Ok(t) => t,
        Err(e) => {
            warn!(
                "Unable to get btime, process_monitor time will be wrong: {}",
                e
            );
            0
        }
    })
}

/// get btime from /proc/stat
fn stat_btime() -> io::Result<u64> {
    let stat = fs::read_to_string("/proc/stat")?;

    for line in stat.lines() {
        if let Some(rest) = line.strip_prefix("btime ") {
            // btime is seconds since Unix epoch
            let v = rest
                .trim()
                .parse::<u64>()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            return Ok(v);
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "btime not found in /proc/stat",
    ))
}

#[repr(C)]
#[derive(Copy, Clone)]
struct Args {
    argc: u32,
    args: [[u8; MAX_ARG_CHARS]; MAX_ARGS],
}
unsafe impl Pod for Args {}

#[repr(C)]
#[derive(Copy, Clone)]
struct ProcessEvent {
    timestamp: u64, // ns since boot

    pid: u32,
    ppid: u32,
    uid: u32,

    name: [u8; TASK_COMM_LEN],
    pname: [u8; TASK_COMM_LEN],

    argv: Args,
    executable: [[u8; MAX_PATH_COMPONENT_SIZE]; MAX_PATH_COMPONENTS], // basename-first order
    working_directory: [[u8; MAX_PATH_COMPONENT_SIZE]; MAX_PATH_COMPONENTS],
}
unsafe impl Pod for ProcessEvent {}

fn nul_terminated_to_string(buf: &[u8]) -> String {
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let s = &buf[..len];
    String::from_utf8_lossy(s).into_owned()
}

fn decode_comm(name: &[u8; TASK_COMM_LEN]) -> String {
    nul_terminated_to_string(name)
}

fn decode_argv(argv: &Args) -> Vec<String> {
    (0..argv.argc as usize)
        .map(|i| nul_terminated_to_string(&argv.args[i]))
        .collect()
}

fn decode_path(components: &[[u8; MAX_PATH_COMPONENT_SIZE]; MAX_PATH_COMPONENTS]) -> String {
    // eBPF fills basename-first as it walks dentry->parent, so reverse non-empty parts
    let mut parts: Vec<String> = components
        .iter()
        .map(|c| nul_terminated_to_string(c))
        .filter(|s| !s.is_empty())
        .collect();
    if parts.is_empty() {
        return String::new();
    }
    parts.reverse();
    // Join with '/' and ensure a leading '/'
    let joined = parts.join("/");
    format!("/{}", joined)
}

pub async fn run<P: AsRef<Path>>(
    btf_file_path: P,
    cfg: yaml::ProcessConfig,
) -> anyhow::Result<Infallible> {
    let mut ebpf = EbpfLoader::new()
        .btf(
            Btf::parse_file(btf_file_path.as_ref(), Endianness::default())
                .ok()
                .as_ref(),
        )
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/process_start.bpf.o"
        )))?;

    let prog: &mut TracePoint = ebpf.program_mut("trace_exec_enter").unwrap().try_into()?;
    prog.load()?;
    prog.attach("syscalls", "sys_enter_execve")?;

    let prog: &mut TracePoint = ebpf.program_mut("trace_exec_exit").unwrap().try_into()?;
    prog.load()?;
    prog.attach("syscalls", "sys_exit_execve")?;

    let events_map = ebpf.take_map("events").ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "events perf array not found")
    })?;

    let mut perf = AsyncPerfEventArray::try_from(events_map)?;

    // Initialize RHai engine from configured directory (fallback if unset)
    /*
    let engine = EcsRhaiEngine::new_from_dir(cfg.rhai_rules_dir.to_string_lossy().as_ref());
    info!(
        "RHAI engine initialized from directory: {}",
        cfg.rhai_rules_dir.to_string_lossy()
    );
    */

    let log_file_path = cfg.log_file.clone();
    let mut log_file = match log_file::open_log_file_async(&cfg.log_file).await {
        Ok(f) => Some(f),
        Err(e) => {
            warn!("Failed to open process monitor log file: {}", e);
            None
        }
    };

    let (tx, mut rx) = mpsc::channel(128);

    for cpu_id in online_cpus().map_err(|(_, e)| e)? {
        let mut buf = perf.open(cpu_id, None)?;
        let tx = tx.clone();
        tokio::spawn(async move {
            // Multiple scratch buffers per read to batch events.
            let mut bufs: Vec<BytesMut> = (0..16).map(|_| BytesMut::with_capacity(1024)).collect();

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

                    debug!("perf process_event pid={}", ev.pid);

                    if tx.send(convert_event(&ev)).await.is_err() {
                        error!(
                            "process monitor event receiver dropped; stopping event recording on cpu {}",
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

    info!("Setup process monitor, listening for process create events");

    loop {
        if let Some(event) = rx.recv().await {
            debug!("Event {}", event);

            // Try to write to log file, recreate if it fails
            if let Some(f) = log_file.as_mut() {
                if let Err(e) =
                    log_file::write_log_line_async(f, &log_file_path, &event.to_string()).await
                {
                    warn!("Failed to write to process monitor log file: {}", e);
                }
            } else {
                // Try to recreate the file if it was None
                match log_file::open_log_file_async(&log_file_path).await {
                    Ok(new_file) => {
                        log_file = Some(new_file);
                        // Retry the write
                        if let Some(f) = log_file.as_mut()
                            && let Err(e) = log_file::write_log_line_async(
                                f,
                                &log_file_path,
                                &event.to_string(),
                            )
                            .await
                        {
                            warn!(
                                "Failed to write to recreated process monitor log file: {}",
                                e
                            );
                        }
                    }
                    Err(_) => {
                        // File still can't be opened, skip logging
                    }
                }
            }

            /*
            let res = engine.eval(&event);
            if !res.is_empty() {
                info!("RHAI matched rules: {:?}", res);
            }
            debug!("Res {:?}", res);
            */
        }
    }
}

fn parse_event(buf: &[u8]) -> Option<ProcessEvent> {
    let need = size_of::<ProcessEvent>();
    if buf.len() < need {
        warn!("perf record too small: got {}, need {}", buf.len(), need);
        return None;
    }

    let mut uninit = MaybeUninit::<ProcessEvent>::uninit();
    unsafe {
        let dst = uninit.as_mut_ptr() as *mut u8;
        std::ptr::copy_nonoverlapping(buf.as_ptr(), dst, need);
        Some(uninit.assume_init())
    }
}

fn convert_event(e: &ProcessEvent) -> EngineEvent {
    // ebpf-based info
    let comm = decode_comm(&e.name);
    let ebpf_exe = decode_path(&e.executable);
    let ebpf_cwd = decode_path(&e.working_directory);
    let ebpf_argv = decode_argv(&e.argv);
    let ebpf_argv_joined = {
        let s = ebpf_argv.join(" ");
        if s.is_empty() { None } else { Some(s) }
    };
    let pcomm = decode_comm(&e.pname);

    let host_name = helper::get_hostname();
    let user_name = helper::get_username(e.uid);

    let proc_exe = helper::get_proc_exe(e.pid);
    let proc_cwd = helper::get_proc_cwd(e.pid);
    let proc_argv = helper::get_proc_argv(e.pid);

    /*
     * Decode if the proc data is good enough to expand on the ebpf data
     * This is because the ebpf bytes read are limited.
     */

    // Decide final args
    let process_args = match (&proc_argv, &ebpf_argv) {
        (Some(proc_argv), ebpf_argv) if helper::argv_prefixes_match(proc_argv, ebpf_argv) => {
            let joined = proc_argv.join(" ");
            if joined.is_empty() {
                ebpf_argv_joined
            } else {
                Some(joined)
            }
        }
        _ => ebpf_argv_joined,
    };
    // Decide final executable path
    let process_executable = match (&proc_exe, &ebpf_exe) {
        (Some(proc_exe), ebpf) if helper::path_tail_matches(proc_exe, ebpf) || ebpf.is_empty() => {
            Some(proc_exe.clone())
        }
        _ => {
            if ebpf_exe.is_empty() {
                None
            } else {
                Some(ebpf_exe.clone())
            }
        }
    };
    // Decide final working directory
    let process_working_directory = match (&proc_cwd, &ebpf_cwd) {
        (Some(proc_cwd), ebpf) if helper::path_tail_matches(proc_cwd, ebpf) || ebpf.is_empty() => {
            Some(proc_cwd.clone())
        }
        _ => {
            if ebpf_cwd.is_empty() {
                None
            } else {
                Some(ebpf_cwd.clone())
            }
        }
    };

    // convert nanoseconds to ISO8601 timestamp
    let timestamp = chrono::Local
        .timestamp_opt(
            (e.timestamp / 1_000_000_000 + get_btime()) as i64,
            (e.timestamp % 1_000_000_000) as u32,
        )
        .single()
        .map(|ts| ts.to_rfc3339_opts(SecondsFormat::Millis, true))
        .unwrap_or_else(|| "unknown".to_string());

    EngineEvent {
        timestamp,
        ecs_version: "0.1.0".to_string(), // just picked a random one lol

        // event.*
        event_kind: "event".to_string(),
        event_category: "process".to_string(),
        event_type: "creation".to_string(),
        event_action: Some("process-started".to_string()),
        event_code: None,
        event_module: Some("ebpf".to_string()),

        // process.*
        process_name: comm,
        process_pid: e.pid,
        process_args,
        process_executable,
        process_ppid: Some(e.ppid),
        process_pname: Some(pcomm),
        process_working_directory,

        // host.*
        host_name,
        host_id: helper::get_machine_id(),

        // user.*
        user_name,
        user_id: Some(e.uid),

        // agent.*
        agent_type: Some("red-baron linux".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nul_terminated_to_string() {
        let mut buf = [0u8; 8];
        buf[..4].copy_from_slice(b"bash");
        assert_eq!(nul_terminated_to_string(&buf), "bash");

        let buf = b"no-nul".to_vec();
        assert_eq!(nul_terminated_to_string(&buf), "no-nul");
    }

    #[test]
    fn test_decode_path_reverses() {
        let mut comps = [[0u8; MAX_PATH_COMPONENT_SIZE]; MAX_PATH_COMPONENTS];
        // simulate ebpf basename-first
        comps[0][..3].copy_from_slice(b"bin");
        comps[1][..3].copy_from_slice(b"usr");
        // Empty remainder should be ignored
        println!("{}", decode_path(&comps));
        assert_eq!(decode_path(&comps), "/usr/bin");
    }
}
