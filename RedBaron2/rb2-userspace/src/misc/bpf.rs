use super::log::log_detection;
use aya::programs::ProgramError;
use aya::programs::loaded_programs;
use serde_json::Value;
use serde_json::json;
use std::collections::HashSet;
use std::io;
use tokio::fs::{self, File};
use tokio::io::{AsyncBufReadExt, BufReader};

/// Returns the set of eBPF prog_id attached to file descriptors for the specified pid
async fn prog_ids_for_pid(pid: i32) -> io::Result<HashSet<u32>> {
    let mut ids = HashSet::new();
    let fdinfo_dir = format!("/proc/{pid}/fdinfo");

    let mut dir = match fs::read_dir(&fdinfo_dir).await {
        Ok(d) => d,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(ids),
        Err(e) => return Err(e),
    };

    while let Some(entry) = dir.next_entry().await? {
        let path = entry.path();

        let file = match File::open(&path).await {
            Ok(f) => f,
            Err(_) => continue, // fd can disappear, ignore
        };

        let reader = BufReader::new(file);
        let mut lines = reader.lines();

        while let Some(line) = lines.next_line().await? {
            if let Some(rest) = line.strip_prefix("prog_id:")
                && let Ok(id) = rest.trim().parse::<u32>()
            {
                ids.insert(id);
            }
        }
    }

    Ok(ids)
}

pub async fn collect_programs() -> anyhow::Result<()> {
    let (self_exclude, systemd_exclude) =
        tokio::join!(prog_ids_for_pid(std::process::id() as i32), async {
            let comm = match fs::read_to_string("/proc/1/comm").await {
                Ok(c) => c,
                Err(_) => return Ok(HashSet::new()),
            };

            if comm.trim() == "systemd" {
                prog_ids_for_pid(1).await
            } else {
                Ok(HashSet::new())
            }
        },);

    let mut excluded = self_exclude?;
    excluded.extend(systemd_exclude?);

    for info_res in loaded_programs() {
        let info = match info_res {
            Ok(i) => i,

            Err(ProgramError::IOError(ioe)) if ioe.kind() == io::ErrorKind::NotFound => {
                continue;
            }
            Err(ProgramError::SyscallError(se))
                if se.io_error.kind() == io::ErrorKind::NotFound =>
            {
                continue;
            }

            Err(e) => return Err(e.into()),
        };

        let id = info.id();
        if excluded.contains(&id) {
            continue;
        }

        let prog_name = info.name_as_str().unwrap_or("<unknown>");
        let prog_type = match info.program_type() {
            Ok(t) => format!("{:?}", t),
            Err(_) => "<unknown>".to_string(),
        };

        let runtime = info.run_time().as_secs();

        if runtime > 0 {
            let hrs = runtime / 3600;
            let mins = (runtime / 60) % 60;
            log_detection(
                "ebpf_program",
                &format!(
                    "Found ebpf program {} of type {} running for {}h:{}m",
                    prog_name, prog_type, hrs, mins
                ),
                json!({
                    "prog_name": prog_name,
                    "prog_type": prog_type,
                    "runtime_hours": hrs,
                    "runtime_minutes": mins,
                }),
            )
            .await;
        } else {
            log_detection(
                "ebpf_program",
                &format!("Found ebpf program {} of type {}", prog_name, prog_type),
                json!({
                    "prog_name": prog_name,
                    "prog_type": prog_type,
                }),
            )
            .await;
        }
    }

    Ok(())
}

pub async fn check_own_bpf() -> anyhow::Result<()> {
    let ids = prog_ids_for_pid(std::process::id() as i32).await?;
    let num = ids.len();

    if num < 12 {
        log_detection(
            "ebpf_selfcheck",
            &format!("rb2's bpf program ids are missing. Currently at: {}", num),
            Value::Null,
        )
        .await;
    }
    Ok(())
}
