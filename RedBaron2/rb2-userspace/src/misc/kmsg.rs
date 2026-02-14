use super::log::log_detection;
use chrono::{DateTime, Local, SecondsFormat, TimeZone, Utc};
use log::debug;
use serde_json::json;
use std::fmt;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::RawFd;
use std::sync::OnceLock;
use tokio::fs::File;
use tokio::io::AsyncBufReadExt;
use tokio::io::AsyncSeekExt;
use tokio::io::BufReader;
use tokio::io::SeekFrom;

/// checks for a list of things that shouldn't be present in dmesg
fn check_malicious(line: &str) -> bool {
    let list = [
        // kernel/trace/bpf_trace.c
        "is installing a program with bpf_probe_write_user helper that may corrupt user memory!", // works until v6.14 rework
        // kernel/module/main.c
        "taints kernel.",
        "tainting kernel with TAINT_LIVEPATCH",
        "module verification failed: signature and/or required key missing",
    ]; // TODO: this list can be expanded
    list.iter().any(|&s| line.contains(s))
}

static BOOT_US: OnceLock<i64> = OnceLock::new();

fn boot_time_us() -> i64 {
    *BOOT_US.get_or_init(|| unsafe {
        let mut rt = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let mut mono = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };

        if libc::clock_gettime(libc::CLOCK_REALTIME, &mut rt) != 0 {
            return 0;
        }

        if libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut mono) != 0 {
            return 0;
        }

        let rt_us = rt.tv_sec * 1_000_000 + rt.tv_nsec / 1000;
        let mono_us = mono.tv_sec * 1_000_000 + mono.tv_nsec / 1000;

        rt_us - mono_us
    })
}

#[derive(Debug, Clone)]
pub struct KmsgLog {
    kernel_ts_us: u64, // since boot
    msg: String,
}

impl KmsgLog {
    /// Parse a single /dev/kmsg line:
    /// "level,seq,timestamp,flags;message\n"
    pub fn new(line: &str) -> Option<Self> {
        let semicolon = line.find(';')?;
        let prefix = &line[..semicolon];
        let mut parts = prefix.split(',');

        let _level = parts.next()?;
        let _seq = parts.next()?;
        let ts_str = parts.next()?;

        let kernel_ts_us: u64 = ts_str.parse().ok()?;

        let msg = line[semicolon + 1..]
            .trim_end_matches(&['\n', '\r'][..])
            .to_owned();

        Some(Self { kernel_ts_us, msg })
    }

    fn local_datetime(&self) -> DateTime<Local> {
        let boot_us = boot_time_us();

        let msg_us = boot_us.saturating_add(self.kernel_ts_us as i64);

        let secs = msg_us / 1_000_000;
        let nsec = (msg_us % 1_000_000).max(0) * 1_000;

        let dt_utc = Utc
            .timestamp_opt(secs, nsec as u32)
            .single()
            .unwrap_or_else(|| Utc.timestamp_opt(0, 0).unwrap());

        dt_utc.with_timezone(&Local)
    }
}

impl fmt::Display for KmsgLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ts = self
            .local_datetime()
            .to_rfc3339_opts(SecondsFormat::Millis, true);
        write!(f, "[{}] {}", ts, self.msg)
    }
}

pub struct KmsgReader {
    fd: RawFd,
    buf: Vec<u8>,
}

impl KmsgReader {
    pub async fn new() -> io::Result<Self> {
        let fd = unsafe {
            libc::open(
                c"/dev/kmsg".as_ptr() as *const _,
                libc::O_RDONLY | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(KmsgReader {
            fd,
            // CONSOLE_LOG_MAX/LOG_LINE_MAX in kernel/printk/printk.c
            // or PRINTKRB_RECORD_MAX in kernel/printk/internal.h
            // (depending on kernel version)
            buf: vec![0u8; 1024],
        })
    }

    /// Drain all currently available kmsg records and return.
    /// If up to date return
    pub async fn scan(&mut self) -> io::Result<()> {
        loop {
            let n = unsafe {
                libc::read(
                    self.fd,
                    self.buf.as_mut_ptr() as *mut libc::c_void,
                    self.buf.len(),
                )
            };

            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock
                    || err.raw_os_error() == Some(libc::EAGAIN)
                {
                    // No more records
                    return Ok(());
                }
                return Err(err);
            }

            if n == 0 {
                return Ok(());
            }

            let n = n as usize;
            let record = String::from_utf8_lossy(&self.buf[..n]);

            if let Some(log) = KmsgLog::new(record.as_ref()) {
                if check_malicious(&log.msg) {
                    log_detection(
                        "malicious_dmesg",
                        &format!("{}", log),
                        json!({ "line": log.msg }),
                    )
                    .await;
                }
            } else {
                debug!("Malformed kmsg record: {:?}", record);
            }
        }
    }
}

impl Drop for KmsgReader {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

pub struct KernLogReader {
    path: &'static str,
    reader: BufReader<File>,
    pos: u64,
    inode: u64,
    dev: u64,
}

impl KernLogReader {
    pub async fn new() -> io::Result<Self> {
        let path = "/var/log/kern.log";
        let file = File::open(path).await?;
        let meta = file.metadata().await?;

        Ok(Self {
            path,
            reader: BufReader::new(file),
            pos: 0,
            inode: meta.ino(),
            dev: meta.dev(),
        })
    }

    async fn reopen_if_rotated_or_truncated(&mut self) -> io::Result<()> {
        let meta = tokio::fs::metadata(self.path).await?;

        let rotated = meta.ino() != self.inode || meta.dev() != self.dev;
        let truncated = meta.len() < self.pos;

        if rotated || truncated {
            debug!(
                "kern.log changed (rotated={}, truncated={}), reopening",
                rotated, truncated
            );

            let mut file = File::open(self.path).await?;
            let meta = file.metadata().await?;

            // After reopen/truncate, read from start.
            file.seek(SeekFrom::Start(0)).await?;
            self.reader = BufReader::new(file);
            self.pos = 0;
            self.inode = meta.ino();
            self.dev = meta.dev();
        }

        Ok(())
    }

    /// drain all currently available kern.log lines
    pub async fn scan(&mut self) -> io::Result<()> {
        self.reopen_if_rotated_or_truncated().await?;

        self.reader
            .get_mut()
            .seek(SeekFrom::Start(self.pos))
            .await?;

        loop {
            let mut line = String::new();
            let n = self.reader.read_line(&mut line).await?;

            if n == 0 {
                // EOF / no more new lines right now; store real file position.
                self.pos = self.reader.stream_position().await?;
                return Ok(());
            }

            let line = line.trim_end_matches(&['\n', '\r'][..]);
            if check_malicious(line) {
                log_detection("malicious_kernlog", line, json!({ "line": line })).await;
            }
        }
    }
}
