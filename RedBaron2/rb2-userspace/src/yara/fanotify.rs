use crate::config::yaml::YaraConfig;
use crate::yara::helper::handle_yara_path_match;
use crate::yara::yara_scan::CHUNK_SIZE_BYTES;
use lru::LruCache;
use nix::fcntl::AT_FDCWD;
use nix::sys::fanotify::{
    EventFFlags, Fanotify, FanotifyResponse, InitFlags, MarkFlags, MaskFlags, Response,
};
use nix::sys::stat::fstat;
use nix::unistd::{Whence, lseek, read};
use std::collections::HashSet;
use std::num::NonZeroUsize;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::sync::atomic::Ordering;
use yara_x::{Rules, ScanResults, blocks::Scanner};

#[derive(Clone)]
struct CacheEntry {
    is_safe: bool,
    rule_names: Vec<String>,
}

fn fd_to_path(fd: &BorrowedFd) -> String {
    let p = format!("/proc/self/fd/{}", fd.as_raw_fd());
    std::fs::read_link(&p)
        .map(|x| x.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "<unknown>".to_string())
}

fn read_to_fill(fd: &BorrowedFd, buf: &mut [u8]) -> usize {
    let mut read_index = 0;
    while read_index < buf.len() {
        match read(fd, &mut buf[read_index..]) {
            Ok(0) | Err(_) => break,
            Ok(bytes_read) => read_index += bytes_read,
        };
    }
    read_index
}

fn yara_scan_fd<'a>(
    fd: &BorrowedFd,
    scanner: &'a mut Scanner,
    buf: &mut Vec<u8>,
) -> anyhow::Result<ScanResults<'a, 'a>> {
    buf.resize(CHUNK_SIZE_BYTES.load(Ordering::Relaxed), 0);
    lseek(fd, 0, Whence::SeekSet)?;

    let mut offset = 0;
    loop {
        let read_len = read_to_fill(fd, buf);
        if read_len == 0 {
            break;
        }
        scanner.scan(offset, &buf[0..read_len])?;
        offset += read_len;
    }
    Ok(scanner.finish()?)
}

fn read_all_fd(fd: &BorrowedFd) -> anyhow::Result<Vec<u8>> {
    lseek(fd, 0, Whence::SeekSet)?;
    let mut out = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        match read(fd, &mut tmp) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&tmp[..n]),
            Err(e) => return Err(anyhow::anyhow!("read_all_fd: {}", e)),
        }
    }
    Ok(out)
}

pub fn yara_init_fanotify_scan(cfg: &YaraConfig, rules: &Rules) -> anyhow::Result<()> {
    let fd = Fanotify::init(
        InitFlags::FAN_CLOEXEC | InitFlags::FAN_CLASS_CONTENT,
        EventFFlags::O_RDONLY | EventFFlags::O_LARGEFILE,
    )?;

    fd.mark(
        MarkFlags::FAN_MARK_FILESYSTEM | MarkFlags::FAN_MARK_ADD,
        MaskFlags::FAN_OPEN_EXEC_PERM,
        AT_FDCWD,
        Some("/"),
    )?;

    let mut buf = vec![0u8; CHUNK_SIZE_BYTES.load(Ordering::Relaxed)];
    let mut cache = LruCache::new(NonZeroUsize::new(512).unwrap());
    let mut scanner = Scanner::new(rules);
    let disabled_rules: HashSet<String> = cfg.disabled_rules.iter().cloned().collect();

    while let Ok(events) = Fanotify::read_events(&fd) {
        for event in events {
            let Some(event_fd) = event.fd() else {
                continue;
            };

            let original_path = fd_to_path(&event_fd);
            let response;

            'scan: {
                let Ok(stat) = fstat(event_fd) else {
                    response = Response::FAN_ALLOW;
                    break 'scan;
                };

                let entry = match cache.get(&stat).cloned() {
                    Some(e) => e,
                    None => {
                        let Ok(results) = yara_scan_fd(&event_fd, &mut scanner, &mut buf) else {
                            response = Response::FAN_ALLOW;
                            break 'scan;
                        };

                        let rule_names: Vec<String> = results
                            .matching_rules()
                            .filter(|rule| !disabled_rules.contains(rule.identifier()))
                            .map(|r| r.identifier().to_string())
                            .collect();

                        let is_safe = rule_names.is_empty();
                        let e = CacheEntry {
                            is_safe,
                            rule_names,
                        };
                        cache.put(stat, e.clone());
                        e
                    }
                };

                if !entry.is_safe {
                    handle_yara_path_match(
                        None,
                        &original_path,
                        &entry.rule_names,
                        &cfg.actions,
                        &cfg.samples_dir,
                        "deny_exec",
                        || read_all_fd(&event_fd),
                    );

                    // enforcement only when actions.kill is enabled
                    if cfg.actions.kill {
                        response = Response::FAN_DENY;
                    } else {
                        response = Response::FAN_ALLOW;
                    }
                } else {
                    response = Response::FAN_ALLOW;
                }
            }

            fd.write_response(FanotifyResponse::new(event_fd, response))
                .ok();
        }
    }

    Ok(())
}
