//! Session tracking for TTY recordings using the kernel SID (session ID).
//!
//! Only records the "root" PTY per login session - nested PTYs from sudo/su/screen/tmux
//! are skipped to avoid duplicate recordings.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::PathBuf;

use log::debug;
use uuid::Uuid;

use super::ParsedTtyWrite;
use super::cast_writer::CastSession;
use super::sqlite_store::TtyDb;

/// Describes which storage backend sessions should use.
pub enum StorageBackend {
    /// Write `.cast` / `.cast.age` files under `output_dir`.
    File { output_dir: PathBuf },
    /// Write compressed+encrypted blobs into the SQLite store.
    Sqlite { db: TtyDb },
}

/// An active recording session for a login session.
struct ActiveSession {
    root_tty: (u16, u16),
    cast_session: CastSession,
    event_count: usize,
    uuid: Uuid,
}

/// Tracks TTY sessions and maps them to cast files.
/// Only the first (root) PTY per SID is recorded.
/// Nested PTYs from sudo/su/screen/tmux are skipped.
pub struct SessionTracker {
    backend: StorageBackend,
    pubkey: Option<String>,
    sessions: HashMap<u32, ActiveSession>,
    suppressed_sids: HashSet<u32>,
}

impl SessionTracker {
    pub fn new(backend: StorageBackend, pubkey: Option<String>) -> io::Result<Self> {
        let label = match &backend {
            StorageBackend::File { .. } => "file",
            StorageBackend::Sqlite { .. } => "sqlite",
        };
        if pubkey.is_some() {
            debug!(
                "Session tracker initialized ({label}) with encryption enabled (root PTY only mode)"
            );
        } else {
            debug!("Session tracker initialized ({label}) without encryption (root PTY only mode)");
        }
        Ok(Self {
            backend,
            pubkey,
            sessions: HashMap::new(),
            suppressed_sids: HashSet::new(),
        })
    }

    /// Proper async API: handle an event end-to-end (create session if needed, write data, resize).
    ///
    /// This replaces the old "return &mut CastSession" pattern (which can’t be used correctly with .await).
    pub async fn handle_tty_write(&mut self, ev: &ParsedTtyWrite) -> io::Result<()> {
        let sid = ev.sid;
        let tty = (ev.tty_major, ev.tty_minor);

        // Fast path: already actively recording this SID
        if let Some(active) = self.sessions.get(&sid) {
            if active.root_tty != tty {
                debug!(
                    "Skipping nested PTY {}:{} (root is {}:{})",
                    tty.0, tty.1, active.root_tty.0, active.root_tty.1
                );
                return Ok(());
            }
        } else {
            // Fast path: already determined nested
            if self.suppressed_sids.contains(&sid) {
                return Ok(());
            }

            // SID: check ancestry for nested sessions
            if ancestor_has_tracked_sid(sid, &self.sessions) {
                debug!(
                    "Suppressing nested SID {} on PTY {}:{} (ancestor session already tracked)",
                    sid, tty.0, tty.1
                );
                self.suppressed_sids.insert(sid);
                return Ok(());
            }

            // Genuinely new login session - create recording
            let uuid = Uuid::new_v4();
            debug!(
                "Creating new session {} for root PTY {}:{} (sid={}){}",
                uuid,
                tty.0,
                tty.1,
                sid,
                if self.pubkey.is_some() {
                    " [encrypted]"
                } else {
                    ""
                }
            );

            let cast_session = match &self.backend {
                StorageBackend::File { output_dir } => {
                    CastSession::new_file(
                        output_dir,
                        uuid,
                        ev.rows,
                        ev.cols,
                        ev.ts,
                        self.pubkey.as_deref(),
                    )
                    .await?
                }
                StorageBackend::Sqlite { db } => {
                    CastSession::new_sqlite(
                        db.clone(),
                        uuid,
                        ev.rows,
                        ev.cols,
                        ev.ts,
                        self.pubkey.as_deref(),
                    )
                    .await?
                }
            };

            self.sessions.insert(
                sid,
                ActiveSession {
                    root_tty: tty,
                    cast_session,
                    event_count: 0,
                    uuid,
                },
            );
        }

        // Record into the root session
        let active = self.sessions.get_mut(&sid).unwrap();
        active.event_count += 1;

        // Keep resize events consistent with output
        active
            .cast_session
            .check_resize(ev.ts, ev.rows, ev.cols)
            .await?;
        active
            .cast_session
            .write_output(ev.ts, ev.tty_out.as_slice())
            .await?;

        Ok(())
    }

    /// Flush all active sessions.
    ///
    /// Also cleans up orphan sessions caused by a race condition: when a child
    /// SID (from sudo/su) produces its first tty_write before the parent SID's
    /// session has been created, it gets its own session. By flush time the
    /// parent is tracked, so we re-check low-event-count sessions and remove
    /// any that now have a tracked ancestor.
    pub async fn flush_all(&mut self) -> io::Result<()> {
        // Collect orphan SIDs
        let orphans: Vec<u32> = self
            .sessions
            .iter()
            .filter(|(_, active)| active.event_count <= 3)
            .map(|(sid, _)| *sid)
            .filter(|sid| ancestor_has_tracked_sid(*sid, &self.sessions))
            .collect();

        for sid in orphans {
            if let Some(mut active) = self.sessions.remove(&sid) {
                debug!(
                    "Cleaning up orphan session {} (SID {}, {} events) - ancestor now tracked",
                    active.uuid, sid, active.event_count
                );

                // Ensure buffers are flushed/closed before deleting file
                let _ = active.cast_session.close().await;

                // Delete the orphan file (file backend only)
                if let StorageBackend::File { output_dir } = &self.backend {
                    let ext = if self.pubkey.is_some() {
                        "cast.age"
                    } else {
                        "cast"
                    };
                    let path = output_dir.join(format!("{}.{}", active.uuid, ext));
                    let _ = fs::remove_file(&path);
                }
            }
            self.suppressed_sids.insert(sid);
        }

        for active in self.sessions.values_mut() {
            active.cast_session.flush().await?;
        }
        Ok(())
    }

    /// Flush and close all active sessions (use during graceful shutdown).
    pub async fn close_all(&mut self) -> io::Result<()> {
        for active in self.sessions.values_mut() {
            active.cast_session.close().await?;
        }
        self.sessions.clear();
        self.suppressed_sids.clear();
        Ok(())
    }
}

/// Check whether the session leader for `sid` is a descendant of a process
/// whose SID is already in `sessions`. Walks up parent chain (capped at 8 hops)
/// reading /proc/<pid>/stat.
fn ancestor_has_tracked_sid(sid: u32, sessions: &HashMap<u32, ActiveSession>) -> bool {
    // Start from the session leader's parent
    let mut pid = match read_proc_ids(sid) {
        Some((ppid, _)) if ppid > 1 => ppid,
        _ => return false,
    };
    for _ in 0..8 {
        let (ppid, ancestor_sid) = match read_proc_ids(pid) {
            Some((pp, s)) => (pp, s),
            None => return false,
        };
        if sessions.contains_key(&ancestor_sid) {
            return true;
        }
        if ppid <= 1 {
            return false;
        }
        pid = ppid;
    }
    false
}

/// Read the PPID and SID of `pid` from /proc/<pid>/stat.
///
/// /proc/<pid>/stat format: `pid (comm) state ppid pgrp session ...`
fn read_proc_ids(pid: u32) -> Option<(u32, u32)> {
    let data = fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    let rest = data.rsplit_once(')')?.1;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // After ')': state(0) ppid(1) pgrp(2) session(3) ...
    let ppid = fields.get(1)?.parse::<u32>().ok()?;
    let session = fields.get(3)?.parse::<u32>().ok()?;
    Some((ppid, session))
}
