use log::warn;
use std::path::Path;
use std::sync::RwLock;
use std::time::{Duration, Instant};
use std::{fs, sync::OnceLock};
use uuid::Uuid;

static HOSTNAME_CACHE: OnceLock<RwLock<Option<(String, Instant)>>> = OnceLock::new();
const HOSTNAME_CACHE_TTL: Duration = Duration::from_secs(60);

fn read_hostname_file() -> Option<String> {
    for p in ["/etc/hostname", "/proc/sys/kernel/hostname"] {
        if let Ok(s) = fs::read_to_string(p) {
            let t = s.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }
    None
}

fn get_hostname_cache() -> &'static RwLock<Option<(String, Instant)>> {
    HOSTNAME_CACHE.get_or_init(|| RwLock::new(None))
}

/// Returns a cached hostname with the staleness window to refetch
pub fn get_hostname() -> Option<String> {
    {
        let cache = get_hostname_cache().read().unwrap();
        if let Some((val, ts)) = cache.as_ref()
            && ts.elapsed() < HOSTNAME_CACHE_TTL
        {
            return Some(val.clone());
        }
    }

    if let Some(fresh) = read_hostname_file() {
        let mut cache = get_hostname_cache().write().unwrap();
        *cache = Some((fresh.clone(), Instant::now()));
        return Some(fresh);
    }

    None
}

static HOST_ID: OnceLock<String> = OnceLock::new();
const HOST_ID_PATH: &str = "/var/lib/rb2/host_id";

/// Reads or creates a persistent host-id (UUID v4) at `/var/lib/rb2/host_id`.
///
/// On first boot the file won't exist, so we generate a fresh UUID v4,
/// write it to disk, and return it.  On subsequent runs the existing
/// value is read back so the id is stable across rb2 restarts.
///
/// The result is cached in-process via `OnceLock` so the file is only
/// touched once per process lifetime.
pub fn get_machine_id() -> Option<String> {
    Some(
        HOST_ID
            .get_or_init(|| {
                // Try to read an existing host_id from disk
                if let Ok(contents) = fs::read_to_string(HOST_ID_PATH) {
                    let trimmed = contents.trim().to_string();
                    if !trimmed.is_empty() {
                        return trimmed;
                    }
                }

                // Generate a new UUID v4
                let id = Uuid::new_v4().to_string();

                // Ensure parent directory exists
                let parent = Path::new(HOST_ID_PATH).parent().unwrap();
                if let Err(e) = fs::create_dir_all(parent) {
                    warn!("Failed to create {}: {e}", parent.display());
                    return id;
                }

                // Persist to disk so it survives restarts
                if let Err(e) = fs::write(HOST_ID_PATH, &id) {
                    warn!("Failed to write {HOST_ID_PATH}: {e}");
                }

                id
            })
            .clone(),
    )
}
