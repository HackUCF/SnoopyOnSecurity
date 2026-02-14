use crate::firewall::sockets::kill_pid;
use crate::firewall::{FirewallEvent, Handler};
use async_trait::async_trait;
use std::io;
use std::sync::atomic::{AtomicI32, Ordering};

pub struct KillFirewall {
    last_kill_pid: AtomicI32, // -1 means "none"
}

impl Default for KillFirewall {
    fn default() -> Self {
        Self {
            last_kill_pid: AtomicI32::new(-1),
        }
    }
}

#[async_trait]
impl Handler for KillFirewall {
    async fn run(&self) -> anyhow::Result<()> {
        Ok(())
    }

    async fn handle_event(&self, ev: &FirewallEvent, dec: bool) -> anyhow::Result<()> {
        if dec {
            return Ok(());
        }

        let prev = self.last_kill_pid.swap(ev.pid, Ordering::Relaxed);

        match kill_pid(ev.pid) {
            Ok(()) => Ok(()),

            Err(e) if e.kind() == io::ErrorKind::NotFound || e.raw_os_error() == Some(3) => {
                // suppress if we tried to kill the same pid
                if prev == ev.pid {
                    Ok(())
                } else {
                    Err(anyhow::Error::from(e))
                }
            }

            Err(e) => Err(anyhow::Error::from(e)),
        }
    }
}
