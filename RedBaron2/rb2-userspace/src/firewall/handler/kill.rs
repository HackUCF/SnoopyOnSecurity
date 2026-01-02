use crate::firewall::common::{FirewallEvent, Handler};
use crate::firewall::sockets::kill_pid;
use async_trait::async_trait;

// last resort whackamole

pub struct KillFirewall {}

#[async_trait]
impl Handler for KillFirewall {
    async fn run(&self) -> anyhow::Result<()> {
        Ok(())
    }

    async fn handle_event(&self, ev: &FirewallEvent, dec: bool) -> anyhow::Result<()> {
        match dec {
            true => Ok(()),
            false => kill_pid(ev.pid.into()).map_err(anyhow::Error::from),
        }
    }
}
