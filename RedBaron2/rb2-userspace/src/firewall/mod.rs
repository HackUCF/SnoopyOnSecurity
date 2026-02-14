pub mod dispatcher;
mod event;
mod handler;
pub mod sockets;

use self::event::nfq::NfqEventProducer;
use crate::firewall::event::ebpf::EbpfEventProducer;
use crate::firewall::handler::kill::KillFirewall;
use crate::firewall::handler::nfq::NfqFirewall;
use async_trait::async_trait;
use tokio::sync::mpsc;

#[derive(Debug, Clone, PartialEq)]
pub struct FirewallEvent {
    pub pid: i32,
    pub comm: Option<String>,
    pub dport: Option<u16>,
    pub ip: Option<String>,
    pub op: Option<String>,
}

#[async_trait]
pub trait Handler: Send + Sync {
    async fn run(&self) -> anyhow::Result<()>;

    async fn handle_event(&self, ev: &FirewallEvent, dec: bool) -> anyhow::Result<()>;
}

#[async_trait]
pub trait EventProducer: Send + Sync {
    async fn run(&self, tx: mpsc::Sender<FirewallEvent>) -> anyhow::Result<()>;
}

pub enum HandlerImpl {
    Nfq(NfqFirewall),
    Kill(KillFirewall),
}

#[async_trait]
impl Handler for HandlerImpl {
    async fn run(&self) -> anyhow::Result<()> {
        match self {
            HandlerImpl::Nfq(inner) => inner.run().await,
            HandlerImpl::Kill(inner) => inner.run().await,
        }
    }

    async fn handle_event(&self, ev: &FirewallEvent, dec: bool) -> anyhow::Result<()> {
        match self {
            HandlerImpl::Nfq(inner) => inner.handle_event(ev, dec).await,
            HandlerImpl::Kill(inner) => inner.handle_event(ev, dec).await,
        }
    }
}

pub enum EventProducerImpl {
    Ebpf(EbpfEventProducer),
    Nfq(NfqEventProducer),
}

#[async_trait]
impl EventProducer for EventProducerImpl {
    async fn run(&self, tx: mpsc::Sender<FirewallEvent>) -> anyhow::Result<()> {
        match self {
            EventProducerImpl::Ebpf(inner) => inner.run(tx).await,
            EventProducerImpl::Nfq(inner) => inner.run(tx).await,
        }
    }
}
