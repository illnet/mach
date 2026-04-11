use async_trait::async_trait;
use log::{debug, info};
use serde::{Deserialize, Serialize};

use crate::rpc::{EventEnvelope, EventServiceInstance, event::EventHook};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct EventIdent {
    pub(crate) id: String,
    pub(crate) is_master: bool,
}

#[async_trait]
impl EventHook<EventEnvelope, EventEnvelope> for EventIdent {
    async fn on_handshake(&self) -> Option<EventEnvelope> {
        Some(EventEnvelope::HandshakeIdent(self.clone()))
    }

    async fn on_event(
        &self,
        _: &EventServiceInstance,
        event: &'_ EventEnvelope,
    ) -> anyhow::Result<()> {
        #[cfg(debug_assertions)]
        {
            debug!("RPC-S2C: {event:?}");
        }
        if let EventEnvelope::Hello(_) = event {
            info!("RPC: Hello");
        }
        Ok(())
    }
}
