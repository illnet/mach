use std::cell::UnsafeCell;

use async_trait::async_trait;

use crate::rpc::{EventEnvelope, EventServiceInstance, event::EventHook};

pub mod logging;

#[cfg(feature = "mimalloc")]
mod mimalloc {
    use mimalloc::MiMalloc;

    #[global_allocator]
    static GLOBAL: MiMalloc = MiMalloc;
}

pub struct OwnedStatic<T: 'static>(&'static T);

impl<T> From<&'static T> for OwnedStatic<T> {
    fn from(value: &'static T) -> Self {
        Self(value)
    }
}

#[async_trait]
impl<H: EventHook<EventEnvelope, EventEnvelope> + Send + Sync>
    EventHook<EventEnvelope, EventEnvelope> for OwnedStatic<H>
{
    async fn on_handshake(&self) -> Option<EventEnvelope> {
        self.0.on_handshake().await
    }

    async fn on_event(
        &self,
        inst: &EventServiceInstance,
        event: &'_ EventEnvelope,
    ) -> anyhow::Result<()> {
        self.0.on_event(inst, event).await?;
        Ok(())
    }
}

pub fn leak<T>(inner: T) -> &'static T {
    Box::leak(Box::new(inner))
}

pub fn spawn_named<F>(
    name: &str,
    future: F,
) -> Result<tokio::task::JoinHandle<F::Output>, std::io::Error>
where
    F: Future + 'static,
    F::Output: 'static,
{
    tokio::task::Builder::new().name(name).spawn_local(future)
}

#[derive(Default, Debug)]
/// Warning: This implementation only assumes that single sync-inc
pub struct UnsafeCounterU64 {
    v: UnsafeCell<u64>,
}

// single-writer, multi-reader-by-convention
unsafe impl Sync for UnsafeCounterU64 {}

impl UnsafeCounterU64 {
    pub fn inc(&self, rhs: u64) {
        unsafe {
            *self.v.get() += rhs;
        }
    }

    pub fn add(&self, rhs: u64) -> u64 {
        unsafe {
            let old = *self.v.get();
            *self.v.get() = old.wrapping_add(rhs);
            old
        }
    }

    pub fn sub(&self, rhs: u64) -> u64 {
        unsafe {
            let old = *self.v.get();
            *self.v.get() = old.wrapping_sub(rhs);
            old
        }
    }

    pub fn store(&self, value: u64) {
        unsafe {
            *self.v.get() = value;
        }
    }

    pub fn swap(&self, value: u64) -> u64 {
        unsafe {
            let old = *self.v.get();
            *self.v.get() = value;
            old
        }
    }

    pub fn load(&self) -> u64 {
        unsafe { *self.v.get() }
    }
}

/// Extract raw JSON string bytes from a framed Status Response packet.
pub fn extract_status_json(packet: &[u8]) -> Option<&[u8]> {
    if packet.is_empty() {
        return None;
    }
    let mut pos = 1;
    let mut len: usize = 0;
    let mut shift = 0;

    loop {
        if pos >= packet.len() {
            return None;
        }
        let byte = packet[pos];
        pos += 1;
        len |= ((byte & 0x7F) as usize) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 32 {
            return None;
        }
    }

    if pos + len > packet.len() {
        return None;
    }
    Some(&packet[pos..pos + len])
}

#[cfg(test)]
mod tests {
    use super::extract_status_json;

    #[test]
    fn parses_status_json_with_payload() {
        let packet = [0x00, 0x02, b'a', b'b'];
        assert_eq!(extract_status_json(&packet), Some(&b"ab"[..]));
    }

    #[test]
    fn parses_status_json_with_empty_payload() {
        let packet = [0x00, 0x00];
        assert_eq!(extract_status_json(&packet), Some(&b""[..]));
    }

    #[test]
    fn parses_status_json_with_multibyte_length() {
        let mut packet = vec![0x00, 0x80, 0x01];
        packet.extend(vec![b'a'; 128]);
        assert_eq!(extract_status_json(&packet), Some(&packet[3..]));
    }

    #[test]
    fn returns_none_for_truncated_status_json() {
        let packet = [0x00, 0x05, b'a', b'b'];
        assert_eq!(extract_status_json(&packet), None);
    }

    #[test]
    fn returns_none_for_empty_packet() {
        assert_eq!(extract_status_json(&[]), None);
    }
}
