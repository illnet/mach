use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use net::{ProxyProgress, ProxyStats};
use opentelemetry::{KeyValue, metrics::Counter};

use crate::{
    router::{RouterInstance, inspect::SessionInspectState},
    telemetry::{
        EventEnvelope, EventServiceInstance,
        event::EventHook,
        get_meter,
        inspect::{InspectRequest, ListSessionsResponse, ListStatsResponse},
    },
};

pub static GLOBAL_C2S_BYTES: AtomicU64 = AtomicU64::new(0);
pub static GLOBAL_S2C_BYTES: AtomicU64 = AtomicU64::new(0);
static GLOBAL_C2S_CHUNKS: AtomicU64 = AtomicU64::new(0);
static GLOBAL_S2C_CHUNKS: AtomicU64 = AtomicU64::new(0);

pub(crate) fn transport_volume_counter() -> Counter<u64> {
    get_meter()
        .u64_counter("lure_proxy_transport_volume")
        .with_unit("By")
        .build()
}

pub(crate) fn transport_packet_counter() -> Counter<u64> {
    get_meter()
        .u64_counter("lure_proxy_transport_packet")
        .with_unit("{packet}")
        .build()
}

pub(crate) fn transport_counters() -> (Counter<u64>, Counter<u64>) {
    (transport_volume_counter(), transport_packet_counter())
}

fn record_proxy_progress_delta(
    inspect: &SessionInspectState,
    volume_record: &Counter<u64>,
    packet_record: &Counter<u64>,
    c2st: &KeyValue,
    s2ct: &KeyValue,
    last: &mut ProxyStats,
    snap: ProxyStats,
) {
    let dc2s_bytes = snap.c2s_bytes.saturating_sub(last.c2s_bytes);
    let ds2c_bytes = snap.s2c_bytes.saturating_sub(last.s2c_bytes);
    let dc2s_chunks = snap.c2s_chunks.saturating_sub(last.c2s_chunks);
    let ds2c_chunks = snap.s2c_chunks.saturating_sub(last.s2c_chunks);

    if dc2s_bytes > 0 || ds2c_bytes > 0 || dc2s_chunks > 0 || ds2c_chunks > 0 {
        log::debug!(
            "record_proxy_progress_delta: session_id={}, dc2s_bytes={}, ds2c_bytes={}, dc2s_chunks={}, ds2c_chunks={}",
            inspect.id,
            dc2s_bytes,
            ds2c_bytes,
            dc2s_chunks,
            ds2c_chunks
        );
        volume_record.add(dc2s_bytes, core::slice::from_ref(c2st));
        volume_record.add(ds2c_bytes, core::slice::from_ref(s2ct));
        packet_record.add(dc2s_chunks, core::slice::from_ref(c2st));
        packet_record.add(ds2c_chunks, core::slice::from_ref(s2ct));
        inspect.route.record_c2s(dc2s_bytes, dc2s_chunks);
        inspect.route.record_s2c(ds2c_bytes, ds2c_chunks);
        inspect.tenant.record_c2s(dc2s_bytes, dc2s_chunks);
        inspect.tenant.record_s2c(ds2c_bytes, ds2c_chunks);
        inspect.instance.record_c2s(dc2s_bytes, dc2s_chunks);
        inspect.instance.record_s2c(ds2c_bytes, ds2c_chunks);
        // Update session-level traffic so inspect_sessions() shows live stats
        inspect.record_c2s_delta(dc2s_bytes, dc2s_chunks);
        inspect.record_s2c_delta(ds2c_bytes, ds2c_chunks);
        // Update global counters for minute-level reporting
        GLOBAL_C2S_BYTES.fetch_add(dc2s_bytes, Ordering::Relaxed);
        GLOBAL_S2C_BYTES.fetch_add(ds2c_bytes, Ordering::Relaxed);
        GLOBAL_C2S_CHUNKS.fetch_add(dc2s_chunks, Ordering::Relaxed);
        GLOBAL_S2C_CHUNKS.fetch_add(ds2c_chunks, Ordering::Relaxed);
    }

    *last = snap;
}

/// Get and reset global traffic counters (client-to-server bytes, server-to-client bytes, packets).
pub fn take_global_traffic_snapshot() -> (u64, u64, u64, u64) {
    let c2s_bytes = GLOBAL_C2S_BYTES.swap(0, Ordering::Relaxed);
    let s2c_bytes = GLOBAL_S2C_BYTES.swap(0, Ordering::Relaxed);
    let c2s_chunks = GLOBAL_C2S_CHUNKS.swap(0, Ordering::Relaxed);
    let s2c_chunks = GLOBAL_S2C_CHUNKS.swap(0, Ordering::Relaxed);
    (c2s_bytes, s2c_bytes, c2s_chunks, s2c_chunks)
}

/// Poll [`ProxyProgress`] every 100 ms and push byte/chunk deltas to OTEL
/// counters and persistent route/tenant/instance/session-level stats.
///
/// Run this concurrently with a proxy future and signal shutdown when the
/// proxy completes. Session-level `inspect.traffic` is updated here continuously.
/// After the proxy finishes, reconcile any remaining bytes via the final
/// [`net::ProxyStats`] totals.
pub(crate) async fn pump_proxy_progress(
    inspect: Arc<crate::router::inspect::SessionInspectState>,
    progress: Arc<ProxyProgress>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_millis(100));
    let (volume_record, packet_record) = transport_counters();
    let s2ct = KeyValue::new("intent", "s2c");
    let c2st = KeyValue::new("intent", "c2s");
    let mut last = ProxyStats::default();
    let mut tick_count = 0u64;
    loop {
        tokio::select! {
            _ = interval.tick() => {
                tick_count += 1;
                let snap = progress.snapshot();
                if snap.c2s_bytes > 0 || snap.s2c_bytes > 0 {
                    log::debug!(
                        "pump_proxy_progress tick {}: session_id={}, snap: c2s_bytes={}, s2c_bytes={}, c2s_chunks={}, s2c_chunks={}",
                        tick_count, inspect.id, snap.c2s_bytes, snap.s2c_bytes, snap.c2s_chunks, snap.s2c_chunks
                    );
                }
                record_proxy_progress_delta(
                    inspect.as_ref(),
                    &volume_record,
                    &packet_record,
                    &c2st,
                    &s2ct,
                    &mut last,
                    snap,
                );
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    let snap = progress.snapshot();
                    log::debug!(
                        "pump_proxy_progress shutdown: session_id={}, final snap: c2s_bytes={}, s2c_bytes={}, c2s_chunks={}, s2c_chunks={}",
                        inspect.id, snap.c2s_bytes, snap.s2c_bytes, snap.c2s_chunks, snap.s2c_chunks
                    );
                    record_proxy_progress_delta(
                        inspect.as_ref(),
                        &volume_record,
                        &packet_record,
                        &c2st,
                        &s2ct,
                        &mut last,
                        snap,
                    );
                    return;
                }
            }
        }
    }
}

pub(crate) async fn drive_transport_metrics<F>(
    inspect: Arc<SessionInspectState>,
    mut should_stop: F,
) where
    F: FnMut() -> bool,
{
    let mut interval = tokio::time::interval(Duration::from_millis(100));
    let (volume_record, packet_record) = transport_counters();

    let s2ct = KeyValue::new("intent", "s2c");
    let c2st = KeyValue::new("intent", "c2s");

    let mut last = inspect.traffic.snapshot();

    loop {
        if should_stop() {
            break;
        }

        let snap = inspect.traffic.snapshot();

        let delta_c2s_bytes = snap.c2s_bytes - last.c2s_bytes;
        let delta_s2c_bytes = snap.s2c_bytes - last.s2c_bytes;
        let delta_c2s_chunks = snap.c2s_chunks - last.c2s_chunks;
        let delta_s2c_chunks = snap.s2c_chunks - last.s2c_chunks;

        volume_record.add(delta_c2s_bytes, core::slice::from_ref(&c2st));
        volume_record.add(delta_s2c_bytes, core::slice::from_ref(&s2ct));
        packet_record.add(delta_c2s_chunks, core::slice::from_ref(&c2st));
        packet_record.add(delta_s2c_chunks, core::slice::from_ref(&s2ct));

        inspect.route.record_c2s(delta_c2s_bytes, delta_c2s_chunks);
        inspect.route.record_s2c(delta_s2c_bytes, delta_s2c_chunks);
        inspect.tenant.record_c2s(delta_c2s_bytes, delta_c2s_chunks);
        inspect.tenant.record_s2c(delta_s2c_bytes, delta_s2c_chunks);
        inspect
            .instance
            .record_c2s(delta_c2s_bytes, delta_c2s_chunks);
        inspect
            .instance
            .record_s2c(delta_s2c_bytes, delta_s2c_chunks);

        last = snap;

        interval.tick().await;
    }
}

pub(crate) struct InspectHook {
    router: &'static RouterInstance,
}

impl InspectHook {
    pub(crate) const fn new(router: &'static RouterInstance) -> Self {
        Self { router }
    }

    async fn handle_list_sessions(
        &self,
        service: &EventServiceInstance,
        req: &InspectRequest,
    ) -> anyhow::Result<()> {
        let sessions = self.router.inspect_sessions().await;
        service
            .produce_event(EventEnvelope::ListSessionsResponse(ListSessionsResponse {
                req: req.req,
                _v: sessions,
            }))
            .await?;
        Ok(())
    }

    async fn handle_list_stats(
        &self,
        service: &EventServiceInstance,
        req: &InspectRequest,
    ) -> anyhow::Result<()> {
        let stats = self.router.inspect_stats().await;
        service
            .produce_event(EventEnvelope::ListStatsResponse(ListStatsResponse {
                req: req.req,
                instance: stats.instance,
                tenants: stats.tenants,
                routes: stats.routes,
                sessions: stats.sessions,
            }))
            .await?;
        Ok(())
    }
}

#[async_trait]
impl EventHook<EventEnvelope, EventEnvelope> for InspectHook {
    async fn on_event(
        &self,
        service: &EventServiceInstance,
        event: &'_ EventEnvelope,
    ) -> anyhow::Result<()> {
        match event {
            EventEnvelope::ListSessionsRequest(req) => {
                self.handle_list_sessions(service, req).await
            }
            EventEnvelope::ListStatsRequest(req) => self.handle_list_stats(service, req).await,
            _ => Ok(()),
        }
    }
}
