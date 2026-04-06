use std::sync::atomic::Ordering;

pub use net::sock::{
    BackendKind, BackendSelection, LureConnection, LureListener, LureNet, backend_kind,
    backend_selection,
};

use crate::{inspect::pump_proxy_progress, logging::LureLogger};

/// Start bidirectional passthrough between `client` and `server`, driving
/// live OTEL metrics from [`net::ProxyHandle::progress`].
pub(crate) async fn passthrough_now(
    client: LureConnection,
    server: LureConnection,
    session: &crate::router::Session,
) -> anyhow::Result<()> {
    let handle = client.into_proxy(server)?;
    let inspect = session.inspect.clone();
    let (metrics_shutdown_tx, metrics_shutdown_rx) = tokio::sync::watch::channel(false);
    let metrics_task = tokio::spawn(async move {
        pump_proxy_progress(inspect, handle.progress, metrics_shutdown_rx).await
    });
    let stats = handle.future.await;
    let _ = metrics_shutdown_tx.send(true);
    let _ = metrics_task.await;
    let stats = match stats {
        Ok(stats) => stats,
        Err(err) => {
            LureLogger::passthrough_unexpected_termination(
                session.id,
                &session.client_addr,
                &session.destination_addr,
                session.inspect.tunnel.load(Ordering::Relaxed),
                &err,
            );
            return Err(err.into());
        }
    };
    // Reconcile any remaining bytes not yet reported by the pump.
    // The pump has already recorded bytes continuously via record_proxy_progress_delta.
    // Here we record only the delta (bytes the pump may have missed in the final window).
    log::debug!(
        "passthrough completed: session_id={}, c2s_bytes={}, s2c_bytes={}",
        session.id,
        stats.c2s_bytes,
        stats.s2c_bytes
    );

    let already_c2s = session.inspect.traffic.c2s_bytes();
    let already_s2c = session.inspect.traffic.s2c_bytes();
    let leftover_c2s = stats.c2s_bytes.saturating_sub(already_c2s);
    let leftover_s2c = stats.s2c_bytes.saturating_sub(already_s2c);

    if leftover_c2s > 0 {
        session.inspect.record_c2s_delta(leftover_c2s, 0);
        session.inspect.route.record_c2s(leftover_c2s, 0);
        session.inspect.tenant.record_c2s(leftover_c2s, 0);
        session.inspect.instance.record_c2s(leftover_c2s, 0);
        crate::inspect::GLOBAL_C2S_BYTES.fetch_add(leftover_c2s, Ordering::Relaxed);
    }
    if leftover_s2c > 0 {
        session.inspect.record_s2c_delta(leftover_s2c, 0);
        session.inspect.route.record_s2c(leftover_s2c, 0);
        session.inspect.tenant.record_s2c(leftover_s2c, 0);
        session.inspect.instance.record_s2c(leftover_s2c, 0);
        crate::inspect::GLOBAL_S2C_BYTES.fetch_add(leftover_s2c, Ordering::Relaxed);
    }

    Ok(())
}
