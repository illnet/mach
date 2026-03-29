#[cfg(all(feature = "ebpf", target_os = "linux"))]
pub(crate) mod ebpf;

pub use net::sock::{
    BackendKind, BackendSelection, LureConnection, LureListener, LureNet, backend_kind,
    backend_selection,
};

use crate::inspect::pump_proxy_progress;

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
    let stats = stats?;
    // Record final delta from stats (any remaining bytes not yet reported).
    log::debug!(
        "passthrough completed: session_id={}, c2s_bytes={}, s2c_bytes={}",
        session.id,
        stats.c2s_bytes,
        stats.s2c_bytes
    );
    session.inspect.record_c2s(stats.c2s_bytes);
    session.inspect.record_s2c(stats.s2c_bytes);
    Ok(())
}
