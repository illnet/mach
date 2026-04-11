use std::time::Duration;

use anyhow::Context;
use lure::{config::LureConfig, proxy::Lure, sock, utils::leak};
use tokio::sync::oneshot;

fn main() -> anyhow::Result<()> {
    env_logger::init();

    let backend = sock::backend_selection();
    println!("backend: {:?} ({})", backend.kind, backend.reason);

    match backend.kind {
        sock::BackendKind::Uring => net::sock::uring::start(async {
            let local = tokio::task::LocalSet::new();
            local.run_until(run()).await
        }),
        sock::BackendKind::Epoll | sock::BackendKind::Tokio => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let local = tokio::task::LocalSet::new();
            rt.block_on(local.run_until(run()))
        }
    }
}

async fn run() -> anyhow::Result<()> {
    // Create Lure with a dummy config.
    let config = LureConfig {
        inst: "inspect_test".to_string(),
        bind: "127.0.0.1:0".to_string(),
        route: vec![],
        ..Default::default()
    };

    let lure = leak(Lure::new(config));
    lure.sync_routes_from_config().await?;
    lure.sync_tunnel_tokens_from_config().await?;

    // Start Lure.
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (ready_tx, ready_rx) = oneshot::channel();
    let server = tokio::task::spawn_local(async move {
        lure.start_with_shutdown(Some(ready_tx), shutdown_rx).await
    });

    // Wait for bind.
    let lure_addr = tokio::time::timeout(Duration::from_secs(2), ready_rx)
        .await
        .context("timeout waiting for lure bind")??;

    println!("lure started at {}", lure_addr);
    println!();

    // Call inspect_stats() a few times to verify it works.
    for i in 1..=5 {
        let stats = lure.inspect_stats().await;
        println!(
            "Call #{}: instance={}, tenants={}, routes={}, sessions={}",
            i,
            stats.instance.inst,
            stats.tenants.len(),
            stats.routes.len(),
            stats.sessions.len()
        );
        println!(
            "  instance traffic: c2s_bytes={}, s2c_bytes={}, c2s_chunks={}, s2c_chunks={}",
            stats.instance.traffic.c2s_bytes,
            stats.instance.traffic.s2c_bytes,
            stats.instance.traffic.c2s_chunks,
            stats.instance.traffic.s2c_chunks
        );

        if i < 5 {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    println!();
    println!("✓ inspect_stats() works correctly");

    // Shutdown.
    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;

    Ok(())
}
