use std::{
    env,
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::Context;
use lure::{
    config::{LureConfig, RouteConfig},
    lure::Lure,
    sock,
    utils::leak,
};
use tokio::sync::oneshot;

const DEFAULT_DURATION_SECS: u64 = 15;
const CHUNK_SIZE: usize = 64 * 1024;

fn main() -> anyhow::Result<()> {
    env_logger::init();

    let mut duration = Duration::from_secs(DEFAULT_DURATION_SECS);
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--duration" => {
                let v = args.next().context("--duration requires a value")?;
                duration = Duration::from_secs(v.parse()?);
            }
            "--help" | "-h" => {
                println!("epoll_stat_probe options:");
                println!("  --duration <secs>  (default {DEFAULT_DURATION_SECS})");
                println!();
                println!("what it does:");
                println!("  - starts a raw TCP echo server (no Minecraft protocol)");
                println!("  - creates an in-process Lure with epoll backend (LURE_IO_EPOLL=1)");
                println!("  - drives continuous 64KB-chunk load through the proxy");
                println!("  - every second: prints instance, route, and session stats");
                println!(
                    "  - highlights Bug 1: session traffic should be live (not 0) during proxy"
                );
                std::process::exit(0);
            }
            other => return Err(anyhow::anyhow!("unknown arg: {other}")),
        }
    }

    let backend = sock::backend_selection();
    println!("backend: {:?} ({})", backend.kind, backend.reason);
    println!("duration: {}s", duration.as_secs());
    println!();

    match backend.kind {
        sock::BackendKind::Uring => net::sock::uring::start(async move {
            let local = tokio::task::LocalSet::new();
            local.run_until(run(duration)).await
        }),
        sock::BackendKind::Epoll | sock::BackendKind::Tokio => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let local = tokio::task::LocalSet::new();
            rt.block_on(local.run_until(run(duration)))
        }
    }
}

async fn run(duration: Duration) -> anyhow::Result<()> {
    // Start a raw TCP echo server.
    let echo = RawEchoServer::start()?;
    println!("echo server at {}", echo.addr);

    // Create Lure instance.
    let config = LureConfig {
        inst: "epoll_stat_probe".to_string(),
        bind: "127.0.0.1:0".to_string(),
        route: vec![RouteConfig {
            matcher: Some("probe.local".to_string()),
            matchers: vec![],
            endpoint: Some(echo.addr.to_string()),
            endpoints: vec![],
            priority: 0,
            flags: None,
            tunnel_token: None,
            ..Default::default()
        }],
        ..Default::default()
    };

    let lure = leak(Lure::new(config.clone()));
    lure.sync_routes_from_config().await?;
    lure.sync_tunnel_tokens_from_config().await?;

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (ready_tx, ready_rx) = oneshot::channel();
    let server = tokio::task::spawn_local(async move {
        lure.start_with_shutdown(Some(ready_tx), shutdown_rx).await
    });
    let lure_addr = tokio::time::timeout(Duration::from_secs(2), ready_rx)
        .await
        .context("timeout waiting for lure bind")??;

    println!("lure at {}", lure_addr);
    println!();

    // Spawn load thread.
    let deadline = Instant::now() + duration;
    let (load_tx, load_rx) = std::sync::mpsc::channel::<Result<(), anyhow::Error>>();
    thread::spawn(move || {
        if let Err(e) = load_worker(lure_addr, deadline) {
            let _ = load_tx.send(Err(e));
        }
    });

    // Every second, poll stats.
    let start = Instant::now();
    println!(
        "time (s) | inst_c2s_bytes | inst_s2c_bytes | route_c2s_bytes | route_s2c_bytes | sess_c2s_bytes | sess_s2c_bytes"
    );
    println!(
        "{:-<8}-+-{:-<14}-+-{:-<14}-+-{:-<15}-+-{:-<15}-+-{:-<14}-+-{:-<14}",
        "", "", "", "", "", "", ""
    );

    loop {
        let elapsed = start.elapsed();
        if elapsed >= duration {
            break;
        }

        tokio::time::sleep(Duration::from_secs(1)).await;

        let stats = lure.inspect_stats().await;
        let elapsed_secs = elapsed.as_secs_f64();

        // Aggregate session bytes (should be live during proxy, not 0).
        let mut sess_c2s = 0u64;
        let mut sess_s2c = 0u64;
        for sess in &stats.sessions {
            sess_c2s += sess.traffic.c2s_bytes;
            sess_s2c += sess.traffic.s2c_bytes;
        }

        // Route stats (first route in config).
        let (route_c2s, route_s2c) = stats
            .routes
            .first()
            .map(|r| (r.traffic.c2s_bytes, r.traffic.s2c_bytes))
            .unwrap_or((0, 0));

        println!(
            "{:>7.1} | {:>14} | {:>14} | {:>15} | {:>15} | {:>14} | {:>14}",
            elapsed_secs,
            stats.instance.traffic.c2s_bytes,
            stats.instance.traffic.s2c_bytes,
            route_c2s,
            route_s2c,
            sess_c2s,
            sess_s2c
        );
    }

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;

    // Check load result.
    if let Ok(Err(e)) = load_rx.try_recv() {
        return Err(e);
    }

    echo.stop();

    println!();
    println!("final stats:");
    let final_stats = lure.inspect_stats().await;
    println!(
        "  instance_c2s_bytes: {}",
        final_stats.instance.traffic.c2s_bytes
    );
    println!(
        "  instance_s2c_bytes: {}",
        final_stats.instance.traffic.s2c_bytes
    );

    if final_stats.instance.traffic.c2s_bytes == 0 {
        anyhow::bail!("ERROR: instance bytes remained zero (load thread did not run)");
    }

    Ok(())
}

fn load_worker(addr: SocketAddr, deadline: Instant) -> anyhow::Result<()> {
    let mut stream = TcpStream::connect(addr)?;
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));

    // Send Minecraft handshake to trigger routing (required by Lure).
    let (hs, login) = mc_handshake_and_login("probe.local")?;
    stream.write_all(&hs)?;
    stream.write_all(&login)?;

    // Now do raw echo loop.
    let mut buf = vec![0u8; CHUNK_SIZE];
    // Fill with recognizable pattern.
    for (i, b) in buf.iter_mut().enumerate() {
        *b = (i as u8).wrapping_add(0x42);
    }

    let mut pending: Vec<usize> = vec![];
    let mut read_buf = [0u8; CHUNK_SIZE];

    loop {
        let now = Instant::now();
        if now >= deadline && pending.is_empty() {
            break;
        }

        // Keep pipeline shallow: if < 2 pending, write one.
        if pending.len() < 2 && now < deadline {
            stream.write_all(&buf)?;
            pending.push(CHUNK_SIZE);
        }

        // Try to drain pending reads.
        while !pending.is_empty() {
            let expected = pending[0];
            match stream.read(&mut read_buf[..expected]) {
                Ok(0) => {
                    return Err(anyhow::anyhow!("echo server closed connection"));
                }
                Ok(n) => {
                    // Could be partial read; just continue draining.
                    let new_expected = expected - n;
                    if new_expected == 0 {
                        pending.remove(0);
                    } else {
                        pending[0] = new_expected;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // Try writing again.
                    break;
                }
                Err(e) => {
                    return Err(e.into());
                }
            }
        }
    }

    Ok(())
}

fn mc_handshake_and_login(host: &str) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let hs = net::HandshakeC2s {
        protocol_version: 758,
        server_address: host,
        server_port: 25565,
        next_state: net::HandshakeNextState::Login,
    };
    let login = net::LoginStartC2s {
        username: "probe_user",
        profile_id: None,
        sig_data: None,
    };

    let mut hs_raw = Vec::new();
    net::encode_packet(&mut hs_raw, &hs)?;
    let mut login_body = Vec::new();
    login.encode_body_with_version(&mut login_body, hs.protocol_version)?;
    let mut login_raw = Vec::new();
    net::encode_raw_packet(&mut login_raw, net::LoginStartC2s::ID, &login_body)?;
    Ok((hs_raw, login_raw))
}

struct RawEchoServer {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    join: thread::JoinHandle<()>,
}

impl RawEchoServer {
    fn start() -> io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = Arc::clone(&stop);

        let join = thread::spawn(move || {
            while !stop_thread.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let _ = stream.set_nodelay(true);
                        thread::spawn(|| raw_echo_loop(stream));
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self { addr, stop, join })
    }

    fn stop(self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.join.join();
    }
}

fn raw_echo_loop(mut stream: TcpStream) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if stream.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}
