use std::{env, error::Error, io::ErrorKind, time::Duration};

use mach::{
    config::{LureConfig, LureConfigLoadError, ProxySigningKey},
    proxy::Lure,
    rpc,
    sock::{BackendKind, backend_selection},
    telemetry::{oltp::init_meter, process::ProcessMetricsService},
    utils::{leak, spawn_named},
};

const SENTRY_DSN: &str =
    "https://d8cb23f37184d406d4b129c0dc0b24d4@o1192891.ingest.us.sentry.io/4511109122293760";

fn main() {
    let sentry = init_sentry("mach");
    if let Err(err) = try_main() {
        capture_sentry_error("mach_fatal", "proxy", &*err);
        eprintln!("mach failed: {err}");
        drop(sentry);
        std::process::exit(1);
    }
}

fn try_main() -> Result<(), Box<dyn Error>> {
    // Minimal CLI: used for Dockerfile smoke checks and quick inspection.
    // Keep this lightweight (no clap) to avoid changing runtime behavior.
    if let Some(arg) = env::args().nth(1) {
        match arg.as_str() {
            "--version" | "-V" => {
                println!("{}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "--help" | "-h" => {
                println!("usage: mach [--version]");
                return Ok(());
            }
            _ => {}
        }
    }

    let _ = dotenvy::dotenv();
    #[cfg(debug_assertions)]
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .init();
    #[cfg(not(debug_assertions))]
    env_logger::init();

    let backend = backend_selection();
    sentry::configure_scope(|scope| {
        scope.set_tag("socket_backend", backend_kind_name(backend.kind));
    });
    match backend.kind {
        BackendKind::Uring => {
            log::info!("socket backend: tokio-uring ({})", backend.reason);
            net::sock::uring::start(async {
                let local = tokio::task::LocalSet::new();
                local.run_until(run()).await
            })
        }
        BackendKind::Epoll => {
            log::info!("socket backend: epoll ({})", backend.reason);
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let local = tokio::task::LocalSet::new();
            runtime.block_on(local.run_until(run()))
        }
        BackendKind::Tokio => {
            if backend.reason.contains("init failed") {
                log::warn!("socket backend: tokio ({})", backend.reason);
            } else {
                log::info!("socket backend: tokio ({})", backend.reason);
            }
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let local = tokio::task::LocalSet::new();
            runtime.block_on(local.run_until(run()))
        }
    }
}

fn init_sentry(service: &'static str) -> Option<sentry::ClientInitGuard> {
    if env::var_os("MACH_NOSENTRY").is_some() || env::var_os("NOSENTRY").is_some() {
        return None;
    }

    let sentry_environment = env_var("MACH_SENTRY_ENV")
        .or_else(|| env::var("SENTRY_ENVIRONMENT").ok())
        .map(Into::into);
    let guard = sentry::init((
        SENTRY_DSN,
        sentry::ClientOptions {
            release: sentry::release_name!(),
            send_default_pii: false,
            server_name: None,
            environment: sentry_environment,
            ..Default::default()
        },
    ));
    sentry::configure_scope(|scope| {
        scope.set_tag("service", service);
        scope.set_tag("binary", env!("CARGO_PKG_NAME"));
        scope.set_tag("default_error_origin", "proxy");
    });
    Some(guard)
}

fn backend_kind_name(kind: BackendKind) -> &'static str {
    match kind {
        BackendKind::Tokio => "tokio",
        BackendKind::Epoll => "epoll",
        BackendKind::Uring => "uring",
    }
}

fn capture_sentry_error(event: &str, origin: &str, err: &dyn Error) {
    sentry::with_scope(
        |scope| {
            scope.set_tag("event", event);
            scope.set_tag("error_origin", origin);
            scope.set_tag("error_type", std::any::type_name_of_val(err));
        },
        || {
            sentry::capture_message("Mach runtime failure", sentry::Level::Error);
        },
    );
}

fn env_var(key: &str) -> Option<String> {
    env::var(key).ok()
}

async fn run() -> Result<(), Box<dyn Error>> {
    let providers = if dotenvy::var("OTEL_EXPORTER_OTLP_ENDPOINT").is_ok() {
        Some((init_meter(), 0u8))
    } else {
        None
    };

    let current_dir = env::current_dir()?;
    let config_file = current_dir.join("settings.toml");

    let mut should_save = false;
    let mut config = match LureConfig::load(&config_file) {
        Ok(config) => config,
        Err(LureConfigLoadError::Io(io)) => {
            if io.kind() == ErrorKind::NotFound {
                should_save = true;
                LureConfig::default()
            } else {
                return Err(io.into());
            }
        }
        Err(LureConfigLoadError::Parse(parse_error)) => return Err(parse_error.into()),
    };
    apply_proxy_signing_key(&mut config);
    apply_tunnel_master_url(&mut config);
    if should_save {
        config.save(&config_file)?;
    }

    let pmt = leak(ProcessMetricsService::new());
    pmt.start();

    let lure = leak(Lure::new(config));
    lure.sync_routes_from_config().await?;

    // Global metrics logger: log aggregate traffic every 60 seconds
    spawn_named("Global metrics logger", async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            let (c2s_bytes, s2c_bytes, c2s_chunks, s2c_chunks) =
                rpc::inspect::take_global_traffic_snapshot();
            if c2s_bytes > 0 || s2c_bytes > 0 {
                let c2s_mb = c2s_bytes as f64 / 1_000_000.0;
                let s2c_mb = s2c_bytes as f64 / 1_000_000.0;
                log::info!(
                    "traffic_minute: c2s={:.2}MB packets={} s2c={:.2}MB packets={} total={:.2}MB",
                    c2s_mb,
                    c2s_chunks,
                    s2c_mb,
                    s2c_chunks,
                    (c2s_mb + s2c_mb)
                );
            }
        }
    })?;

    #[cfg(unix)]
    {
        let reload_path = config_file.clone();
        let reload_lure = lure;
        spawn_named("Reload handler", async move {
            use tokio::signal::unix::{SignalKind, signal};

            // SIGCONT=18
            let mut sigcont = match signal(SignalKind::from_raw(18)) {
                Ok(sig) => sig,
                Err(err) => {
                    log::error!("Failed to register SIGCONT handler: {err}");
                    return;
                }
            };

            while sigcont.recv().await.is_some() {
                match LureConfig::load(&reload_path) {
                    Ok(cfg) => {
                        if let Err(err) = reload_lure.reload_config(cfg).await {
                            log::error!("Failed to apply reloaded config: {err:?}");
                        }
                    }
                    Err(LureConfigLoadError::Io(io)) if io.kind() == ErrorKind::NotFound => {
                        if let Err(err) = reload_lure.reload_config(LureConfig::default()).await {
                            log::error!("Failed to apply default config during reload: {err:?}");
                        }
                    }
                    Err(err) => {
                        log::error!("Failed to load config during reload: {err}");
                    }
                }
            }
        })?;
    }
    #[cfg(not(unix))]
    {
        let _ = &config_file;
        log::info!("config reload via SIGCONT is not supported on this platform");
    }

    spawn_named("Main thread", async move {
        if let Err(e) = lure.start().await {
            capture_sentry_error("mach_start_failed", "proxy", &*e);
            log::error!("{e}");
        }
        if let Some(providers) = providers {
            providers.0.shutdown().unwrap();
            // providers.1.shutdown()?;
        }
    })?;
    #[cfg(unix)]
    {
        use futures::future::{FutureExt, select_all};
        use tokio::signal::unix::{SignalKind, signal};

        let mut sigint = signal(SignalKind::interrupt())?;
        let mut sigterm = signal(SignalKind::terminate())?;

        let sigint_fut = sigint.recv().boxed();
        let sigterm_fut = sigterm.recv().boxed();

        let _ = select_all([sigint_fut, sigterm_fut]).await;
        log::info!("Received signal, stopping...");
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
        log::info!("Received Ctrl-C, stopping...");
    }
    Ok(())
}

fn apply_proxy_signing_key(config: &mut LureConfig) {
    if let Some(value) = env_var("MACH_PROXY_SIGNING_KEY") {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return;
        }
        match ProxySigningKey::from_base64(trimmed) {
            Ok(key) => {
                config.proxy_signing_key = Some(key);
                log::info!("proxy signing key loaded from env");
            }
            Err(err) => {
                log::warn!("MACH_PROXY_SIGNING_KEY is not valid base64: {err}");
            }
        }
        return;
    }

    if config.proxy_signing_key.is_some() {
        return;
    }

    let mut seed = [0u8; 32];
    if let Err(err) = getrandom::fill(&mut seed) {
        log::warn!("failed to generate proxy signing key: {err}");
        return;
    }
    config.proxy_signing_key = Some(ProxySigningKey::from_bytes(seed.to_vec()));
    log::info!("generated ephemeral proxy signing key");
}

fn apply_tunnel_master_url(config: &mut LureConfig) {
    let Some(value) = env_var("MACH_TUN_MASTER_URL") else {
        return;
    };

    let trimmed = value.trim();
    if trimmed.is_empty() {
        config.tunnel.master_url = None;
        return;
    }

    config.tunnel.master_url = Some(trimmed.to_string());
    log::info!("tunnel master url loaded from env");
}
