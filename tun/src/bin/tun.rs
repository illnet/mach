use log::error;

const SENTRY_DSN: &str =
    "https://d8cb23f37184d406d4b129c0dc0b24d4@o1192891.ingest.us.sentry.io/4511109122293760";

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let sentry = init_sentry("minitun");

    if let Err(err) = tun::client::run_cli() {
        capture_sentry_error("minitun_fatal", "tunnel_client", &err);
        error!("{err}");
        drop(sentry);
        std::process::exit(1);
    }
}

fn init_sentry(service: &'static str) -> Option<sentry::ClientInitGuard> {
    if std::env::var_os("MINITUN_NOSENTRY").is_some() || std::env::var_os("NOSENTRY").is_some() {
        return None;
    }

    let sentry_environment = std::env::var("MINITUN_SENTRY_ENV")
        .ok()
        .or_else(|| std::env::var("SENTRY_ENVIRONMENT").ok())
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
        scope.set_tag("binary", "minitun");
        scope.set_tag("default_error_origin", "tunnel_client");
    });
    Some(guard)
}

fn capture_sentry_error(event: &str, origin: &str, err: &anyhow::Error) {
    sentry::with_scope(
        |scope| {
            scope.set_tag("event", event);
            scope.set_tag("error_origin", origin);
            scope.set_tag("error_type", "anyhow::Error");
            scope.set_extra("error", format!("{err:#}").into());
        },
        || {
            sentry::capture_message(
                &format!("Tunnel client runtime failure: {err:#}"),
                sentry::Level::Error,
            );
        },
    );
}
