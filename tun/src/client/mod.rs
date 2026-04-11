mod cli;
mod commands;
mod config;
mod runtime;

use clap::Parser;
use log::{info, warn};

use self::{
    cli::{Cli, Command, SystemdCommand},
    commands::{run_config, run_install, run_reload, run_sign, run_systemd_gensys, run_update},
    config::{
        default_config_path, find_config_path, load_config, pid_file_path, save_config,
        try_migrate_from_env,
    },
    runtime::run_orchestrator,
};

pub fn run_cli() -> anyhow::Result<()> {
    let cli = Cli::parse();
    sentry::configure_scope(|scope| {
        scope.set_tag("command", command_name(&cli.command));
    });

    match cli.command {
        Command::Run => {
            let (path, config) = if let Some(path) = find_config_path() {
                let config = load_config(&path)?;
                (path, config)
            } else if let Some(migrated) = try_migrate_from_env()? {
                let path = default_config_path()?;
                warn!(
                    "[migration] no config file found; auto-migrating from env vars \
                     (MINITUN_ENDPOINT / MINITUN_TOKEN / MINITUN_TOKENS) \
                     to {}",
                    path.display()
                );
                save_config(&path, &migrated)?;
                info!(
                    "[migration] config written to {}. \
                     Future starts use this file automatically. \
                     To install as a service: `minitun systemd gensys`",
                    path.display()
                );
                (path, migrated)
            } else {
                anyhow::bail!(
                    "no config file found; run `minitun install --token <t> --endpoints <e>` first, \
                     or set MINITUN_ENDPOINT and MINITUN_TOKEN env vars"
                )
            };
            if config.tunnels.is_empty() {
                anyhow::bail!("config has no [[tunnel]] entries");
            }
            let pid_path = pid_file_path()?;

            let backend = net::sock::backend_kind();
            sentry::configure_scope(|scope| {
                scope.set_tag("socket_backend", backend_kind_name(backend));
            });

            match backend {
                net::sock::BackendKind::Tokio | net::sock::BackendKind::Epoll => {
                    let rt = tokio::runtime::Builder::new_multi_thread()
                        .enable_all()
                        .build()?;
                    let local = tokio::task::LocalSet::new();
                    rt.block_on(local.run_until(run_orchestrator(config, path, pid_path)))?;
                }
                net::sock::BackendKind::Uring => {
                    net::sock::uring::start(async move {
                        run_orchestrator(config, path, pid_path).await
                    })?;
                }
            }
        }
        Command::Install(args) => {
            run_install(args)?;
        }
        Command::Reload => {
            run_reload()?;
        }
        Command::Update => {
            run_update()?;
        }
        Command::Systemd(args) => match args.command {
            SystemdCommand::Gensys { user, system, name } => {
                run_systemd_gensys(user, system, name)?;
            }
        },
        Command::Config(args) => {
            run_config(args)?;
        }
        Command::Sign(args) => {
            run_sign(args)?;
        }
    }

    Ok(())
}

fn backend_kind_name(kind: net::sock::BackendKind) -> &'static str {
    match kind {
        net::sock::BackendKind::Tokio => "tokio",
        net::sock::BackendKind::Epoll => "epoll",
        net::sock::BackendKind::Uring => "uring",
    }
}

fn command_name(command: &Command) -> &'static str {
    match command {
        Command::Run => "run",
        Command::Install(_) => "install",
        Command::Reload => "reload",
        Command::Update => "update",
        Command::Systemd(_) => "systemd",
        Command::Config(_) => "config",
        Command::Sign(_) => "sign",
    }
}
