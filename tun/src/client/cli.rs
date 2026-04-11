use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(name = "minitun")]
#[command(about = "Lure mini tunnel agent")]
pub(super) struct Cli {
    #[command(subcommand)]
    pub(super) command: Command,
}

#[derive(Subcommand)]
pub(super) enum Command {
    /// Start the tunnel agent using ~/.config/minitun.toml
    Run,
    /// Install binary and manage config (user: ~/.local/bin, system: /usr/local/bin)
    Install(InstallArgs),
    /// Send SIGHUP to the running minitun process to reload config
    Reload,
    /// Self-update from GitHub releases
    Update,
    /// Manage systemd service unit
    Systemd(SystemdArgs),
    /// Manage config file
    Config(ConfigArgs),
    /// Compute a valid HMAC signature for a hello message (development helper)
    Sign(SignArgs),
}

#[derive(Args)]
pub(super) struct InstallArgs {
    /// Authentication token (format: key_id:secret, both hex-encoded).
    /// Repeat to add multiple tunnel entries.
    #[arg(long = "token", action = clap::ArgAction::Append)]
    pub(super) tokens: Vec<String>,

    /// Endpoints for tunnel entries (space or comma separated, repeatable).
    /// If single --endpoints, it applies to all --tokens.
    #[arg(long = "endpoints", action = clap::ArgAction::Append)]
    pub(super) endpoints: Vec<String>,

    /// Add/update a map entry key (must be paired with --map-addr).
    #[arg(long = "map-name", requires = "map_addr")]
    pub(super) map_name: Option<String>,

    /// Map entry local address (paired with --map-name).
    #[arg(long = "map-addr", requires = "map_name")]
    pub(super) map_addr: Option<String>,

    /// Enable strict mode in config.
    #[arg(long)]
    pub(super) strict: bool,

    /// Set reconnect backoff duration (e.g. "1s", "500ms", "2m").
    #[arg(long)]
    pub(super) reconnect: Option<String>,

    /// Install system-wide: binary → /usr/local/bin/minitun, config → /etc/minitun.toml.
    #[arg(long)]
    pub(super) system: bool,
}

#[derive(Args)]
pub(super) struct ConfigArgs {
    #[command(subcommand)]
    pub(super) command: ConfigCommand,
}

#[derive(Subcommand)]
pub(super) enum ConfigCommand {
    /// Print the current config file.
    Show,
    /// Add a tunnel entry.
    AddTunnel(AddTunnelArgs),
    /// Remove a tunnel entry by index or key_id prefix.
    RemoveTunnel { index_or_key: String },
    /// Add a map entry.
    AddMap { name: String, addr: String },
    /// Remove a map entry.
    RemoveMap { name: String },
}

#[derive(Args)]
pub(super) struct AddTunnelArgs {
    /// Endpoints for the tunnel (space or comma separated, repeatable).
    #[arg(long = "endpoints", action = clap::ArgAction::Append)]
    pub(super) endpoints: Vec<String>,
    /// Token in format key_id:secret (both hex-encoded).
    #[arg(long)]
    pub(super) token: String,
}

#[derive(Args)]
pub(super) struct SystemdArgs {
    #[command(subcommand)]
    pub(super) command: SystemdCommand,
}

#[derive(Subcommand)]
pub(super) enum SystemdCommand {
    /// Generate a systemd unit file template for the current config.
    Gensys {
        /// Install as a per-user service.
        #[arg(long, conflicts_with = "system")]
        user: bool,
        /// Install as a system-wide service (default).
        #[arg(long, conflicts_with = "user")]
        system: bool,
        /// Service name (default: minitun).
        #[arg(long)]
        name: Option<String>,
    },
}

#[derive(Args)]
pub(super) struct SignArgs {
    /// Token (format: key_id:secret, both hex-encoded)
    #[arg(short, long, env = "MINITUN_TOKEN")]
    pub(super) token: String,

    /// Intent to sign for
    #[arg(long, value_parser = ["listen", "connect", "beacon"])]
    pub(super) intent: String,

    /// Unix timestamp (seconds). If omitted, uses current time.
    #[arg(long)]
    pub(super) timestamp: Option<u64>,

    /// Session token for connect intent (64 hex chars, 32 bytes)
    #[arg(long)]
    pub(super) session: Option<String>,
}
