# minitun — Tunnel Agent for Lure

A lightweight TCP tunnel agent that enables NAT passthrough for Lure proxy routes. One `minitun` process can manage multiple tunnel keys with multi-endpoint failover and hot-reload.

## Quick Start

```bash
# Install binary and create config
minitun install \
  --token 0011223344556677:8f1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f00112233445566778899aabb \
  --endpoints "lure.example.com:25577"

# View config
minitun config show

# Start the agent
minitun run
```

## Configuration

**File:** `~/.config/minitun.toml` (or `./minitun.toml`)

```toml
# Reconnect backoff duration (default: "1s")
reconnect = "1s"

# Optional: only allow forwarding to addresses in [map]
strict = false

# Tunnel entries
[[tunnel]]
endpoints = ["lure.example.com:25577"]
token = "0011223344556677:8f1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f00112233445566778899aabb"

[[tunnel]]
endpoints = ["sgp-lure.example.com:25577", "hkg-lure.example.com:25577"]
token = "8899aabbccddeeff:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

[map]
lobby = "127.0.0.1:25565"
```

## Commands

```bash
minitun run
  Start the agent

minitun install [--token <t>] [--endpoints <e,...>] [--map-name <n> --map-addr <a>]
  Install binary to ~/.local/bin/minitun, create/update config

minitun reload
  Send SIGHUP to running process (no downtime)

minitun update
  Self-update from GitHub releases

minitun config show
  Display current config

minitun config add-tunnel --token <t> --endpoints <e,...>
  Add a tunnel entry

minitun config remove-tunnel <index_or_key_id_prefix>
  Remove a tunnel entry

minitun config add-map <name> <addr>
  Add a whitelist entry (for strict mode)

minitun config remove-map <name>
  Remove a whitelist entry

minitun systemd gensys [--user|--system]
  Generate systemd unit file template

minitun sign --token <t> --intent <listen|connect> [--timestamp <ts>] [--session <s>]
  Development helper: compute HMAC signatures
```

## Features

✅ **TOML Configuration** — simple, structured config with credentials
✅ **Multi-Endpoint** — automatic failover via round-robin cycling
✅ **Hot Reload** — `minitun reload` sends SIGHUP, only changed tunnels restart
✅ **Strict Mode** — whitelist target addresses in `[map]` section
✅ **Self-Update** — `minitun update` downloads from GitHub releases
✅ **Systemd Ready** — `minitun systemd gensys` generates unit files
✅ **Multiple Backends** — Tokio (stable), epoll (fast), io_uring (experimental)

## Example: Multi-Endpoint Failover

```toml
# Routes through Singapore or Hong Kong on failure
[[tunnel]]
endpoints = ["sgp.lure.com:25577", "hkg.lure.com:25577"]
token = "key_id:secret"
```

Agent cycles through endpoints on reconnect failures (round-robin).

## Example: Strict Mode

```toml
strict = true

[map]
lobby = "127.0.0.1:25565"
```

Sessions targeting addresses not in `[map]` are rejected.

## Systemd Integration

Generate a unit file:

```bash
minitun systemd gensys --user > ~/.config/systemd/user/minitun.service
systemctl --user daemon-reload
systemctl --user enable --now minitun
```

Or manage manually:

```bash
minitun run &  # Start in background
minitun reload # Reload on config change
kill -SIGHUP <pid>  # Also works for manual reload
```

## Token Format

Tokens are 40 hex characters in `key_id:secret` format:
- `key_id`: 16 hex chars (8 bytes)
- `secret`: 64 hex chars (32 bytes)

Generate:

```bash
python3 -c "import secrets; print(f'{secrets.token_hex(8)}:{secrets.token_hex(32)}')"
```

## Logging

```bash
RUST_LOG=debug minitun run
RUST_LOG=info minitun run
```

## Building

```bash
cd /path/to/Lure
cargo build -p tun --release
# Binary at: target/release/minitun
```

## Full Documentation

See `docs/tunnel.md` for:
- Wire protocol specification
- Security considerations
- Advanced routing scenarios
- Troubleshooting guide
- Slave forwarding (distributed deployments)

## License

Part of the Lure project. See root LICENSE.
