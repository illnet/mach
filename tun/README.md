# minitun

Lightweight TCP tunnel agent for Lure. Manages multiple tunnel keys with multi-endpoint failover and hot-reload.

## Install

```bash
minitun install --token <key_id>:<secret> --endpoints lure.example.com:25577
```

Copies binary to `~/.local/bin/minitun` and writes config to `~/.config/minitun.toml`.

## Config

`~/.config/minitun.toml` (also checks `./minitun.toml`):

```toml
# only forward to addresses in [map] when true
strict = false
reconnect = "1s"

[[tunnel]]
endpoints = ["lure.example.com:25577"]
token = "0011223344556677:aabbccdd..."

# multiple endpoints = round-robin failover
[[tunnel]]
endpoints = ["sgp.lure.com:25577", "hkg.lure.com:25577"]
token = "8899aabbccddeeff:11223344..."

[map]
lobby = "127.0.0.1:25565"
```

Token format: `<16 hex key_id>:<64 hex secret>`. Generate one:

```bash
python3 -c "import secrets; print(f'{secrets.token_hex(8)}:{secrets.token_hex(32)}')"
```

## Usage

```bash
minitun run                # start agent
minitun reload             # SIGHUP running process, diff-based restart
minitun update             # self-update from github releases
minitun config show        # print config
minitun config add-tunnel --token <t> --endpoints <e,...>
minitun config remove-tunnel <index|key_id_prefix>
minitun config add-map <name> <addr>
minitun config remove-map <name>
```

## Systemd

```bash
minitun systemd gensys --user > ~/.config/systemd/user/minitun.service
systemctl --user daemon-reload
systemctl --user enable --now minitun
```

## Reload Behavior

`minitun reload` (or `kill -HUP <pid>`) reloads config and diffs against running state:

- Tunnel removed: connections terminated
- Token or endpoints changed: tunnel restarted
- Only `map`/`strict` changed: updated in-place, no reconnect

## Build

```bash
cargo build -p tun --release
# target/release/minitun
```

## Protocol

See [docs/tunnel.md](../docs/tunnel.md) for wire format, security model, slave forwarding, and troubleshooting.
