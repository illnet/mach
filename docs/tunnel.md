# TCP Tunnel (Beta)

This document describes the pure-TCP tunnel agent flow and the slave-to-master forwarded-request extension for distributed Mach deployments.

## Purpose

- NAT passthrough for routes marked as tunnel-enabled.
- No encryption or auth beyond a shared 32-byte token.
- `minitun` connects to Mach ingress and reverse-proxies to the target.
- Optional slave forwarding mode relays tunnel session requests through a master Mach instance while keeping the client data plane local to the slave.

## Status

**Beta-Ready**: Session timeout cleanup, comprehensive testing, and observability implemented.

**Not yet production-ready**: Keep-alive protocol extension (deferred to v2).

## Route Configuration

Add tunnel flags and a 32-byte token to a route in `settings.toml`.

```toml
[[route]]
matcher = "tunnel.example.com"
endpoint = "10.0.0.12:25565"
priority = 0

[route.flags]
tunnel = true

# 32-byte token as hex (64 chars) or base64
# tunnel_token = "8f1f..."
# tunnel_token = "s3Iu3RkV..."
```

### minitun

`minitun` is the singleton tunnel client. One process can register multiple tunnel keys against the same Mach endpoint using a TOML configuration file.

#### Configuration

Create `~/.config/minitun.toml`:

```toml
# Reconnect backoff (default: "1s")
reconnect = "1s"

# Optional: strict mode — only forward to addresses in [map]
strict = false

# Tunnel entries (each can have multiple endpoints for failover)
[[tunnel]]
endpoints = ["mach.example.com:25577"]
token = "0011223344556677:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

[[tunnel]]
endpoints = ["sgp-mach.example.com:25577", "hkg-mach.example.com:25577"]
token = "8899aabbccddeeff:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

# Optional: address whitelist for strict mode
[map]
lobby = "127.0.0.1:25565"
```

#### Generate Tokens

Create cryptographically secure 32-byte tokens:

```bash
# Using openssl
openssl rand -hex 32

# Using Python
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Format: `key_id_hex:secret_hex` where:
- `key_id_hex`: 16 hex chars (8 bytes)
- `secret_hex`: 64 hex chars (32 bytes)

#### Setup

```bash
# Install binary and create initial config
minitun install \
  --token 0011223344556677:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --endpoints "mach.example.com:25577" \
  --map-name lobby --map-addr 127.0.0.1:25565

# Add more tunnels
minitun config add-tunnel \
  --token 8899aabbccddeeff:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  --endpoints "sgp-mach.example.com:25577,hkg-mach.example.com:25577"

# View current config
minitun config show
```

#### Running

```bash
# Start the agent (reads ~/.config/minitun.toml)
minitun run

# Or as a systemd service
minitun systemd gensys --user > ~/.config/systemd/user/minitun.service
systemctl --user daemon-reload
systemctl --user enable --now minitun

# Reload config without restart
minitun reload
```

#### Self-Update

```bash
minitun update
```

Automatically downloads the latest binary from GitHub releases.

### Slave Forwarding Configuration

Slave forwarding is instance-driven. Any node with `tunnel.master_url` set will send per-session tunnel offers to that master.

```toml
inst = "sgp-edge-1"

[tunnel]
master_url = "master.example.com:25577"
```

- `MACH_TUN_MASTER_URL` overrides `tunnel.master_url`.
- The value is a TCP endpoint (`host:port`), even though the config field keeps the historical `*_url` naming.

## Tunnel Wire Protocol

All tunnel connections begin with a fixed hello frame:

- Magic: `LTUN` (4 bytes)
- Version: `3` (1 byte)
- Intent: `1` = listen, `2` = connect, `3` = forward (1 byte)
- Key ID: 8 bytes
- Timestamp: 8 bytes
- HMAC: 32 bytes
- Session: 32 bytes (only for intent=connect)
- Forward payload: session + ttl + `from` socket address + `to` socket address (only for intent=forward)

### Server Messages

After receiving a tunnel hello, the server can send:

- SessionOffer: `0x01` + 32-byte session token
- TargetAddr: `0x02` + addr family + port + IP
  - family `4`: 1 byte, port 2 bytes (be), IPv4 4 bytes
  - family `6`: 1 byte, port 2 bytes (be), IPv6 16 bytes
- ForwardAck: `0x03` + 32-byte correlation/session id
- ForwardRequest: `0x04` + 32-byte correlation/session id + 1-byte ttl +
  `from` socket address + `to` socket address
  - `from`/`to` use the same addr family + port + IP payload layout as
    `TargetAddr`
  - this is the master-to-agent request that pairs with `ForwardAck` in the
    forwarded-session flow

## End-to-End Flow

1) Agent connects to Mach ingress with intent=listen and token.
2) Client connects normally (Minecraft handshake + login).
3) If the resolved route has `tunnel` flag and a valid `tunnel_token`, Mach:
   - generates a session token
   - sends SessionOffer to the active agent
4) Agent reconnects with intent=connect, token, session token.
5) Mach responds with TargetAddr (the resolved backend address).
6) Mach bridges client stream to agent stream and forwards:
   - raw handshake
   - raw login start
   - any pending buffered bytes

### Distributed Slave Forward Flow

1) A slave Mach instance accepts a client on a tunnel-enabled route.
2) The slave resolves the backend locally, creates a pending tunnel session, and opens a tunnel `forward` hello to `tunnel.master_url`.
3) The forward payload contains:
   - the session token
   - `ttl`: a loop guard for forwarded offers
   - `from`: the slave edge socket that the agent must connect back to
   - `to`: the resolved backend socket address
   - The tunnel `key_id` stays in the fixed hello header and is still covered by the HMAC.
4) The master validates the HMAC and forwards the raw request to the active listening agent for that tunnel, then replies with `ForwardAck`.
5) The agent connects back to the slave edge at `from` using the normal `connect` flow.
6) The slave validates the session and replies with `TargetAddr(to)`.
7) The data plane remains direct between slave edge and agent; the master is only a control-plane relay.

## Security Considerations

### What is Protected
- **Token authentication**: Each tunnel route uses a 32-byte token to authenticate agents.
- **Session isolation**: Session tokens are cryptographically random and checked on every connection.
- **Token mismatch detection**: Attempting to connect with a mismatched token is logged and rejected.

### What is NOT Protected
- **No encryption**: Tunnel traffic is sent in plain TCP. Use TLS/DTLS at the application layer or network layer (VPN/WireGuard).
- **No authentication on subsequent connections**: After the initial token validation, subsequent client traffic is not authenticated.
- **No integrity checks**: Network packets can be modified in flight. Rely on application-level integrity (e.g., Minecraft protocol hash).
- **Token exposure**: If the token is compromised, any agent can impersonate the tunnel. Treat tokens like credentials.

### Best Practices
1. **Use HTTPS/TLS for sensitive applications** - Don't rely on the tunnel for encryption.
2. **Rotate tokens regularly** - Change tunnel tokens periodically (quarterly or after personnel changes).
3. **Use VPN for additional network security** - Combine with WireGuard or Tailscale for defense in depth.
4. **Monitor tunnel connections** - Enable debug logging and monitor for unauthorized connection attempts.
5. **Limit access to configuration** - Store `settings.toml` securely with restricted file permissions.

## Operational Limits and Timeouts

### Session Timeout (30 seconds)
- A client must complete the Minecraft login handshake within 30 seconds after receiving a SessionOffer.
- If no agent connects to accept the session within 30 seconds, the session expires automatically.
- Expired sessions are cleaned up every 5 seconds. Metrics are available in debug logs.

### Keep-Alive
- **Not currently supported** - If the agent connection is idle, it may be closed by network infrastructure.
- **Workaround**: Design agents to reconnect periodically or on any connection error.
- **Future**: Keep-alive will be added in a future wire-protocol revision.

### Maximum Pending Sessions
- **Default limit**: 10,000 pending sessions per Mach instance.
- **Rationale**: Prevents unbounded memory growth from clients that accept but never complete login.
- **Behavior**: New session offers are rejected if the limit is exceeded; clients receive a "tunnel session limit exceeded" error.

## Observability

### Logging

Tunnel events are logged using the standard Mach logger:

```
[INFO] Tunnel agent registered: token=8f
[DEBUG] Tunnel session offered: token=8f target=10.0.0.12:25565
[DEBUG] Tunnel session accepted: token=8f target=10.0.0.12:25565
[DEBUG] Tunnel agent disconnected: token=8f
[DEBUG] Tunnel session expired: session=3c
[WARN] Tunnel agent not found: token=8f session=3c
[WARN] Tunnel session not found: session=3c
[WARN] Tunnel token mismatch (unauthorized accept attempt): agent=8f session=3c
[DEBUG] Tunnel forward request received: token=8f from=198.51.100.10:25577 target=10.0.0.12:25565
[ERROR] Tunnel session error during session handling (target 10.0.0.12:25565): ...
```

Enable debug logging to see session lifecycle events:

```bash
RUST_LOG=debug minitun run
```

### Metrics

The following metrics are exposed:

- `tunnel.agents.registered` (gauge) - Number of connected tunnel agents
- `tunnel.agents.connected` (gauge) - Number of agents with active listening
- `tunnel.sessions.offered` (counter) - Total sessions offered to agents
- `tunnel.sessions.accepted` (counter) - Total sessions accepted by agents
- `tunnel.sessions.timeout` (counter) - Total sessions that expired
- `tunnel.sessions.failed` (counter) - Total session failures

## Troubleshooting

### Agent cannot connect to Mach

**Symptoms**: Agent reports connection refused or timeout.

**Diagnosis**:
1. Verify Mach is listening on the correct address: `netstat -tlnp | grep mach`
2. Check firewall rules: `sudo iptables -L -n` or cloud security group
3. Verify network connectivity: `ping <mach-server>`

**Solution**: Open the port in firewall and verify connectivity.

### Client connects but hangs during handshake

**Symptoms**: Client logs in, but game freezes on "Logging in...".

**Diagnosis**:
1. Check agent logs: Are there any connection errors?
2. Check Mach logs for "session timeout" or "agent disconnected"
3. Enable debug logging on both sides

**Solution**:
1. Verify the endpoint address is correct: `telnet <endpoint>`
2. Check agent is still connected: Look for "Tunnel agent registered" in logs
3. Increase timeout if needed (currently hard-coded to 30 seconds)

### "Tunnel session limit exceeded" error

**Symptoms**: Clients receive a disconnect with message "tunnel session limit exceeded".

**Diagnosis**:
1. Check if legitimate traffic spike or attack
2. Monitor agent connections: Are agents accepting sessions?

**Solution**:
1. Increase pending session limit (requires code change)
2. Add rate limiting to clients
3. Investigate why agents are not accepting sessions

### Agent disconnects unexpectedly

**Symptoms**: Agent logs show successful registration, then unexpected disconnection.

**Diagnosis**:
1. Check network stability: Look for packet loss or timeout errors
2. Check Mach logs for write errors or protocol violations
3. Verify agent correctly handles connection drops

**Solution**:
1. Implement agent reconnect logic (exponential backoff)
2. Add keep-alive heartbeats (future feature)
3. Use persistent network (WireGuard/VPN) for reliability

## Example Deployment

### Agent on internal network, Mach on public internet

```
[Internal Network]
  minitun (token: 0011223344556677:...)
       |
       | (TLS/WireGuard recommended)
       |
    [Internet]
       |
   Mach Gateway
       |
   Minecraft Clients
```

**minitun config** (`~/.config/minitun.toml`):
```toml
[[tunnel]]
endpoints = ["proxy.example.com:25567"]
token = "0011223344556677:8f1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f00112233445566778899aabb"
```

**Start agent**:
```bash
minitun install --token 0011223344556677:8f1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f00112233445566778899aabb \
  --endpoints proxy.example.com:25567
minitun run
```

**Route configuration in Mach** (`settings.toml`):
```toml
[[route]]
matcher = "behind-nat.example.com"
endpoint = "internal-server.local:25565"
priority = 0

[route.flags]
tunnel = true
tunnel_token = "8f1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f00112233445566778899aabb"
```

### Multi-agent for redundancy

Deploy multiple `minitun` instances with the same token if you want redundancy. Mach will keep one active listener per key, so restarts and failover are handled by reconnecting instances.

**Shared config** (`~/.config/minitun.toml`):
```toml
[[tunnel]]
endpoints = ["proxy.example.com:25567"]
token = "0011223344556677:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
```

**All instances run**:
```bash
minitun run
```

Both instances connect with the same token; Mach accepts whichever connects first. On restart, the other instance takes over automatically.

## Notes

- Tunnel detection happens before decoding Minecraft handshake; if the magic
  bytes are not present, Mach proceeds with the normal handshake path.
- This is a simple coordination layer and does not provide encryption.
- Session timeouts are automatic and transparent to agents and clients.
