<p align="center">
  <img src="https://github.com/sammwyy/Lure/raw/main/assets/icon@64.png" alt="Lure Icon"/>
</p>

<h1 align="center">Lure</h1>
<p align="center"><em>The native Minecraft reverse proxy that works.</em></p>

---

## Contents

- [What It Is](#what-it-is)
- [Performance tuning](#performance-tuning)
- [Features](#features)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Running (I/O Backends)](#running-io-backends)
- [Tunneling (Beta)](#tunneling-beta)
- [Env Vars](#env-vars)
- [Compatibility / Quirks](#compatibility--quirks)
- [Development](#development)
- [Credits](#credits)

## What It Is

Lure is a TCP proxy that speaks enough Minecraft to proxy and filter<sub>(not yet)</sub> connections without
turning the config into a second programming language.

Its only purpose is to correctly delivers the correct Minecraft server to the client, however it
could be used to against quite the basic threats.

Can be configured with a yet-not-quite-friendly controller. However, we have a nice GUI to actually
control. If you really interested, you can be the early-adopter by contacting Discord @stdpi.

## Performance tuning

You can choose one of the connection backends that suits your use.

- **tokio**: Stable, quite fast polling and scales on multiple cores.
- **epoll**: Beta (Linux-only), the way HAProxy delivers million packets. Enable with `LURE_IO_EPOLL=1`
- **tokio-uring**: failed to perform under real stress even seems stable. Enable with `LURE_IO_URING=1` (**deprecated**, please don't use)

## Features

- Multi-route and multi-endpoint routing (single or multiple matchers/endpoints), load balancing
- Optional RPC control plane for orchestration (see [Lucky](https://github.com/hUwUtao/Lucky))
- PROXY protocol support, with signing authorization from proxy, implemented with [BetterProxyProtocol](https://github.com/LangDuaMC/BetterProxyProtocol)
- OTEL metrics observation
- Basic connection rate limiting, and risky IP filtering in the future.
- TCP tunnel agent (beta) to connect with the most efficient overhead

## Quick Start

```bash
cargo run
```

Reads `settings.toml` from the current directory. If it does not exist, Lure will generate one.
The generated default binds to `0.0.0.0:25577`.

Reload config on `SIGCONT`:

```bash
kill -CONT <pid>
```

Optional RPC backend (orchestration): set `LURE_RPC`.

Telemetry: set `OTEL_EXPORTER_OTLP_ENDPOINT` to enable OTEL export.

## Configuration

`settings.toml` is plain TOML. No generators. No templates. No "just run the installer".

Notes:
- The config key is spelled `proxy_procol` (typo preserved for compatibility).

Minimal example:

```toml
inst = "main"
bind = "0.0.0.0:25577"
proxy_procol = false
max_conn = 65535
cooldown = 3

[strings]
ROUTE_NOT_FOUND = "route not found"
SERVER_OFFLINE = "server offline"

[[route]]
matchers = ["mc.acme.co", "play.acme.co"]
endpoints = ["10.0.0.10:25565", "10.0.0.11:25565"]
priority = 0

[route.flags]
proxy_protocol = true
preserve_host = true
auth_mode = "protected"

[[route]]
matcher = "eu.acme.co"
endpoint = "10.0.1.10:25565"
priority = 0

[route.flags]
proxy_protocol = true
auth_mode = "public"
```

## Running (I/O Backends)

Default is Tokio:

```bash
cargo run
```

Epoll backend (beta, Linux-only):

```bash
LURE_IO_EPOLL=1 cargo run
```

tokio-uring (not recommended; "failed experiment"):

```bash
LURE_IO_URING=1 cargo run --features uring
```

## Tunneling (Beta)

Need NAT passthrough? Lure can hand a connection to a tunnel agent that lives inside the network.

- Docs: `docs/tunnel.md`
- Security model: only to traverse NAT (TLS/VPN recommended for encryption)

### Agent Setup

Create `~/.config/minitun.toml`:

```toml
[[tunnel]]
endpoints = ["lure.example.com:25577"]
token = "0011223344556677:8f1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f00112233445566778899aabb"
```

Run the agent:

```bash
minitun install --token 0011223344556677:8f1f2a3b... --endpoints lure.example.com:25577
minitun run
```

### Route Configuration

Add tunnel flags to a route in Lure's `settings.toml`:

```toml
[[route]]
matcher = "behind-nat.example.com"
endpoint = "10.0.0.12:25565"
priority = 0

[route.flags]
tunnel = true
tunnel_token = "8f1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f00112233445566778899aabb"
```

### More Details

See `docs/tunnel.md` for full configuration, systemd integration, multi-endpoint failover, hot reload, and troubleshooting.

## Observability (OTLP)

Lure exports metrics and traces via OpenTelemetry Protocol (OTLP).

### Enabling export

Set `OTEL_EXPORTER_OTLP_ENDPOINT` to your collector address:

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318 ./lure
```

Per-signal overrides are also supported:

```bash
OTEL_EXPORTER_OTLP_METRICS_ENDPOINT=http://otel-collector:4318/v1/metrics
OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://otel-collector:4317
```

Default protocol is `http/protobuf`. The meter and tracer scope name is `lure`.

### Metric reference

All metric names use underscores. Units are specified via OTel `.with_unit()`;
exported metrics include unit annotations (e.g. `{packet}`, `By`, `ms`, `us`).

#### Handshake metrics

| Metric | Type | Unit | Attributes | Description |
|---|---|---|---|---|
| `lure_socket_open` | Counter | `{connection}` | — | TCP connections accepted |
| `lure_handshake` | Counter | `{handshake}` | `state` | Handshake attempts (status or login) |
| `lure_handshake_fail` | Counter | `{handshake}` | `state` | Failed handshakes |
| `lure_handshake_duration` | Histogram | `ms` | `state` | Handshake round-trip time |

`state` values: `status` (status-ping), `login`.

#### Router metrics

| Metric | Type | Unit | Description |
|---|---|---|---|
| `lure_router_routes` | Gauge | `{route}` | Active configured routes |
| `lure_router_route_resolve` | Counter | `1` | Route lookups performed |
| `lure_router_sessions` | Gauge | `{session}` | Active proxy sessions |
| `lure_router_session_create` | Counter | `{session}` | Sessions created |
| `lure_router_session_destroy` | Counter | `{session}` | Sessions destroyed |

#### Proxy metrics

| Metric | Type | Unit | Attributes | Description |
|---|---|---|---|---|
| `lure_proxy_packet` | Counter | `{packet}` | `intent` | Packets during handshake |
| `lure_proxy_packet_size` | Histogram | `By` | `intent` | Packet size during handshake |
| `lure_proxy_transport_volume` | Counter | `By` | `intent` | Bytes transferred in passthrough |
| `lure_proxy_transport_packet` | Counter | `{packet}` | `intent` | Packets in passthrough |

`intent` values: `frontbound` / `backbound` (handshake); `c2s` / `s2c` (passthrough).

#### Tokio runtime metrics (stable)

Emitted every 30 seconds. Triplet metrics (`*_total`, `*_max`, `*_min`) report
three independent data points per interval.

| Metric | Type | Unit | Description |
|---|---|---|---|
| `lure_runtime_workers` | Gauge | `{thread}` | Worker thread count |
| `lure_runtime_park_total` | Gauge | `{park}` | Total worker park events |
| `lure_runtime_park_max` | Gauge | `{park}` | Max worker park events |
| `lure_runtime_park_min` | Gauge | `{park}` | Min worker park events |
| `lure_runtime_busy_duration_total` | Counter | `us` | Total cumulative busy time |
| `lure_runtime_busy_duration_max` | Counter | `us` | Busiest worker duration |
| `lure_runtime_busy_duration_min` | Counter | `us` | Least busy worker duration |
| `lure_runtime_queue_depth` | Gauge | `{task}` | Global task queue depth |

#### Tokio runtime metrics (unstable)

Requires `tokio_unstable` feature (enabled by default). Same reporting period as stable metrics.

| Metric | Type | Unit | Description |
|---|---|---|---|
| `lure_runtime_noop_total`, `*_max`, `*_min` | Counter | `{noop}` | No-op polls |
| `lure_runtime_steal_total`, `*_max`, `*_min` | Counter | `{steal}` | Tasks stolen between workers |
| `lure_runtime_steal_operations_total`, `*_max`, `*_min` | Counter | `{operation}` | Work-stealing operations |
| `lure_runtime_remote_schedule` | Counter | `{task}` | Tasks scheduled from outside |
| `lure_runtime_local_schedule_total`, `*_max`, `*_min` | Counter | `{task}` | Tasks on local queues |
| `lure_runtime_overflow_total`, `*_max`, `*_min` | Counter | `{overflow}` | Local queue overflows |
| `lure_runtime_polls_total`, `*_max`, `*_min` | Counter | `{poll}` | Future polls |
| `lure_runtime_local_queue_depth_total`, `*_max`, `*_min` | Gauge | `{task}` | Per-worker queue depth |
| `lure_runtime_blocking_queue_depth` | Gauge | `{task}` | Blocking task queue depth |
| `lure_runtime_tasks_live` | Gauge | `{task}` | Live (not dropped) tasks |
| `lure_runtime_threads_blocking` | Gauge | `{thread}` | Blocking thread pool size |
| `lure_runtime_threads_blocking_idle` | Gauge | `{thread}` | Idle blocking threads |
| `lure_runtime_budget_forced_yield` | Counter | `{yield}` | Budget-forced task yields |
| `lure_runtime_io_driver_ready` | Counter | `{event}` | I/O driver ready events |
| `lure_runtime_busy_ratio` | Gauge | `1` | Runtime busy fraction (0.0–1.0) |
| `lure_runtime_mean_polls_per_park` | Gauge | `{poll}` | Average polls between park events |

## Env Vars

- `LURE_RPC`: RPC backend URL (optional)
- `LURE_PROXY_SIGNING_KEY`: base64 Ed25519 private key for signing proxy headers (optional)
- `LURE_TUN_MASTER_URL`: override `tunnel.master_url` for slave forwarded-request mode
- `MINITUN_ENDPOINT`: endpoint for `minitun agent`
- `MINITUN_TOKENS`: comma/newline-separated `key_id:secret` list for singleton `minitun`
- `MINITUN_TOKEN`: single-token shorthand for `minitun`
- **OTLP / Observability:**
  - `OTEL_EXPORTER_OTLP_ENDPOINT`: gRPC/HTTP collector endpoint; enables both metrics and traces
  - `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT`: metrics-only collector (overrides `ENDPOINT`)
  - `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`: traces-only collector (overrides `ENDPOINT`)
  - `OTEL_METRIC_EXPORT_INTERVAL`: meter push interval in ms (default: 60000)
  - `OTEL_SERVICE_NAME`: service name resource attribute (default: `unknown-service`)
  - `OTEL_SERVICE_VERSION`: service version resource attribute (optional)
  - `OTEL_SERVICE_NAMESPACE`: service namespace resource attribute (optional)
  - `OTEL_SERVICE_INSTANCE_ID`: instance ID resource attribute (optional)
  - `OTEL_DEPLOYMENT_ENVIRONMENT`: deployment environment (optional)
  - `OTEL_RESOURCE_ATTRIBUTES`: comma-separated `key=value` pairs for custom resource attributes (optional)
- `LURE_ENABLE_TOKIO_CONSOLE=1`: enable Tokio console tracing subscriber
- `LURE_IO_EPOLL=1`: enable epoll backend (beta)
- `LURE_IO_URING=1`: enable tokio-uring backend (not recommended; requires `--features uring`)

## Compatibility / Quirks

- Works with old clients (1.7+) and includes Forge (FML) handshake handling.
- PROXY protocol support is v2.
- If you enable proxy protocol, also enable it on anything behind the proxy that needs to parse it
  (Paper/Velocity/Bungee/Geyser, etc).

## Development

- Build: `cargo build`
- Run: `cargo run`
- Test: `cargo test`
- Format: `cargo fmt`

## Credits

- Original implementor: [sammwyy](https://github.com/sammwyy)
