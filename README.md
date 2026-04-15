<p align="center">
  <img src="./assets/mach.svg" alt="Mach" width="160"/>
</p>

<h1 align="center">
  MACH
</h1>

<p align="center">
  <strong>The Minecraft ingress designed for high pressure under low resource.</strong>
</p>

<p align="center">
  <a href="https://github.com/illnet/mach"><img alt="Repo" src="https://img.shields.io/badge/repo-illnet%2Fmach-181717?style=for-the-badge&logo=github"></a>
  <a href="https://www.rust-lang.org/"><img alt="Rust nightly" src="https://img.shields.io/badge/rust-nightly-f74c00?style=for-the-badge&logo=rust"></a>
  <a href="https://www.docker.com/"><img alt="Docker yes" src="https://img.shields.io/badge/docker-yes-2496ed?style=for-the-badge&logo=docker&logoColor=white"></a>
  <a href="https://discord.gg/rs93smkSms"><img alt="Discord" src="https://img.shields.io/badge/discord-join%20chat-5865f2?style=for-the-badge&logo=discord&logoColor=white"></a>
</p>

> [!NOTE]
> `mach` is a fork from the original Lure, that were living under same Lure name. Founded into illnet. Contribution and member applicant is welcome <3. [Discord here](https://discord.gg/rs93smkSms)

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

Mach is a TCP proxy that speaks enough Minecraft to proxy and filter<sub>(not yet)</sub> connections without
turning the config into a second programming language.

Its only purpose is to correctly delivers the correct Minecraft server to the client, however it
could be used to against quite the basic threats.

Can be configured with a yet-not-quite-friendly controller. However, we have a nice GUI to actually
control. If you really interested, you can be the early-adopter by contacting Discord @stdpi.

## Performance tuning

You can choose one of the connection backends that suits your use.

- **tokio**: Stable, quite fast polling and scales on multiple cores.
- **epoll**: Beta (Linux-only), the way HAProxy delivers million packets. Enable with `MACH_IO_EPOLL=1`

## Features

- Multi-route and multi-endpoint routing (single or multiple matchers/endpoints), load balancing
- Optional RPC control plane for orchestration
- PROXY protocol support, with signing authorization from proxy, implemented with [BetterProxyProtocol](https://github.com/LangDuaMC/BetterProxyProtocol)
- OTEL metrics observation
- Basic connection rate limiting, and risky IP filtering in the future.
- TCP tunnel agent (beta) to connect with the most efficient overhead

## Quick Start

```bash
cargo run
```

Reads `settings.toml` from the current directory. If it does not exist, Mach will generate one.
The generated default binds to `0.0.0.0:25577`.

Reload config on `SIGCONT`:

```bash
kill -CONT <pid>
```

Optional RPC backend (orchestration): set `MACH_RPC` (`MACH_RPC`).

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
MACH_IO_EPOLL=1 cargo run
```

## Tunneling (Beta)

NAT passthrough via `minitun`, a lightweight tunnel agent. Supports multi-endpoint failover, hot-reload, and TOML config.

- **Agent docs:** [`tun/README.md`](tun/README.md)
- **Wire protocol & security:** [`docs/tunnel.md`](docs/tunnel.md)

## Observability (OTLP)

Mach exports metrics and traces via OpenTelemetry Protocol (OTLP).

### Enabling export

Set `OTEL_EXPORTER_OTLP_ENDPOINT` to your collector address:

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318 ./mach
```

Per-signal overrides are also supported:

```bash
OTEL_EXPORTER_OTLP_METRICS_ENDPOINT=http://otel-collector:4318/v1/metrics
OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://otel-collector:4317
```

Default protocol is `http/protobuf`. The meter and tracer scope name is `mach` (kept for compatibility).

### Metric reference

All metric names use underscores. Units are specified via OTel `.with_unit()`;
exported metrics include unit annotations (e.g. `{packet}`, `By`, `ms`, `us`).

#### Handshake metrics

| Metric | Type | Unit | Attributes | Description |
|---|---|---|---|---|
| `mach_socket_open` | Counter | `{connection}` | — | TCP connections accepted |
| `mach_handshake` | Counter | `{handshake}` | `state` | Handshake attempts (status or login) |
| `mach_handshake_fail` | Counter | `{handshake}` | `state` | Failed handshakes |
| `mach_handshake_duration` | Histogram | `ms` | `state` | Handshake round-trip time |

`state` values: `status` (status-ping), `login`.

#### Router metrics

| Metric | Type | Unit | Description |
|---|---|---|---|
| `mach_router_routes` | Gauge | `{route}` | Active configured routes |
| `mach_router_route_resolve` | Counter | `1` | Route lookups performed |
| `mach_router_sessions` | Gauge | `{session}` | Active proxy sessions |
| `mach_router_session_create` | Counter | `{session}` | Sessions created |
| `mach_router_session_destroy` | Counter | `{session}` | Sessions destroyed |

#### Proxy metrics

| Metric | Type | Unit | Attributes | Description |
|---|---|---|---|---|
| `mach_proxy_packet` | Counter | `{packet}` | `intent` | Packets during handshake |
| `mach_proxy_packet_size` | Histogram | `By` | `intent` | Packet size during handshake |
| `mach_proxy_transport_volume` | Counter | `By` | `intent` | Bytes transferred in passthrough |
| `mach_proxy_transport_packet` | Counter | `{packet}` | `intent` | Packets in passthrough |

`intent` values: `frontbound` / `backbound` (handshake); `c2s` / `s2c` (passthrough).

#### Tokio runtime metrics (stable)

Emitted every 30 seconds. Triplet metrics (`*_total`, `*_max`, `*_min`) report
three independent data points per interval.

| Metric | Type | Unit | Description |
|---|---|---|---|
| `mach_runtime_workers` | Gauge | `{thread}` | Worker thread count |
| `mach_runtime_park_total` | Gauge | `{park}` | Total worker park events |
| `mach_runtime_park_max` | Gauge | `{park}` | Max worker park events |
| `mach_runtime_park_min` | Gauge | `{park}` | Min worker park events |
| `mach_runtime_busy_duration_total` | Counter | `us` | Total cumulative busy time |
| `mach_runtime_busy_duration_max` | Counter | `us` | Busiest worker duration |
| `mach_runtime_busy_duration_min` | Counter | `us` | Least busy worker duration |
| `mach_runtime_queue_depth` | Gauge | `{task}` | Global task queue depth |

#### Tokio runtime metrics (unstable)

Requires `tokio_unstable` feature (enabled by default). Same reporting period as stable metrics.

| Metric | Type | Unit | Description |
|---|---|---|---|
| `mach_runtime_noop_total`, `*_max`, `*_min` | Counter | `{noop}` | No-op polls |
| `mach_runtime_steal_total`, `*_max`, `*_min` | Counter | `{steal}` | Tasks stolen between workers |
| `mach_runtime_steal_operations_total`, `*_max`, `*_min` | Counter | `{operation}` | Work-stealing operations |
| `mach_runtime_remote_schedule` | Counter | `{task}` | Tasks scheduled from outside |
| `mach_runtime_local_schedule_total`, `*_max`, `*_min` | Counter | `{task}` | Tasks on local queues |
| `mach_runtime_overflow_total`, `*_max`, `*_min` | Counter | `{overflow}` | Local queue overflows |
| `mach_runtime_polls_total`, `*_max`, `*_min` | Counter | `{poll}` | Future polls |
| `mach_runtime_local_queue_depth_total`, `*_max`, `*_min` | Gauge | `{task}` | Per-worker queue depth |
| `mach_runtime_blocking_queue_depth` | Gauge | `{task}` | Blocking task queue depth |
| `mach_runtime_tasks_live` | Gauge | `{task}` | Live (not dropped) tasks |
| `mach_runtime_threads_blocking` | Gauge | `{thread}` | Blocking thread pool size |
| `mach_runtime_threads_blocking_idle` | Gauge | `{thread}` | Idle blocking threads |
| `mach_runtime_budget_forced_yield` | Counter | `{yield}` | Budget-forced task yields |
| `mach_runtime_io_driver_ready` | Counter | `{event}` | I/O driver ready events |
| `mach_runtime_busy_ratio` | Gauge | `1` | Runtime busy fraction (0.0–1.0) |
| `mach_runtime_mean_polls_per_park` | Gauge | `{poll}` | Average polls between park events |

## Env Vars

- `MACH_RPC` : RPC backend URL (optional)
- `MACH_PROXY_SIGNING_KEY` : base64 Ed25519 private key for signing proxy headers (optional)
- `MACH_TUN_MASTER_URL` : override `tunnel.master_url` for slave forwarded-request mode
- `MINITUN_ENDPOINT`: endpoint for `minitun agent`
- `MINITUN_TOKENS`: comma/newline-separated `key_id:secret` list for singleton `minitun`
- `MINITUN_TOKEN`: single-token shorthand for `minitun`
- `MACH_NOSENTRY=1` (or legacy `MACH_NOSENTRY=1`): disable Sentry
- `MACH_SENTRY_ENV`: Sentry environment override (`MACH_SENTRY_ENV`)
- `MACH_ENFORCE_LOCAL_BLOCK=1` : block local/private IP forwards
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
- `MACH_ENABLE_TOKIO_CONSOLE=1`: enable Tokio console tracing subscriber
- `MACH_IO_EPOLL=1`: enable epoll backend (beta)

## Compatibility / Quirks

- Works with old clients (1.7+) and includes Forge (FML) handshake handling.
- PROXY protocol support is v2.
- If you enable proxy protocol, also enable it on anything behind the proxy that needs to parse it
  (Paper/Velocity/Bungee/Geyser, etc).

## Development

- Build: `cargo build`
- Run: `cargo run` (default binary: `mach`)
- Test: `cargo test`
- Format: `cargo fmt`

## Credits

- Original implementor: [sammwyy](https://github.com/sammwyy)
