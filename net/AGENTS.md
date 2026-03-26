# Repository Guidelines

## Project Structure & Module Organization
- `src/lib.rs` is the crate entrypoint and public export surface.
- `src/mc/` contains Minecraft protocol codecs, packet types, state handling, and protocol tests.
- `src/ha/` contains HAProxy protocol parsing helpers.
- `src/sock/` contains Linux-focused socket backends and support code for `tokio`, `epoll`, `io_uring`, and eBPF paths.
- `benches/mc.rs` and `benches/ha.rs` hold Criterion benchmarks for hot parsing and transport paths.
- `build.rs` compiles native support code; keep Rust/C interface changes tightly synchronized.

## Build, Test, and Development Commands
- `cargo build -p net` builds the crate with the pinned nightly toolchain.
- `cargo test -p net` runs inline/unit coverage, including protocol tests under `src/mc/tests.rs`.
- `cargo bench -p net` runs Criterion benches; use this before and after performance-sensitive parser or socket changes.
- `cargo clippy -p net --all-targets --all-features` checks common correctness and maintainability issues.
- `cargo fmt -p net` formats Rust code using workspace `rustfmt` settings.
- `cargo test -p net --features uring` or `--features ebpf` should be used only when touching those feature-gated paths.

## Coding Style & Naming Conventions
- Follow workspace `.editorconfig`: 4-space indentation, LF endings, and 100-column Rust lines.
- `rustfmt` uses crate-granular imports with grouped standard/external crates; do not hand-format around it.
- Keep modules `snake_case`, types `UpperCamelCase`, constants `SCREAMING_SNAKE_CASE`.
- Prefer small, explicit parsing and I/O helpers over clever abstractions in hot paths.
- Document public APIs and non-obvious invariants, especially packet framing, buffer ownership, unsafe blocks, and kernel-facing assumptions.

## Testing, Performance, and Guardrails
- Add or update tests for every protocol bugfix, edge-case decoder change, and socket state transition.
- Actively search for existing patterns before editing: reuse established encoder/decoder shapes, error mapping, and feature gating instead of introducing parallel styles.
- Avoid common pitfalls: silent packet truncation, unchecked length math, partial-read assumptions, backend-specific behavior drift, and unsound FFI or unsafe shortcuts.
- For performance work, verify with benches or targeted measurements; avoid allocating, copying, or logging inside hot loops unless justified.
- Keep changes narrow and clean: remove dead paths, note feature interactions, and update docs/comments when behavior or invariants change.

## Commit & Review Guidelines
- Recent history favors conventional prefixes such as `feat:`, `fix:`, `build:`, `ci:`, and `chore:`.
- Keep commit subjects short and imperative.
- PRs should summarize behavior changes, list feature flags affected, and include test or benchmark evidence for parser/socket changes.
