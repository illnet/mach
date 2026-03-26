#[cfg(all(target_os = "linux", feature = "ebpf"))]
pub mod ebpf;
pub mod tokio;
#[cfg(not(all(target_os = "linux", feature = "ebpf")))]
pub mod ebpf {
    #[cfg(unix)]
    use std::os::fd::RawFd;
    use std::{io, sync::Arc};
    #[cfg(not(unix))]
    type RawFd = i32;

    #[derive(Debug, Default, Clone, Copy)]
    pub struct EbpfStats {
        pub loop_polls: u64,
        pub disconnect_events: u64,
    }

    #[derive(Default)]
    pub struct EbpfProgress;

    impl EbpfProgress {
        pub fn snapshot(&self) -> EbpfStats {
            EbpfStats::default()
        }
    }

    #[derive(Debug, Default, Clone, Copy)]
    pub struct EbpfDone {
        pub result: i32,
        pub stats: EbpfStats,
    }

    #[must_use]
    pub fn ebpf_enabled() -> bool {
        false
    }

    pub fn offload_pair_and_wait(_fd_a: RawFd, _fd_b: RawFd) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "eBPF offload is unsupported on this build target",
        ))
    }

    pub fn spawn_pair_observed(
        _fd_a: RawFd,
        _fd_b: RawFd,
    ) -> io::Result<(tokio::sync::oneshot::Receiver<EbpfDone>, Arc<EbpfProgress>)> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "eBPF offload is unsupported on this build target",
        ))
    }
}
// Linux-only backends.
//
// On non-Linux platforms we provide small compatibility shims so the crate
// continues to compile and callers can still match on BackendKind values.
#[cfg(target_os = "linux")]
pub mod epoll;
#[cfg(not(target_os = "linux"))]
pub mod epoll {
    use std::{io, net::SocketAddr};

    pub(crate) fn probe() -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "epoll backend is only supported on linux",
        ))
    }

    pub struct Listener {
        inner: crate::sock::tokio::Listener,
    }

    impl Listener {
        pub(crate) async fn bind(addr: SocketAddr) -> io::Result<Self> {
            Ok(Self {
                inner: crate::sock::tokio::Listener::bind(addr).await?,
            })
        }

        pub(crate) async fn accept(&self) -> io::Result<(Connection, SocketAddr)> {
            let (conn, addr) = self.inner.accept().await?;
            Ok((Connection { inner: conn }, addr))
        }

        pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
            self.inner.local_addr()
        }
    }

    pub struct Connection {
        pub(crate) inner: crate::sock::tokio::Connection,
    }

    impl Connection {
        pub(crate) async fn connect(addr: SocketAddr) -> io::Result<Self> {
            Ok(Self {
                inner: crate::sock::tokio::Connection::connect(addr).await?,
            })
        }

        pub fn addr(&self) -> &SocketAddr {
            self.inner.addr()
        }

        pub fn peer_addr(&self) -> io::Result<SocketAddr> {
            self.inner.peer_addr()
        }

        pub fn local_addr(&self) -> io::Result<SocketAddr> {
            self.inner.local_addr()
        }

        pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
            self.inner.set_nodelay(nodelay)
        }

        pub(crate) async fn read_chunk(&mut self, buf: Vec<u8>) -> io::Result<(usize, Vec<u8>)> {
            self.inner.read_chunk(buf).await
        }

        pub(crate) async fn write_all(&mut self, buf: Vec<u8>) -> io::Result<Vec<u8>> {
            self.inner.write_all(buf).await
        }

        pub(crate) async fn flush(&mut self) -> io::Result<()> {
            self.inner.flush().await
        }

        pub(crate) fn try_read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.inner.try_read(buf)
        }

        pub(crate) async fn shutdown(&mut self) -> io::Result<()> {
            self.inner.shutdown().await
        }

        pub(crate) fn raw_fd(&self) -> Option<i32> {
            self.inner.raw_fd()
        }

        pub(crate) fn into_proxy_inner(
            self,
            peer: Box<dyn crate::sock::Sock>,
        ) -> io::Result<crate::sock::ProxyHandle> {
            self.inner.into_proxy(peer)
        }
    }

    pub async fn passthrough_basic(a: &mut Connection, b: &mut Connection) -> io::Result<()> {
        crate::sock::tokio::passthrough_basic(&mut a.inner, &mut b.inner).await
    }
}

#[cfg(all(target_os = "linux", feature = "uring"))]
pub mod uring;
#[cfg(not(all(target_os = "linux", feature = "uring")))]
pub mod uring {
    use std::{future::Future, io, net::SocketAddr};

    use tokio::net::{TcpListener, TcpStream};

    pub(crate) fn probe() -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            if cfg!(target_os = "linux") {
                "io_uring backend is disabled at compile time (enable net feature `uring`)"
            } else {
                "io_uring backend is only supported on linux"
            },
        ))
    }

    pub fn spawn<F>(future: F) -> tokio::task::JoinHandle<F::Output>
    where
        // tokio-uring spawns !Send tasks on a LocalSet. Keep the same surface
        // area so callers don't need extra bounds.
        F: Future + 'static,
        F::Output: 'static,
    {
        tokio::task::spawn_local(future)
    }

    pub fn start<F>(future: F) -> F::Output
    where
        // tokio-uring runs a single-threaded runtime that supports !Send tasks.
        // Keep the same API shape so callers can use LocalSet / trait objects.
        F: Future + 'static,
        F::Output: 'static,
    {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to build tokio runtime")
            .block_on(future)
    }

    pub struct Listener {
        inner: TcpListener,
    }

    impl Listener {
        pub(crate) fn bind(addr: SocketAddr) -> io::Result<Self> {
            let std_listener = std::net::TcpListener::bind(addr)?;
            std_listener.set_nonblocking(true)?;
            let inner = TcpListener::from_std(std_listener)?;
            Ok(Self { inner })
        }

        pub(crate) async fn accept(&self) -> io::Result<(Connection, SocketAddr)> {
            let (stream, addr) = self.inner.accept().await?;
            Ok((Connection::new(stream, addr), addr))
        }

        pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
            self.inner.local_addr()
        }
    }

    pub struct Connection {
        pub(crate) stream: TcpStream,
        addr: SocketAddr,
    }

    impl Connection {
        pub(crate) async fn connect(addr: SocketAddr) -> io::Result<Self> {
            let stream = TcpStream::connect(addr).await?;
            let addr = stream.peer_addr()?;
            Ok(Self { stream, addr })
        }

        pub(crate) fn new(stream: TcpStream, addr: SocketAddr) -> Self {
            Self { stream, addr }
        }

        pub fn addr(&self) -> &SocketAddr {
            &self.addr
        }

        pub fn peer_addr(&self) -> io::Result<SocketAddr> {
            self.stream.peer_addr()
        }

        pub fn local_addr(&self) -> io::Result<SocketAddr> {
            self.stream.local_addr()
        }

        pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
            self.stream.set_nodelay(nodelay)
        }

        pub(crate) async fn read_chunk(
            &mut self,
            mut buf: Vec<u8>,
        ) -> io::Result<(usize, Vec<u8>)> {
            use tokio::io::AsyncReadExt;
            let n = self.stream.read(&mut buf).await?;
            Ok((n, buf))
        }

        pub(crate) async fn write_all(&mut self, buf: Vec<u8>) -> io::Result<Vec<u8>> {
            use tokio::io::AsyncWriteExt;
            self.stream.write_all(buf.as_slice()).await?;
            Ok(buf)
        }

        pub(crate) async fn flush(&mut self) -> io::Result<()> {
            use tokio::io::AsyncWriteExt;
            self.stream.flush().await
        }

        pub(crate) fn try_read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.stream.try_read(buf)
        }

        pub(crate) async fn shutdown(&mut self) -> io::Result<()> {
            use tokio::io::AsyncWriteExt;
            self.stream.shutdown().await
        }

        pub(crate) fn raw_fd(&self) -> Option<i32> {
            #[cfg(unix)]
            {
                use std::os::fd::AsRawFd;
                Some(self.stream.as_raw_fd())
            }
            #[cfg(not(unix))]
            {
                None
            }
        }

        pub(crate) fn into_proxy_inner(
            self,
            peer: Box<dyn crate::sock::Sock>,
        ) -> io::Result<crate::sock::ProxyHandle> {
            // Fall back to the tokio copy path for uring connections.
            let conn = crate::sock::tokio::Connection::new(self.stream, self.addr);
            conn.into_proxy(peer)
        }
    }

    pub async fn passthrough_basic(a: &mut Connection, b: &mut Connection) -> io::Result<()> {
        let (mut a_read, mut a_write) = a.stream.split();
        let (mut b_read, mut b_write) = b.stream.split();

        let a_to_b = tokio::io::copy(&mut a_read, &mut b_write);
        let b_to_a = tokio::io::copy(&mut b_read, &mut a_write);
        let _ = tokio::try_join!(a_to_b, b_to_a)?;
        Ok(())
    }
}

use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};

// ── Backend selection ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    Tokio,
    Epoll,
    Uring,
}

#[derive(Debug, Clone)]
pub struct BackendSelection {
    pub kind: BackendKind,
    pub reason: String,
}

static BACKEND_SELECTION: OnceLock<BackendSelection> = OnceLock::new();

#[must_use]
pub fn backend_kind() -> BackendKind {
    backend_selection().kind
}

pub fn backend_selection() -> &'static BackendSelection {
    let override_env = std::env::var("LURE_IO_EPOLL")
        .ok()
        .or_else(|| std::env::var("NET_IO_EPOLL").ok());
    let uring_override = std::env::var("LURE_IO_URING")
        .ok()
        .or_else(|| std::env::var("NET_IO_URING").ok());
    BACKEND_SELECTION.get_or_init(|| match override_env.as_deref() {
        Some("0") => BackendSelection {
            kind: BackendKind::Tokio,
            reason: "LURE_IO_EPOLL=0 (forced tokio)".to_string(),
        },
        Some("1") => match epoll::probe() {
            Ok(()) => BackendSelection {
                kind: BackendKind::Epoll,
                reason: "LURE_IO_EPOLL=1 and epoll available".to_string(),
            },
            Err(err) => BackendSelection {
                kind: BackendKind::Tokio,
                reason: format!("LURE_IO_EPOLL=1 but {err}"),
            },
        },
        _ => match uring_override.as_deref() {
            Some("1") => match uring::probe() {
                Ok(()) => BackendSelection {
                    kind: BackendKind::Uring,
                    reason: "LURE_IO_URING=1 (explicit) and io_uring available".to_string(),
                },
                Err(err) => BackendSelection {
                    kind: BackendKind::Tokio,
                    reason: format!("LURE_IO_URING=1 but {err}"),
                },
            },
            Some("0") => BackendSelection {
                kind: BackendKind::Tokio,
                reason: "LURE_IO_URING=0 (forced tokio)".to_string(),
            },
            _ => BackendSelection {
                kind: BackendKind::Tokio,
                reason: "default tokio (io_uring probe disabled)".to_string(),
            },
        },
    })
}

// ── Internal enum types (kept for passthrough_basic tests) ───────────────────

pub enum Listener {
    Tokio(tokio::Listener),
    Epoll(epoll::Listener),
    Uring(uring::Listener),
}

impl Listener {
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        match backend_kind() {
            BackendKind::Tokio => Ok(Self::Tokio(tokio::Listener::bind(addr).await?)),
            BackendKind::Epoll => Ok(Self::Epoll(epoll::Listener::bind(addr).await?)),
            BackendKind::Uring => Ok(Self::Uring(uring::Listener::bind(addr)?)),
        }
    }

    pub async fn accept(&self) -> io::Result<(Connection, SocketAddr)> {
        match self {
            Self::Tokio(listener) => {
                let (conn, addr) = listener.accept().await?;
                Ok((Connection::Tokio(conn), addr))
            }
            Self::Epoll(listener) => {
                let (conn, addr) = listener.accept().await?;
                Ok((Connection::Epoll(conn), addr))
            }
            Self::Uring(listener) => {
                let (conn, addr) = listener.accept().await?;
                Ok((Connection::Uring(conn), addr))
            }
        }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Tokio(listener) => listener.local_addr(),
            Self::Epoll(listener) => listener.local_addr(),
            Self::Uring(listener) => listener.local_addr(),
        }
    }
}

pub enum Connection {
    Tokio(tokio::Connection),
    Epoll(epoll::Connection),
    Uring(uring::Connection),
}

impl Connection {
    pub async fn connect(addr: SocketAddr) -> io::Result<Self> {
        match backend_kind() {
            BackendKind::Tokio => Ok(Self::Tokio(tokio::Connection::connect(addr).await?)),
            BackendKind::Epoll => Ok(Self::Epoll(epoll::Connection::connect(addr).await?)),
            BackendKind::Uring => Ok(Self::Uring(uring::Connection::connect(addr).await?)),
        }
    }

    pub const fn backend_kind(&self) -> BackendKind {
        match self {
            Self::Tokio(_) => BackendKind::Tokio,
            Self::Epoll(_) => BackendKind::Epoll,
            Self::Uring(_) => BackendKind::Uring,
        }
    }

    pub fn addr(&self) -> &SocketAddr {
        match self {
            Self::Tokio(conn) => conn.addr(),
            Self::Epoll(conn) => conn.addr(),
            Self::Uring(conn) => conn.addr(),
        }
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Tokio(conn) => conn.peer_addr(),
            Self::Epoll(conn) => conn.peer_addr(),
            Self::Uring(conn) => conn.peer_addr(),
        }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Tokio(conn) => conn.local_addr(),
            Self::Epoll(conn) => conn.local_addr(),
            Self::Uring(conn) => conn.local_addr(),
        }
    }

    pub async fn read_chunk(&mut self, buf: Vec<u8>) -> io::Result<(usize, Vec<u8>)> {
        match self {
            Self::Tokio(conn) => conn.read_chunk(buf).await,
            Self::Epoll(conn) => conn.read_chunk(buf).await,
            Self::Uring(conn) => conn.read_chunk(buf).await,
        }
    }

    pub async fn write_all(&mut self, buf: Vec<u8>) -> io::Result<Vec<u8>> {
        match self {
            Self::Tokio(conn) => conn.write_all(buf).await,
            Self::Epoll(conn) => conn.write_all(buf).await,
            Self::Uring(conn) => conn.write_all(buf).await,
        }
    }

    pub async fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Tokio(conn) => conn.flush().await,
            Self::Epoll(conn) => conn.flush().await,
            Self::Uring(conn) => conn.flush().await,
        }
    }

    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        match self {
            Self::Tokio(conn) => conn.set_nodelay(nodelay),
            Self::Epoll(conn) => conn.set_nodelay(nodelay),
            Self::Uring(conn) => conn.set_nodelay(nodelay),
        }
    }

    pub fn try_read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tokio(conn) => conn.try_read(buf),
            Self::Epoll(conn) => conn.try_read(buf),
            Self::Uring(conn) => conn.try_read(buf),
        }
    }

    pub async fn shutdown(&mut self) -> io::Result<()> {
        match self {
            Self::Tokio(conn) => conn.shutdown().await,
            Self::Epoll(conn) => conn.shutdown().await,
            Self::Uring(conn) => conn.shutdown().await,
        }
    }

    pub fn raw_fd(&self) -> Option<i32> {
        match self {
            Self::Tokio(conn) => conn.raw_fd(),
            Self::Epoll(conn) => conn.raw_fd(),
            Self::Uring(conn) => conn.raw_fd(),
        }
    }
}

pub async fn passthrough_basic(a: &mut Connection, b: &mut Connection) -> io::Result<()> {
    match (a, b) {
        (Connection::Tokio(a), Connection::Tokio(b)) => tokio::passthrough_basic(a, b).await,
        (Connection::Epoll(a), Connection::Epoll(b)) => epoll::passthrough_basic(a, b).await,
        (Connection::Uring(a), Connection::Uring(b)) => uring::passthrough_basic(a, b).await,
        _ => Err(io::Error::other(
            "mismatched connection backends for passthrough",
        )),
    }
}

// ── Proxy completion types ────────────────────────────────────────────────────

/// Final byte/chunk counters for a completed proxy session.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProxyStats {
    pub c2s_bytes: u64,
    pub s2c_bytes: u64,
    pub c2s_chunks: u64,
    pub s2c_chunks: u64,
}

/// Live-updatable progress counters for an in-flight proxy session.
///
/// Updated with `Relaxed` ordering — values are approximate and intended for
/// monitoring (OTEL metrics), not synchronization.
#[derive(Default)]
pub struct ProxyProgress {
    pub c2s_bytes: AtomicU64,
    pub s2c_bytes: AtomicU64,
    pub c2s_chunks: AtomicU64,
    pub s2c_chunks: AtomicU64,
}

impl ProxyProgress {
    /// Snapshot current counters (approximate).
    pub fn snapshot(&self) -> ProxyStats {
        ProxyStats {
            c2s_bytes: self.c2s_bytes.load(Ordering::Relaxed),
            s2c_bytes: self.s2c_bytes.load(Ordering::Relaxed),
            c2s_chunks: self.c2s_chunks.load(Ordering::Relaxed),
            s2c_chunks: self.s2c_chunks.load(Ordering::Relaxed),
        }
    }
}

/// Handle for a proxy session started by [`Sock::into_proxy`].
///
/// Drive `future` to completion to run the proxy. Poll `progress` for live
/// byte counters (updated approximately every 100 ms for epoll, per-chunk for
/// tokio).
pub struct ProxyHandle {
    /// Resolves with final stats when both sides close.
    pub future: Pin<Box<dyn Future<Output = io::Result<ProxyStats>> + Send + 'static>>,
    /// Live progress counters; safe to poll from any thread at any time.
    pub progress: Arc<ProxyProgress>,
}

// ── Sock trait ────────────────────────────────────────────────────────────────

/// A transport socket that can participate in the proxy lifecycle.
///
/// Object-safe: all async methods return `Pin<Box<dyn Future>>`. The
/// `into_proxy` method uses a `Box<Self>` receiver, which Rust supports for
/// trait objects without any nightly features.
///
/// The global entry point is [`LureNet::global`], which picks the backend
/// automatically based on environment variables.
pub trait Sock: Send + 'static {
    fn backend_kind(&self) -> BackendKind;
    fn peer_addr(&self) -> io::Result<SocketAddr>;
    fn local_addr(&self) -> io::Result<SocketAddr>;
    fn set_nodelay(&self, nodelay: bool) -> io::Result<()>;
    /// Raw OS file descriptor number, or `None` on non-Unix platforms.
    fn raw_fd(&self) -> Option<i32>;
    fn try_read(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    fn read_chunk<'a>(
        &'a mut self,
        buf: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = io::Result<(usize, Vec<u8>)>> + Send + 'a>>;
    fn write_all<'a>(
        &'a mut self,
        buf: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + Send + 'a>>;
    fn flush<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>>;
    fn shutdown<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>>;
    /// Consume both sockets and begin bidirectional proxying.
    ///
    /// Returns a [`ProxyHandle`] immediately; drive `handle.future` to run the
    /// proxy to completion.
    fn into_proxy(self: Box<Self>, peer: Box<dyn Sock>) -> io::Result<ProxyHandle>;
}

impl Sock for Connection {
    fn backend_kind(&self) -> BackendKind {
        Self::backend_kind(self)
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Self::peer_addr(self)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Self::local_addr(self)
    }

    fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        Self::set_nodelay(self, nodelay)
    }

    fn raw_fd(&self) -> Option<i32> {
        Self::raw_fd(self)
    }

    fn try_read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        Self::try_read(self, buf)
    }

    fn read_chunk<'a>(
        &'a mut self,
        buf: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = io::Result<(usize, Vec<u8>)>> + Send + 'a>> {
        Box::pin(async move { Self::read_chunk(self, buf).await })
    }

    fn write_all<'a>(
        &'a mut self,
        buf: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + Send + 'a>> {
        Box::pin(async move { Self::write_all(self, buf).await })
    }

    fn flush<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async move { Self::flush(self).await })
    }

    fn shutdown<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async move { Self::shutdown(self).await })
    }

    fn into_proxy(self: Box<Self>, peer: Box<dyn Sock>) -> io::Result<ProxyHandle> {
        match *self {
            Connection::Tokio(conn) => conn.into_proxy(peer),
            // Linux: real epoll::Connection has its own into_proxy via Sock impl.
            // Non-Linux shim: into_proxy_inner delegates to the inner tokio::Connection.
            #[cfg(target_os = "linux")]
            Connection::Epoll(conn) => {
                <epoll::Connection as Sock>::into_proxy(Box::new(conn), peer)
            }
            #[cfg(not(target_os = "linux"))]
            Connection::Epoll(conn) => conn.into_proxy_inner(peer),
            Connection::Uring(conn) => conn.into_proxy_inner(peer),
        }
    }
}

// ── OS FD utilities ───────────────────────────────────────────────────────────

/// Duplicate a file descriptor (Unix only).
#[cfg(unix)]
pub fn duplicate_fd(fd: i32) -> io::Result<i32> {
    let rc = unsafe { libc::dup(fd) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(rc)
}

// ── LureNet ───────────────────────────────────────────────────────────────────

/// Singleton network manager. Picks the I/O backend once on first access and
/// exposes a unified API for accepting and connecting to TCP sockets.
///
/// Backend selection is controlled by environment variables:
/// - `LURE_IO_EPOLL=1` — use the epoll backend (Linux only)
/// - `LURE_IO_URING=1` — use io_uring (Linux, compile with feature `uring`)
/// - `LURE_IO_EPOLL=0` or neither — default Tokio backend
pub struct LureNet {
    backend: BackendKind,
}

static LURE_NET: OnceLock<LureNet> = OnceLock::new();

impl LureNet {
    /// Returns a reference to the global `LureNet` singleton, initialising it
    /// on first call.
    pub fn global() -> &'static Self {
        LURE_NET.get_or_init(|| {
            let backend = backend_kind();
            log::debug!(
                "LureNet: backend={backend:?} ({})",
                backend_selection().reason
            );
            Self { backend }
        })
    }

    /// Bind a TCP listener on `addr` using the selected backend.
    pub async fn bind(&self, addr: SocketAddr) -> io::Result<LureListener> {
        LureListener::bind(addr).await
    }

    /// Connect to `addr` using the selected backend, returning a `Box<dyn Sock>`.
    pub async fn connect(&self, addr: SocketAddr) -> io::Result<Box<dyn Sock>> {
        let conn = Connection::connect(addr).await?;
        Ok(Box::new(conn))
    }

    /// The backend that was selected.
    pub fn backend(&self) -> BackendKind {
        self.backend
    }
}

// ── LureListener ──────────────────────────────────────────────────────────────

/// A TCP listener that produces [`LureConnection`]s using the selected backend.
pub struct LureListener(Listener);

impl LureListener {
    /// Bind to `addr` using the selected I/O backend.
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        Ok(Self(Listener::bind(addr).await?))
    }

    /// Accept the next incoming connection.
    pub async fn accept(&self) -> io::Result<(LureConnection, SocketAddr)> {
        let (conn, addr) = self.0.accept().await?;
        Ok((LureConnection::from_conn(conn, addr), addr))
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }
}

// ── LureConnection ────────────────────────────────────────────────────────────

/// A backend-agnostic TCP connection.
///
/// The concrete I/O backend is hidden behind `Box<dyn Sock>`. Call
/// [`LureConnection::into_proxy`] to start bidirectional forwarding between
/// two connections.
pub struct LureConnection {
    inner: Box<dyn Sock>,
    /// Peer address captured at connection time (avoids repeated syscalls).
    addr: SocketAddr,
}

impl LureConnection {
    fn from_conn(conn: Connection, addr: SocketAddr) -> Self {
        Self {
            inner: Box::new(conn),
            addr,
        }
    }

    /// Connect to `addr` using the global backend.
    pub async fn connect(addr: SocketAddr) -> io::Result<Self> {
        let conn = Connection::connect(addr).await?;
        let actual_addr = conn.peer_addr().unwrap_or(addr);
        Ok(Self {
            inner: Box::new(conn),
            addr: actual_addr,
        })
    }

    pub fn backend_kind(&self) -> BackendKind {
        self.inner.backend_kind()
    }

    /// Peer socket address captured when the connection was established.
    pub fn addr(&self) -> &SocketAddr {
        &self.addr
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr()
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.inner.set_nodelay(nodelay)
    }

    pub fn try_read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.try_read(buf)
    }

    pub async fn read_chunk(&mut self, buf: Vec<u8>) -> io::Result<(usize, Vec<u8>)> {
        self.inner.read_chunk(buf).await
    }

    pub async fn write_all(&mut self, buf: Vec<u8>) -> io::Result<Vec<u8>> {
        self.inner.write_all(buf).await
    }

    pub async fn flush(&mut self) -> io::Result<()> {
        self.inner.flush().await
    }

    pub async fn shutdown(&mut self) -> io::Result<()> {
        self.inner.shutdown().await
    }

    /// Consume both connections and begin bidirectional proxying.
    ///
    /// Returns a [`ProxyHandle`] immediately; drive `handle.future` to
    /// completion to run the proxy.
    pub fn into_proxy(self, peer: LureConnection) -> io::Result<ProxyHandle> {
        self.inner.into_proxy(peer.inner)
    }
}
