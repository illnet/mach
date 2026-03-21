use std::{
    io,
    net::SocketAddr,
    os::fd::{AsRawFd, RawFd},
    ptr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering},
    },
    thread,
};

use libc::{c_int, c_void, close, dup};
use tokio::{
    net::{TcpListener, TcpStream},
    time::{Duration, sleep},
};

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct EpollDone {
    pub id: u64,
    pub stats: EpollStats,
    pub result: c_int,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct EpollStats {
    pub c2s_bytes: u64,
    pub s2c_bytes: u64,
    pub c2s_chunks: u64,
    pub s2c_chunks: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct LureEpollShared {
    fd_a: c_int,
    fd_b: c_int,
    c2s_bytes: u64,
    s2c_bytes: u64,
    c2s_chunks: u64,
    s2c_chunks: u64,
    result: c_int,
    state_flags: u32,
    abort_flag: u32,
}

impl LureEpollShared {
    const fn new(fd_a: c_int, fd_b: c_int) -> Self {
        Self {
            fd_a,
            fd_b,
            c2s_bytes: 0,
            s2c_bytes: 0,
            c2s_chunks: 0,
            s2c_chunks: 0,
            result: 0,
            state_flags: 0,
            abort_flag: 0,
        }
    }

    unsafe fn stats_volatile(&self) -> EpollStats {
        EpollStats {
            c2s_bytes: unsafe { ptr::read_volatile(&raw const self.c2s_bytes) },
            s2c_bytes: unsafe { ptr::read_volatile(&raw const self.s2c_bytes) },
            c2s_chunks: unsafe { ptr::read_volatile(&raw const self.c2s_chunks) },
            s2c_chunks: unsafe { ptr::read_volatile(&raw const self.s2c_chunks) },
        }
    }

    unsafe fn state_flags_volatile(&self) -> u32 {
        unsafe { ptr::read_volatile(&raw const self.state_flags) }
    }

    unsafe fn result_volatile(&self) -> c_int {
        unsafe { ptr::read_volatile(&raw const self.result) }
    }

    unsafe fn set_abort_once(&mut self) {
        if unsafe { ptr::read_volatile(&raw const self.abort_flag) } == 0 {
            unsafe { ptr::write_volatile(&raw mut self.abort_flag, 1) };
        }
    }
}

#[repr(C)]
struct LureEpollConnection {
    _private: [u8; 0],
}

const LURE_EPOLL_DONE: u32 = 1u32 << 1;

#[derive(Default)]
struct StartupFailSignal {
    failed: AtomicBool,
    err: AtomicI32,
}

unsafe extern "C" {
    fn lure_epoll_connection_main(
        shared: *mut LureEpollShared,
        on_startup_fail: unsafe extern "C" fn(*mut c_void, c_int),
        user_data: *mut c_void,
        out_conn: *mut *mut LureEpollConnection,
    ) -> c_int;
    fn lure_epoll_connection_join(conn: *mut LureEpollConnection) -> c_int;
    fn lure_epoll_connection_free(conn: *mut LureEpollConnection);
}

pub struct EpollBackend {
    next_id: AtomicU64,
    shutdown: AtomicBool,
}

#[derive(Default)]
pub struct EpollProgress {
    c2s_bytes: AtomicU64,
    s2c_bytes: AtomicU64,
    c2s_chunks: AtomicU64,
    s2c_chunks: AtomicU64,
}

impl EpollProgress {
    fn store_stats(&self, stats: EpollStats) {
        self.c2s_bytes.store(stats.c2s_bytes, Ordering::Relaxed);
        self.s2c_bytes.store(stats.s2c_bytes, Ordering::Relaxed);
        self.c2s_chunks.store(stats.c2s_chunks, Ordering::Relaxed);
        self.s2c_chunks.store(stats.s2c_chunks, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> EpollStats {
        EpollStats {
            c2s_bytes: self.c2s_bytes.load(Ordering::Relaxed),
            s2c_bytes: self.s2c_bytes.load(Ordering::Relaxed),
            c2s_chunks: self.c2s_chunks.load(Ordering::Relaxed),
            s2c_chunks: self.s2c_chunks.load(Ordering::Relaxed),
        }
    }
}

impl EpollBackend {
    pub fn new(_worker_threads: usize, _max_conns: usize, _buf_cap: usize) -> io::Result<Self> {
        Ok(Self {
            next_id: AtomicU64::new(1),
            shutdown: AtomicBool::new(false),
        })
    }

    pub fn spawn_pair(
        &self,
        fd_a: RawFd,
        fd_b: RawFd,
    ) -> io::Result<tokio::sync::oneshot::Receiver<EpollDone>> {
        let (rx, _) = self.spawn_pair_observed(fd_a, fd_b)?;
        Ok(rx)
    }

    pub fn spawn_pair_observed(
        &self,
        fd_a: RawFd,
        fd_b: RawFd,
    ) -> io::Result<(
        tokio::sync::oneshot::Receiver<EpollDone>,
        Arc<EpollProgress>,
    )> {
        if self.shutdown.load(Ordering::Relaxed) {
            close_fd(fd_a);
            close_fd(fd_b);
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "epoll backend is shutting down",
            ));
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let progress = Arc::new(EpollProgress::default());
        let rt = tokio::runtime::Handle::current();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let progress_bg = Arc::clone(&progress);
        thread::Builder::new()
            .name(format!("lure-epoll-conn-{id}"))
            .spawn(move || {
                let done = run_pair_blocking(fd_a, fd_b, id, Some(progress_bg), rt);
                let _ = tx.send(done);
            })
            .map_err(io::Error::other)?;
        Ok((rx, progress))
    }

    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }
}

impl Drop for EpollBackend {
    fn drop(&mut self) {
        self.shutdown();
    }
}

unsafe extern "C" fn startup_fail_cb(user_data: *mut c_void, err: c_int) {
    if user_data.is_null() {
        return;
    }

    // Callback can run on C threads. We only publish startup failure bits.
    let signal = unsafe { &*(user_data.cast::<StartupFailSignal>()) };
    signal.err.store(err, Ordering::Relaxed);
    signal.failed.store(true, Ordering::Release);
}

#[derive(Debug)]
pub struct Listener {
    inner: TcpListener,
}

impl Listener {
    pub(crate) async fn bind(addr: SocketAddr) -> io::Result<Self> {
        let inner = TcpListener::bind(addr).await?;
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
    stream: TcpStream,
    addr: SocketAddr,
}

impl Connection {
    pub(crate) async fn connect(addr: SocketAddr) -> io::Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        let addr = stream.peer_addr()?;
        Ok(Self { stream, addr })
    }

    pub(crate) const fn new(stream: TcpStream, addr: SocketAddr) -> Self {
        Self { stream, addr }
    }

    pub const fn as_ref(&self) -> &TcpStream {
        &self.stream
    }

    pub const fn as_mut(&mut self) -> &mut TcpStream {
        &mut self.stream
    }

    pub const fn addr(&self) -> &SocketAddr {
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

    pub(crate) async fn read_chunk(&mut self, mut buf: Vec<u8>) -> io::Result<(usize, Vec<u8>)> {
        use tokio::io::AsyncReadExt;
        let n = self.stream.read(buf.as_mut_slice()).await?;
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
}

pub fn duplicate_fd(fd: RawFd) -> io::Result<RawFd> {
    let rc = unsafe { dup(fd) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(rc)
}

pub(crate) fn probe() -> io::Result<()> {
    if cfg!(target_os = "linux") {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "epoll backend is linux-only",
        ))
    }
}

async fn observe_and_trip(shared_addr: usize, progress: Option<Arc<EpollProgress>>) {
    let mut wd_last_chunks: Option<u64> = None;
    let mut wd_tick_100ms = 0u32;
    let mut wd_stall_polls = 0u32;

    loop {
        let shared = unsafe { &mut *(shared_addr as *mut LureEpollShared) };
        let stats = unsafe { shared.stats_volatile() };
        if let Some(progress) = &progress {
            progress.store_stats(stats);
        }
        let state = unsafe { shared.state_flags_volatile() };
        let chunks = stats.c2s_chunks.saturating_add(stats.s2c_chunks);

        // Fast observer loop for stats (100ms), with independent watchdog cadence (5s).
        wd_tick_100ms = wd_tick_100ms.saturating_add(1);
        if wd_tick_100ms >= 50 {
            wd_tick_100ms = 0;
            if let Some(prev) = wd_last_chunks {
                if prev == chunks {
                    wd_stall_polls = wd_stall_polls.saturating_add(1);
                    // 12 x 5s windows ~= 60s with no packet progress.
                    if wd_stall_polls >= 12 {
                        unsafe { shared.set_abort_once() };
                    }
                } else {
                    wd_stall_polls = 0;
                }
            }
            wd_last_chunks = Some(chunks);
        }

        if (state & LURE_EPOLL_DONE) != 0 {
            if let Some(progress) = &progress {
                progress.store_stats(stats);
            }
            break;
        }

        sleep(Duration::from_millis(100)).await;
    }
}

fn run_pair_blocking(
    fd_a: RawFd,
    fd_b: RawFd,
    id: u64,
    progress: Option<Arc<EpollProgress>>,
    rt: tokio::runtime::Handle,
) -> EpollDone {
    let mut shared = Box::new(LureEpollShared::new(fd_a as c_int, fd_b as c_int));
    let fail_signal = Box::new(StartupFailSignal::default());

    let mut conn: *mut LureEpollConnection = std::ptr::null_mut();
    let rc = unsafe {
        lure_epoll_connection_main(
            shared.as_mut(),
            startup_fail_cb,
            (&*fail_signal as *const StartupFailSignal)
                .cast_mut()
                .cast::<c_void>(),
            &raw mut conn,
        )
    };

    if rc < 0 {
        let err = if fail_signal.failed.load(Ordering::Acquire) {
            -fail_signal.err.load(Ordering::Relaxed)
        } else {
            rc
        };
        return EpollDone {
            id,
            stats: EpollStats::default(),
            result: err,
        };
    }

    if conn.is_null() {
        return EpollDone {
            id,
            stats: EpollStats::default(),
            result: -libc::EIO,
        };
    }

    let observe_addr = (&mut *shared as *mut LureEpollShared) as usize;
    let observer = rt.spawn(async move {
        observe_and_trip(observe_addr, progress).await;
    });

    let join_rc = unsafe { lure_epoll_connection_join(conn) };
    unsafe {
        lure_epoll_connection_free(conn);
    }
    let _ = rt.block_on(observer);

    let result = if join_rc < 0 {
        join_rc
    } else {
        unsafe { shared.result_volatile() }
    };

    let stats = unsafe { shared.stats_volatile() };
    EpollDone { id, stats, result }
}

pub async fn passthrough_basic(a: &mut Connection, b: &mut Connection) -> io::Result<()> {
    let fd_a = duplicate_fd(a.as_ref().as_raw_fd())?;
    let fd_b = duplicate_fd(b.as_ref().as_raw_fd())?;

    let mut shared = Box::new(LureEpollShared::new(fd_a as c_int, fd_b as c_int));
    let fail_signal = Box::new(StartupFailSignal::default());

    let mut conn: *mut LureEpollConnection = std::ptr::null_mut();
    let rc = unsafe {
        lure_epoll_connection_main(
            shared.as_mut(),
            startup_fail_cb,
            (&*fail_signal as *const StartupFailSignal)
                .cast_mut()
                .cast::<c_void>(),
            &raw mut conn,
        )
    };

    if rc < 0 {
        let err = if fail_signal.failed.load(Ordering::Acquire) {
            fail_signal.err.load(Ordering::Relaxed)
        } else {
            -rc
        };
        return Err(io::Error::from_raw_os_error(err));
    }

    if conn.is_null() {
        return Err(io::Error::other(
            "epoll startup returned null connection handle",
        ));
    }

    let observe_addr = (&mut *shared as *mut LureEpollShared) as usize;
    let observer = tokio::spawn(async move {
        observe_and_trip(observe_addr, None).await;
    });

    let conn_addr = conn as usize;
    let join_task = tokio::task::spawn_blocking(move || {
        let conn = conn_addr as *mut LureEpollConnection;
        let rc = unsafe { lure_epoll_connection_join(conn) };
        unsafe {
            lure_epoll_connection_free(conn);
        }
        rc
    });

    let (_observer_res, join_res) = tokio::join!(observer, join_task);
    let join_rc = join_res.map_err(|err| io::Error::other(err.to_string()))?;

    if join_rc < 0 {
        return Err(io::Error::from_raw_os_error(-join_rc));
    }

    let result = unsafe { shared.result_volatile() };
    if result < 0 {
        return Err(io::Error::from_raw_os_error(-result));
    }

    Ok(())
}

pub fn passthrough(_fd_a: RawFd, _fd_b: RawFd) -> io::Result<EpollStats> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "use passthrough_basic with epoll connection main",
    ))
}

pub fn close_fd(fd: RawFd) {
    let _ = unsafe { close(fd) };
}

// ── Global EpollBackend singleton ─────────────────────────────────────────────

static GLOBAL_EPOLL: OnceLock<io::Result<Arc<EpollBackend>>> = OnceLock::new();

/// Returns the global [`EpollBackend`], initialising it on first call.
pub fn get_global_backend() -> io::Result<Arc<EpollBackend>> {
    GLOBAL_EPOLL
        .get_or_init(|| {
            let workers = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4);
            EpollBackend::new(workers, 1024, 8192).map(Arc::new)
        })
        .as_ref()
        .map(Arc::clone)
        .map_err(|e| io::Error::other(e.to_string()))
}

// ── Sock trait implementation ─────────────────────────────────────────────────

use std::{future::Future, pin::Pin, sync::OnceLock};

impl Connection {
    /// Start bidirectional proxy by duping both FDs and submitting to the
    /// global [`EpollBackend`] worker pool.
    pub(crate) fn into_proxy(
        self,
        peer: Box<dyn crate::sock::Sock>,
    ) -> io::Result<crate::sock::ProxyHandle> {
        use std::sync::atomic::Ordering;

        let self_fd = self.as_ref().as_raw_fd();
        let peer_fd = peer
            .raw_fd()
            .ok_or_else(|| io::Error::other("epoll proxy: peer has no raw fd"))?;

        let fd_a = duplicate_fd(self_fd)?;
        let fd_b = duplicate_fd(peer_fd)?;
        drop(self); // deregister original fd from tokio's reactor
        drop(peer); // same for peer

        let backend = get_global_backend().inspect_err(|_| {
            close_fd(fd_a);
            close_fd(fd_b);
        })?;

        let (rx, ep_progress) = backend.spawn_pair_observed(fd_a, fd_b)?;

        let progress = Arc::new(crate::sock::ProxyProgress::default());
        let prog2 = Arc::clone(&progress);

        let future: Pin<
            Box<dyn Future<Output = io::Result<crate::sock::ProxyStats>> + Send + 'static>,
        > = Box::pin(async move {
            // Poll ep_progress at 100 ms cadence until completion to give live
            // stats to the parent's metrics layer.
            let done = {
                let mut rx = rx;
                loop {
                    match tokio::time::timeout(
                        tokio::time::Duration::from_millis(100),
                        &mut rx,
                    )
                    .await
                    {
                        Ok(Ok(d)) => break d,
                        Ok(Err(_)) => return Err(io::Error::other("epoll done channel closed")),
                        Err(_) => {
                            // 100 ms elapsed — update live progress and continue
                            let snap = ep_progress.snapshot();
                            prog2.c2s_bytes.store(snap.c2s_bytes, Ordering::Relaxed);
                            prog2.s2c_bytes.store(snap.s2c_bytes, Ordering::Relaxed);
                            prog2.c2s_chunks.store(snap.c2s_chunks, Ordering::Relaxed);
                            prog2.s2c_chunks.store(snap.s2c_chunks, Ordering::Relaxed);
                        }
                    }
                }
            };

            if done.result < 0 {
                return Err(io::Error::from_raw_os_error(-done.result));
            }

            let stats = crate::sock::ProxyStats {
                c2s_bytes: done.stats.c2s_bytes,
                s2c_bytes: done.stats.s2c_bytes,
                c2s_chunks: done.stats.c2s_chunks,
                s2c_chunks: done.stats.s2c_chunks,
            };
            prog2.c2s_bytes.store(stats.c2s_bytes, Ordering::Relaxed);
            prog2.s2c_bytes.store(stats.s2c_bytes, Ordering::Relaxed);
            prog2.c2s_chunks.store(stats.c2s_chunks, Ordering::Relaxed);
            prog2.s2c_chunks.store(stats.s2c_chunks, Ordering::Relaxed);
            Ok(stats)
        });

        Ok(crate::sock::ProxyHandle { future, progress })
    }
}

impl crate::sock::Sock for Connection {
    fn backend_kind(&self) -> crate::sock::BackendKind {
        crate::sock::BackendKind::Epoll
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Connection::peer_addr(self)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Connection::local_addr(self)
    }

    fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        Connection::set_nodelay(self, nodelay)
    }

    fn raw_fd(&self) -> Option<i32> {
        Some(self.as_ref().as_raw_fd())
    }

    fn try_read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        Connection::try_read(self, buf)
    }

    fn read_chunk<'a>(
        &'a mut self,
        buf: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = io::Result<(usize, Vec<u8>)>> + Send + 'a>> {
        Box::pin(async move { Connection::read_chunk(self, buf).await })
    }

    fn write_all<'a>(
        &'a mut self,
        buf: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + Send + 'a>> {
        Box::pin(async move { Connection::write_all(self, buf).await })
    }

    fn flush<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async move { Connection::flush(self).await })
    }

    fn shutdown<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async move { Connection::shutdown(self).await })
    }

    fn into_proxy(
        self: Box<Self>,
        peer: Box<dyn crate::sock::Sock>,
    ) -> io::Result<crate::sock::ProxyHandle> {
        (*self).into_proxy(peer)
    }
}
