use std::{
    io,
    net::SocketAddr,
    os::fd::{AsRawFd, RawFd},
    ptr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicUsize, Ordering},
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

// ── EpollManager (N-worker pool) ──────────────────────────────────────────────

use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{Mutex, OnceLock, Weak},
};

/// Layout of the completion frame written by C workers to the shared done-pipe.
/// Must match `LureEpollDone` in epoll.h exactly (48 bytes, no padding gaps).
#[repr(C)]
struct LureEpollDoneC {
    conn_id: u64,
    c2s_bytes: u64,
    s2c_bytes: u64,
    c2s_chunks: u64,
    s2c_chunks: u64,
    result: i32,
    _pad: u32,
}

const _: () = assert!(
    std::mem::size_of::<LureEpollDoneC>() == 48,
    "LureEpollDone C/Rust size mismatch"
);

/// Live byte/chunk counters shared with C worker for mid-session polling.
/// Rust allocates this, passes pointer to C; C writes plain u64 values.
/// Rust polls via read_volatile every 100ms. Cache-line aligned to avoid false sharing.
#[repr(C, align(64))]
pub struct LureEpollLiveBytes {
    pub c2s_bytes: u64,
    pub s2c_bytes: u64,
    pub c2s_chunks: u64,
    pub s2c_chunks: u64,
    // 32 bytes of implicit padding to fill cache line (compiler respects align(64))
}

impl LureEpollLiveBytes {
    pub unsafe fn read_volatile(&self) -> EpollStats {
        EpollStats {
            c2s_bytes: unsafe { ptr::read_volatile(&raw const self.c2s_bytes) },
            s2c_bytes: unsafe { ptr::read_volatile(&raw const self.s2c_bytes) },
            c2s_chunks: unsafe { ptr::read_volatile(&raw const self.c2s_chunks) },
            s2c_chunks: unsafe { ptr::read_volatile(&raw const self.s2c_chunks) },
        }
    }
}

#[repr(C)]
struct LureEpollWorkerC {
    _private: [u8; 0],
}

unsafe impl Send for LureEpollWorkerC {}
unsafe impl Sync for LureEpollWorkerC {}

unsafe extern "C" {
    fn lure_epoll_worker_new(done_pipe_write_fd: c_int) -> *mut LureEpollWorkerC;
    fn lure_epoll_worker_submit(
        w: *mut LureEpollWorkerC,
        fd_a: c_int,
        fd_b: c_int,
        conn_id: u64,
        live: *mut LureEpollLiveBytes,
    ) -> c_int;
    fn lure_epoll_worker_abort(w: *mut LureEpollWorkerC, conn_id: u64);
    fn lure_epoll_worker_shutdown(w: *mut LureEpollWorkerC);
    fn lure_epoll_worker_free(w: *mut LureEpollWorkerC);
}

struct WorkerHandle {
    ptr: *mut LureEpollWorkerC,
}

unsafe impl Send for WorkerHandle {}
unsafe impl Sync for WorkerHandle {}

impl Drop for WorkerHandle {
    fn drop(&mut self) {
        unsafe {
            lure_epoll_worker_shutdown(self.ptr);
            lure_epoll_worker_free(self.ptr);
        }
    }
}

/// A non-owning file-descriptor reference that implements `AsRawFd` so that
/// `AsyncFd` can wrap it without closing the underlying fd on drop.
struct FdRef(RawFd);
impl std::os::fd::AsRawFd for FdRef {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

/// N-worker pool.  Each `LureEpollWorker` C thread monitors its share of
/// connections via a private epoll_fd.  All workers write completions to one
/// shared done-pipe; a single Tokio drain task forwards completions to the
/// per-connection oneshot channels stored in `pending`.
pub struct EpollManager {
    workers: Vec<WorkerHandle>,
    done_read_fd: RawFd,
    done_write_fd: RawFd,
    pending: Mutex<HashMap<u64, tokio::sync::oneshot::Sender<EpollDone>>>,
    next_worker: AtomicUsize,
    next_id: AtomicU64,
}

unsafe impl Send for EpollManager {}
unsafe impl Sync for EpollManager {}

impl Drop for EpollManager {
    fn drop(&mut self) {
        // Workers are dropped first (their Drop shuts them down), then the pipe.
        // WorkerHandle::drop() calls lure_epoll_worker_shutdown which joins the
        // thread before lure_epoll_worker_free — so the pipe write end is still
        // valid during shutdown.
        close_fd(self.done_write_fd);
        close_fd(self.done_read_fd);
    }
}

impl EpollManager {
    fn build() -> io::Result<Self> {
        let n_workers = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);

        let mut pipe_fds = [0i32; 2];
        // SAFETY: pipe2 is a simple syscall with a valid array pointer.
        let rc = unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        let done_read_fd = pipe_fds[0];
        let done_write_fd = pipe_fds[1];

        let mut workers = Vec::with_capacity(n_workers);
        for _ in 0..n_workers {
            // SAFETY: done_write_fd is valid; C worker does NOT close it.
            let w = unsafe { lure_epoll_worker_new(done_write_fd) };
            if w.is_null() {
                // Workers already built are dropped here via Vec::drop →
                // WorkerHandle::drop, which shuts them down cleanly.
                close_fd(done_write_fd);
                close_fd(done_read_fd);
                return Err(io::Error::other("failed to create epoll worker thread"));
            }
            workers.push(WorkerHandle { ptr: w });
        }

        Ok(Self {
            workers,
            done_read_fd,
            done_write_fd,
            pending: Mutex::new(HashMap::new()),
            next_worker: AtomicUsize::new(0),
            next_id: AtomicU64::new(1),
        })
    }

    /// Submit a connection pair.  C takes ownership of both fds (closes them
    /// on completion or error).  Returns a receiver that resolves with the
    /// final [`EpollDone`] and a Box of live byte counters for mid-session polling.
    pub fn submit(
        &self,
        fd_a: RawFd,
        fd_b: RawFd,
    ) -> io::Result<(
        tokio::sync::oneshot::Receiver<EpollDone>,
        Box<LureEpollLiveBytes>,
    )> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.pending.lock().unwrap().insert(id, tx);

        let live = Box::new(LureEpollLiveBytes {
            c2s_bytes: 0,
            s2c_bytes: 0,
            c2s_chunks: 0,
            s2c_chunks: 0,
        });

        let n = self.workers.len();
        let idx = self.next_worker.fetch_add(1, Ordering::Relaxed) % n;
        // SAFETY: ptr is valid; fd_a/fd_b ownership transferred to C; live pointer is valid for session lifetime.
        let rc = unsafe { lure_epoll_worker_submit(self.workers[idx].ptr, fd_a, fd_b, id, live.as_ref() as *const LureEpollLiveBytes as *mut _) };
        if rc < 0 {
            // C closed fd_a/fd_b already; just clean up the pending entry.
            self.pending.lock().unwrap().remove(&id);
            return Err(io::Error::from_raw_os_error(-rc));
        }

        Ok((rx, live))
    }

    fn deliver(&self, frame: LureEpollDoneC) {
        let done = EpollDone {
            id: frame.conn_id,
            stats: EpollStats {
                c2s_bytes: frame.c2s_bytes,
                s2c_bytes: frame.s2c_bytes,
                c2s_chunks: frame.c2s_chunks,
                s2c_chunks: frame.s2c_chunks,
            },
            result: frame.result,
        };
        let mut pending = self.pending.lock().unwrap();
        if let Some(tx) = pending.remove(&frame.conn_id) {
            let _ = tx.send(done);
        }
    }
}

/// Tokio task: continuously read 48-byte completion frames from `done_read_fd`
/// and deliver them to the waiting oneshot channels in `mgr`.
async fn drain_completions(done_read_fd: RawFd, mgr: Weak<EpollManager>) {
    use tokio::io::unix::AsyncFd;
    const FRAME: usize = std::mem::size_of::<LureEpollDoneC>();

    let afd = match AsyncFd::new(FdRef(done_read_fd)) {
        Ok(a) => a,
        Err(_) => return,
    };

    let mut leftover: Vec<u8> = Vec::new();

    loop {
        let Some(mgr) = mgr.upgrade() else { break };

        let mut guard = match afd.readable().await {
            Ok(g) => g,
            Err(_) => break,
        };
        guard.clear_ready();

        // Tight read loop until EAGAIN.
        loop {
            let want = (FRAME - leftover.len()).max(FRAME);
            let mut buf = vec![0u8; want];
            // SAFETY: buf is valid for `want` bytes.
            let n =
                unsafe { libc::read(done_read_fd, buf.as_mut_ptr() as *mut libc::c_void, want) };
            if n <= 0 {
                if n < 0 {
                    let e = io::Error::last_os_error();
                    if e.kind() == io::ErrorKind::WouldBlock {
                        break; // no more data right now
                    }
                }
                return; // pipe closed or unrecoverable error
            }
            leftover.extend_from_slice(&buf[..n as usize]);

            while leftover.len() >= FRAME {
                // SAFETY: leftover is at least FRAME bytes; read_unaligned
                // handles any alignment.
                let frame: LureEpollDoneC =
                    unsafe { std::ptr::read_unaligned(leftover.as_ptr() as *const LureEpollDoneC) };
                leftover.drain(..FRAME);
                mgr.deliver(frame);
            }
        }
    }
}

static GLOBAL_EPOLL_MANAGER: OnceLock<io::Result<Arc<EpollManager>>> = OnceLock::new();

/// Returns the global [`EpollManager`], initialising it on first call.
/// Must be called from within a Tokio runtime context (spawns the drain task).
pub fn get_epoll_manager() -> io::Result<Arc<EpollManager>> {
    GLOBAL_EPOLL_MANAGER
        .get_or_init(|| {
            EpollManager::build().map(|mgr| {
                let arc = Arc::new(mgr);
                let weak = Arc::downgrade(&arc);
                let read_fd = arc.done_read_fd;
                tokio::spawn(drain_completions(read_fd, weak));
                arc
            })
        })
        .as_ref()
        .map(Arc::clone)
        .map_err(|e| io::Error::other(e.to_string()))
}

// ── Sock trait implementation ─────────────────────────────────────────────────

impl Connection {
    /// Start bidirectional proxy via the global [`EpollManager`] N-worker pool.
    ///
    /// Both fds are duplicated, then the original `TcpStream` handles are
    /// dropped to deregister them from Tokio's reactor before handing the duped
    /// fds to a C worker thread.
    pub(crate) fn into_proxy(
        self,
        peer: Box<dyn crate::sock::Sock>,
    ) -> io::Result<crate::sock::ProxyHandle> {
        let self_fd = self.as_ref().as_raw_fd();
        let peer_fd = peer
            .raw_fd()
            .ok_or_else(|| io::Error::other("epoll proxy: peer has no raw fd"))?;

        let fd_a = duplicate_fd(self_fd)?;
        let fd_b = duplicate_fd(peer_fd).inspect_err(|_| close_fd(fd_a))?;

        // Drop originals to deregister from Tokio's reactor before C takes over.
        drop(self);
        drop(peer);

        let mgr = get_epoll_manager().inspect_err(|_| {
            close_fd(fd_a);
            close_fd(fd_b);
        })?;

        // After submit, C owns fd_a/fd_b — do not close on error here.
        let (rx, live) = mgr.submit(fd_a, fd_b)?;

        let progress = Arc::new(crate::sock::ProxyProgress::default());
        let prog2 = Arc::clone(&progress);
        let prog_observer = Arc::clone(&progress);

        // Spawn observer task to poll live counters every 100ms
        tokio::task::spawn_local(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(100));
            loop {
                interval.tick().await;
                // SAFETY: live is valid and owned by this task; C writes until session close.
                let snap = unsafe { live.read_volatile() };
                prog_observer.c2s_bytes.store(snap.c2s_bytes, Ordering::Relaxed);
                prog_observer.s2c_bytes.store(snap.s2c_bytes, Ordering::Relaxed);
                prog_observer.c2s_chunks.store(snap.c2s_chunks, Ordering::Relaxed);
                prog_observer.s2c_chunks.store(snap.s2c_chunks, Ordering::Relaxed);
                // Keep observing until prog_observer is the last strong reference (session end)
                if Arc::strong_count(&prog_observer) == 1 {
                    break;
                }
            }
            // live is dropped here after C is done writing (confirmed by session close)
        });

        let future: Pin<
            Box<dyn Future<Output = io::Result<crate::sock::ProxyStats>> + Send + 'static>,
        > = Box::pin(async move {
            let done = rx
                .await
                .map_err(|_| io::Error::other("epoll done channel closed"))?;

            if done.result < 0 {
                return Err(io::Error::from_raw_os_error(-done.result));
            }

            let stats = crate::sock::ProxyStats {
                c2s_bytes: done.stats.c2s_bytes,
                s2c_bytes: done.stats.s2c_bytes,
                c2s_chunks: done.stats.c2s_chunks,
                s2c_chunks: done.stats.s2c_chunks,
            };
            // Update progress with final stats so callers see the complete picture.
            prog2.c2s_bytes.store(stats.c2s_bytes, Ordering::Relaxed);
            prog2.s2c_bytes.store(stats.s2c_bytes, Ordering::Relaxed);
            prog2.c2s_chunks.store(stats.c2s_chunks, Ordering::Relaxed);
            prog2.s2c_chunks.store(stats.s2c_chunks, Ordering::Relaxed);
            Ok(stats)
        });

        Ok(crate::sock::ProxyHandle { future, progress })
    }
}

// ── Legacy Global EpollBackend singleton (kept for passthrough_basic tests) ───

static GLOBAL_EPOLL: OnceLock<io::Result<Arc<EpollBackend>>> = OnceLock::new();

/// Returns the global [`EpollBackend`], used only by [`passthrough_basic`].
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
