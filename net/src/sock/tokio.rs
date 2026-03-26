#[cfg(unix)]
use std::{
    future::Future,
    sync::{Arc, atomic::Ordering},
};
use std::{io, net::SocketAddr, pin::Pin};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

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

impl TryFrom<TcpStream> for Connection {
    type Error = io::Error;

    fn try_from(stream: TcpStream) -> Result<Self, io::Error> {
        let addr = stream.peer_addr()?;
        Ok(Self { stream, addr })
    }
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
        let n = self.stream.read(buf.as_mut_slice()).await?;
        Ok((n, buf))
    }

    pub(crate) async fn write_all(&mut self, buf: Vec<u8>) -> io::Result<Vec<u8>> {
        self.stream.write_all(buf.as_slice()).await?;
        Ok(buf)
    }

    pub(crate) async fn flush(&mut self) -> io::Result<()> {
        self.stream.flush().await
    }

    pub(crate) fn try_read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.try_read(buf)
    }

    pub(crate) async fn shutdown(&mut self) -> io::Result<()> {
        self.stream.shutdown().await
    }
}

// ── Sock trait implementation ─────────────────────────────────────────────────

impl Connection {
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

    /// Start bidirectional proxy between `self` and `peer` using Tokio
    /// `copy_bidirectional`-style two-task approach with live progress tracking.
    pub(crate) fn into_proxy(
        self,
        peer: Box<dyn crate::sock::Sock>,
    ) -> io::Result<crate::sock::ProxyHandle> {
        // Duplicate peer's FD and register as a new TcpStream so we own both
        // halves independently of their previous tokio registrations.
        let peer_fd = peer
            .raw_fd()
            .ok_or_else(|| io::Error::other("tokio proxy: peer has no raw fd"))?;

        #[cfg(not(unix))]
        {
            drop(peer);
            let _ = peer_fd;
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "tokio proxy: not supported on non-unix",
            ));
        }

        #[cfg(unix)]
        {
            let peer_stream: TcpStream = {
                use std::os::unix::io::FromRawFd;
                let fd_dup = crate::sock::duplicate_fd(peer_fd)?;
                drop(peer); // deregister peer's original fd from tokio's reactor
                let std_stream = unsafe { std::net::TcpStream::from_raw_fd(fd_dup) };
                std_stream.set_nonblocking(true)?;
                TcpStream::from_std(std_stream)?
            };

            let progress = Arc::new(crate::sock::ProxyProgress::default());
            let prog_c2s = Arc::clone(&progress);
            let prog_s2c = Arc::clone(&progress);
            let prog_final = Arc::clone(&progress);

            let (a_read, a_write) = self.stream.into_split();
            let (b_read, b_write) = peer_stream.into_split();

            let future: Pin<
                Box<dyn Future<Output = io::Result<crate::sock::ProxyStats>> + Send + 'static>,
            > = Box::pin(async move {
                let mut c2s_task = tokio::spawn(async move {
                    copy_tracked(a_read, b_write, &prog_c2s.c2s_bytes, &prog_c2s.c2s_chunks).await
                });
                let mut s2c_task = tokio::spawn(async move {
                    copy_tracked(b_read, a_write, &prog_s2c.s2c_bytes, &prog_s2c.s2c_chunks).await
                });

                let mut c2s_done = false;
                let mut s2c_done = false;

                while !c2s_done || !s2c_done {
                    tokio::select! {
                        result = &mut c2s_task, if !c2s_done => {
                            match result {
                                Ok(Ok(())) => c2s_done = true,
                                Ok(Err(err)) => {
                                    if !s2c_done {
                                        s2c_task.abort();
                                        let _ = (&mut s2c_task).await;
                                    }
                                    return Err(io::Error::other(err));
                                }
                                Err(err) => {
                                    log::error!("c2s task join failed: {err:?}");
                                    if !s2c_done {
                                        s2c_task.abort();
                                        let _ = (&mut s2c_task).await;
                                    }
                                    return Err(io::Error::other(err.to_string()));
                                }
                            }
                        }
                        result = &mut s2c_task, if !s2c_done => {
                            match result {
                                Ok(Ok(())) => s2c_done = true,
                                Ok(Err(err)) => {
                                    if !c2s_done {
                                        c2s_task.abort();
                                        let _ = (&mut c2s_task).await;
                                    }
                                    return Err(io::Error::other(err));
                                }
                                Err(err) => {
                                    log::error!("s2c task join failed: {err:?}");
                                    if !c2s_done {
                                        c2s_task.abort();
                                        let _ = (&mut c2s_task).await;
                                    }
                                    return Err(io::Error::other(err.to_string()));
                                }
                            }
                        }
                    }
                }

                Ok(prog_final.snapshot())
            });

            Ok(crate::sock::ProxyHandle { future, progress })
        }
    }
}

/// Copy all bytes from `from` to `to`, updating atomic progress counters.
#[cfg(unix)]
async fn copy_tracked(
    mut from: tokio::net::tcp::OwnedReadHalf,
    mut to: tokio::net::tcp::OwnedWriteHalf,
    bytes_counter: &std::sync::atomic::AtomicU64,
    chunks_counter: &std::sync::atomic::AtomicU64,
) -> io::Result<()> {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = from.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        to.write_all(&buf[..n]).await?;
        bytes_counter.fetch_add(n as u64, Ordering::Relaxed);
        chunks_counter.fetch_add(1, Ordering::Relaxed);
    }
    Ok(())
}

impl crate::sock::Sock for Connection {
    fn backend_kind(&self) -> crate::sock::BackendKind {
        crate::sock::BackendKind::Tokio
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.stream.peer_addr()
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.stream.local_addr()
    }

    fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        Connection::set_nodelay(self, nodelay)
    }

    fn raw_fd(&self) -> Option<i32> {
        Connection::raw_fd(self)
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

pub async fn passthrough_basic(a: &mut Connection, b: &mut Connection) -> io::Result<()> {
    let (mut a_read, mut a_write) = a.as_mut().split();
    let (mut b_read, mut b_write) = b.as_mut().split();

    let a_to_b = tokio::io::copy(&mut a_read, &mut b_write);
    let b_to_a = tokio::io::copy(&mut b_read, &mut a_write);
    let _ = tokio::try_join!(a_to_b, b_to_a)?;
    Ok(())
}
