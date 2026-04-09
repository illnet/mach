use std::{future::Future, io, net::SocketAddr};

use io_uring::IoUring;
use tokio::net::{TcpListener, TcpStream};

pub(crate) fn probe() -> io::Result<()> {
    IoUring::new(1)
        .map(|_| ())
        .map_err(|err| io::Error::new(err.kind(), format!("io_uring syscall unavailable: {err}")))
}

pub fn spawn<F>(future: F) -> tokio::task::JoinHandle<F::Output>
where
    // Keep the uring surface area compatible with callers that may hand us
    // !Send tasks. The transport layer below is currently a Tokio fallback.
    F: Future + 'static,
    F::Output: 'static,
{
    tokio::task::spawn_local(future)
}

pub fn start<F>(future: F) -> F::Output
where
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

    pub(crate) async fn read_chunk(&mut self, mut buf: Vec<u8>) -> io::Result<(usize, Vec<u8>)> {
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
        // Until the io_uring transport is made Send-compatible with the
        // object-safe Sock trait, proxy through the Tokio implementation.
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
