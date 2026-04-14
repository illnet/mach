//! # `net`-code
//! A minimal, dependency-free-ish netcodes to run a minecraft reverse proxy.
//! With sufficient amount of implemented parser and encoder, it is still light and pretty much served perfectly for this case.
//!
//! - `net::ha` - HA-Proxy Protocol: For authentication, session pre-tagging.
//! - `net::mc` - Minecraft Protocol: For native handshake, status, etc.
//! - `net::sock` - Socket abstraction layer: [`LureNet`], [`LureConnection`], [`Sock`] trait.
pub mod ha;
pub mod mc;
pub mod sock;
