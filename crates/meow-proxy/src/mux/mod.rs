//! sing-mux compatible connection multiplexing (mihomo-style).
//!
//! Implements the client side of the protocol used by mihomo / sing-box:
//! a single physical proxy connection carries a mux session, and each
//! logical flow is one mux stream.  Wire format mirrors metacubex/sing-mux:
//!
//! * reserved destination `sp.mux.sing-box.arpa:444` in the proxy
//!   handshake marks the connection as a mux connection (server side);
//! * after the proxy handshake the client sends a 2-byte (+padding) request
//!   header picking the mux protocol (smux in this PR; yamux/h2mux land in
//!   follow-up PRs);
//! * every stream carries the real destination as a sing-encoded
//!   `Socksaddr` prefix (see `address`).
//!
//! See docs/specs/proxy-mux.md for the full wire specification.

pub mod address;
pub mod client;
pub mod packet;
pub mod request;
pub mod smux;
pub mod stream;

pub use client::{DialFn, MuxClient, MuxOptions};
pub use packet::MuxPacketConn;
pub use stream::MuxStreamConn;

/// Reserved destination used in the proxy handshake to open a mux session.
pub const MUX_DESTINATION_FQDN: &str = "sp.mux.sing-box.arpa";
pub const MUX_DESTINATION_PORT: u16 = 444;

/// Mux protocol identifiers.
///
/// `Smux` matches sing-mux's request-header byte value 0.  Yamux/H2Mux
/// (bytes 1/2) and Xray Mux.Cool land in follow-up PRs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Smux = 0,
}

impl Protocol {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "" | "smux" => Some(Protocol::Smux),
            _ => None,
        }
    }
}
