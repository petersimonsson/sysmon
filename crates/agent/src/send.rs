//! Sending datagrams to monitors over IPv4 and IPv6.

use std::net::{SocketAddr, UdpSocket};

use anyhow::Context;

/// One socket per address family in use. A socket bound to `0.0.0.0` can
/// only reach IPv4 addresses, so IPv6 targets (including `localhost`, which
/// often resolves to `::1` first) need their own.
pub struct Sender {
    v4: Option<UdpSocket>,
    v6: Option<UdpSocket>,
}

impl Sender {
    pub fn new(targets: &[SocketAddr]) -> anyhow::Result<Self> {
        let bind = |addr: &str| {
            UdpSocket::bind(addr).with_context(|| format!("binding UDP socket on {addr}"))
        };
        Ok(Self {
            v4: targets
                .iter()
                .any(SocketAddr::is_ipv4)
                .then(|| bind("0.0.0.0:0"))
                .transpose()?,
            v6: targets
                .iter()
                .any(SocketAddr::is_ipv6)
                .then(|| bind("[::]:0"))
                .transpose()?,
        })
    }

    pub fn send_to(&self, datagram: &[u8], target: SocketAddr) -> std::io::Result<usize> {
        let socket = if target.is_ipv4() { &self.v4 } else { &self.v6 };
        socket
            .as_ref()
            .expect("a socket for every target's family")
            .send_to(datagram, target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sends_to_ipv4_and_ipv6() {
        let rx4 = UdpSocket::bind("127.0.0.1:0").unwrap();
        let rx6 = UdpSocket::bind("[::1]:0").unwrap();
        let targets = [rx4.local_addr().unwrap(), rx6.local_addr().unwrap()];
        let sender = Sender::new(&targets).unwrap();
        for t in targets {
            sender.send_to(b"hello", t).unwrap();
        }
        let mut buf = [0u8; 16];
        rx4.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        rx6.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        for rx in [&rx4, &rx6] {
            let n = rx.recv(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"hello");
        }
    }
}
