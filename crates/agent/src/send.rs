//! Sending datagrams to monitors over IPv4 and IPv6.

use std::net::{SocketAddr, UdpSocket};

/// One socket per address family, created when first needed. A socket
/// bound to `0.0.0.0` can only reach IPv4 addresses, so IPv6 targets
/// (including `localhost`, which often resolves to `::1` first) need their
/// own, and a re-resolved name may switch between the two.
#[derive(Default)]
pub struct Sender {
    v4: Option<UdpSocket>,
    v6: Option<UdpSocket>,
}

impl Sender {
    pub fn send_to(&mut self, datagram: &[u8], target: SocketAddr) -> std::io::Result<usize> {
        let (slot, bind) = if target.is_ipv4() {
            (&mut self.v4, "0.0.0.0:0")
        } else {
            (&mut self.v6, "[::]:0")
        };
        if slot.is_none() {
            *slot = Some(UdpSocket::bind(bind)?);
        }
        slot.as_ref().unwrap().send_to(datagram, target)
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
        let mut sender = Sender::default();
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
