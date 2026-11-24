//! sysmon receiver: UDP socket thread, chunk reassembly and fan-out.

mod assembler;
mod rejects;

pub use assembler::{Assembler, Event};
pub use rejects::{Reason, Rejected, Rejections};

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// A datagram exactly as received, for the recorder.
#[derive(Debug, Clone)]
pub struct RawDatagram {
    pub recv_ts_ns: u64,
    pub from: SocketAddr,
    pub bytes: Vec<u8>,
}

/// Where the receiver sends its output. The channels should be bounded; when
/// one is full the item is dropped and counted rather than blocking the socket.
pub struct Sinks {
    pub events: flume::Sender<Event>,
    pub raw: Option<flume::Sender<RawDatagram>>,
    /// Counts what was turned away, by sender and reason.
    pub rejections: Arc<Rejections>,
}

/// Bind `addr` and run the receive loop on a dedicated thread.
///
/// Datagrams are authenticated and decrypted with `opener` first; anything
/// that fails is dropped before it reaches the recorder or the assembler.
pub fn spawn(
    addr: SocketAddr,
    opener: sysmon_proto::Opener,
    sinks: Sinks,
) -> std::io::Result<JoinHandle<()>> {
    let socket = UdpSocket::bind(addr)?;
    // Wake regularly so partial samples are flushed even when traffic stops.
    socket.set_read_timeout(Some(Duration::from_millis(250)))?;
    tracing::info!(%addr, "listening");

    std::thread::Builder::new()
        .name("sysmon-ingest".into())
        .spawn(move || run(socket, opener, sinks))
}

fn run(socket: UdpSocket, opener: sysmon_proto::Opener, sinks: Sinks) {
    let mut rejected = 0u64;
    let mut assembler = Assembler::new(Duration::from_millis(1500));
    let mut buf = vec![0u8; 64 * 1024];
    let mut dropped = 0u64;

    loop {
        let now = Instant::now();
        match socket.recv_from(&mut buf) {
            Ok((len, from)) => {
                let bytes = match opener.open(&buf[..len]) {
                    Ok(b) => b,
                    Err(err) => {
                        sinks.rejections.record(
                            from.ip(),
                            Reason::of(&err, &buf[..len]),
                            unix_now_ns(),
                        );
                        rejected += 1;
                        if rejected.is_power_of_two() {
                            tracing::warn!(%from, %err, rejected, "rejected datagram");
                        }
                        continue;
                    }
                };
                let bytes = &bytes[..];
                let recv_ns = unix_now_ns();
                if let Some(raw) = &sinks.raw {
                    let item = RawDatagram {
                        recv_ts_ns: recv_ns,
                        from,
                        bytes: bytes.to_vec(),
                    };
                    if raw.try_send(item).is_err() {
                        dropped += 1;
                    }
                }
                match sysmon_proto::decode(bytes) {
                    Ok((header, msg)) => assembler.push(header, msg, now, recv_ns),
                    Err(err) => {
                        tracing::debug!(%from, %err, "undecodable datagram");
                        sinks
                            .rejections
                            .record(from.ip(), Reason::of(&err, bytes), recv_ns);
                    }
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(e) => {
                tracing::error!(error = %e, "recv failed, stopping receiver");
                return;
            }
        }

        assembler.flush_stale(now);
        for event in assembler.drain() {
            match sinks.events.try_send(event) {
                Ok(()) => {}
                Err(flume::TrySendError::Full(_)) => dropped += 1,
                Err(flume::TrySendError::Disconnected(_)) => return,
            }
        }
        if dropped > 0 && dropped.is_power_of_two() {
            tracing::warn!(dropped, "consumers are falling behind");
        }
    }
}

pub use sysmon_proto::unix_now_ns;
