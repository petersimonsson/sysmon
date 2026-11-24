//! Datagrams the receiver turned away, by sender and reason, so the UI can
//! say why an agent isn't showing up instead of waiting silently.

use std::net::IpAddr;
use std::sync::Mutex;

/// Senders remembered at once; past this the one heard from longest ago
/// goes, so a flood from many addresses can't grow the list without end.
const MAX_SENDERS: usize = 32;

/// Why a datagram was turned away, in terms of what to change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reason {
    /// Encrypted, but this monitor has no key.
    NoKey,
    /// Encrypted with a different key (or altered on the way).
    WrongKey,
    /// Not encrypted, but this monitor only accepts encrypted data.
    NotEncrypted,
    /// From a newer protocol version than this monitor reads.
    TooNew(u8),
    /// Not sysmon data at all, or damaged beyond reading.
    NotSysmon,
}

impl Reason {
    /// Classify an [`sysmon_proto::Opener::open`] or decode failure of `buf`.
    pub fn of(err: &sysmon_proto::Error, buf: &[u8]) -> Self {
        use sysmon_proto::Error as E;
        match err {
            E::NeedsKey => Self::NoKey,
            // The opener says the same for a wrong key and for a datagram
            // that wasn't encrypted at all; the flags tell them apart.
            E::Unauthenticated => {
                let encrypted = buf
                    .get(3)
                    .is_some_and(|f| f & sysmon_proto::flags::ENCRYPTED != 0);
                if encrypted {
                    Self::WrongKey
                } else {
                    Self::NotEncrypted
                }
            }
            E::UnsupportedVersion(v) if *v > sysmon_proto::VERSION => Self::TooNew(*v),
            _ => Self::NotSysmon,
        }
    }
}

impl std::fmt::Display for Reason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoKey => {
                f.write_str("its data is encrypted, but this monitor has no key (--key-file)")
            }
            Self::WrongKey => f.write_str("its data is encrypted with a different key"),
            Self::NotEncrypted => f.write_str(
                "its data isn't encrypted, but this monitor needs a key (agent --key-file)",
            ),
            Self::TooNew(v) => write!(
                f,
                "its agent speaks protocol v{v}, newer than this monitor (v{}): update the monitor",
                sysmon_proto::VERSION
            ),
            Self::NotSysmon => f.write_str("what it sends can't be read as sysmon data"),
        }
    }
}

/// Datagrams turned away from one sender for one reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejected {
    pub from: IpAddr,
    pub reason: Reason,
    pub count: u64,
    /// When the last one arrived (Unix ns).
    pub last_ns: u64,
}

/// What the receiver has turned away, shared with whoever wants to show it.
#[derive(Debug, Default)]
pub struct Rejections(Mutex<Vec<Rejected>>);

impl Rejections {
    pub fn record(&self, from: IpAddr, reason: Reason, now_ns: u64) {
        let mut list = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(r) = list
            .iter_mut()
            .find(|r| r.from == from && r.reason == reason)
        {
            r.count += 1;
            r.last_ns = now_ns;
            return;
        }
        if list.len() >= MAX_SENDERS
            && let Some(oldest) = (0..list.len()).min_by_key(|&i| list[i].last_ns)
        {
            list.swap_remove(oldest);
        }
        list.push(Rejected {
            from,
            reason,
            count: 1,
            last_ns: now_ns,
        });
    }

    /// Those turned away since `since_ns`, the most recent first.
    pub fn since(&self, since_ns: u64) -> Vec<Rejected> {
        let list = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let mut out: Vec<_> = list
            .iter()
            .filter(|r| r.last_ns >= since_ns)
            .cloned()
            .collect();
        out.sort_by(|a, b| b.last_ns.cmp(&a.last_ns).then(a.from.cmp(&b.from)));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sysmon_proto::{Key, Opener, Sealer};

    fn datagram() -> Vec<u8> {
        let system = sysmon_proto::SystemSample::default();
        sysmon_proto::encode_sample(1, 2, 0, &system, &[], &[])
            .unwrap()
            .remove(0)
    }

    fn reason(opener: &Opener, d: &[u8]) -> Reason {
        Reason::of(&opener.open(d).unwrap_err(), d)
    }

    #[test]
    fn failures_are_told_apart() {
        let key = Key::generate();
        let sealed = Sealer::new(Some(&key), false).seal(datagram()).unwrap();
        let plain = datagram();

        assert_eq!(reason(&Opener::new(None), &sealed), Reason::NoKey);
        let other = Key::generate();
        assert_eq!(
            reason(&Opener::new(Some(&other)), &sealed),
            Reason::WrongKey
        );
        assert_eq!(
            reason(&Opener::new(Some(&key)), &plain),
            Reason::NotEncrypted
        );

        let mut newer = plain.clone();
        newer[2] = sysmon_proto::VERSION + 1;
        assert_eq!(
            reason(&Opener::new(None), &newer),
            Reason::TooNew(sysmon_proto::VERSION + 1)
        );
        assert_eq!(
            reason(&Opener::new(None), b"GET / HTTP/1.1\r\n"),
            Reason::NotSysmon
        );
    }

    #[test]
    fn counts_per_sender_and_reason_newest_first() {
        let r = Rejections::default();
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        r.record(a, Reason::WrongKey, 10);
        r.record(a, Reason::WrongKey, 20);
        r.record(b, Reason::NoKey, 15);
        let got = r.since(0);
        assert_eq!(got.len(), 2);
        assert_eq!((got[0].from, got[0].count, got[0].last_ns), (a, 2, 20));
        assert_eq!((got[1].from, got[1].count), (b, 1));
        assert_eq!(r.since(16).len(), 1, "only those heard from lately");
    }

    #[test]
    fn the_list_stays_bounded() {
        let r = Rejections::default();
        for i in 0..100u32 {
            r.record(IpAddr::from(i.to_be_bytes()), Reason::NotSysmon, i as u64);
        }
        let got = r.since(0);
        assert_eq!(got.len(), MAX_SENDERS);
        assert_eq!(got[0].last_ns, 99, "the newest are kept");
    }
}
