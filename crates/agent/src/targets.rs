//! Monitor addresses, resolved again periodically.
//!
//! A name is looked up again every [`RESOLVE_EVERY`], so a monitor that
//! moves to a new address is followed without restarting the agent, and a
//! name that doesn't resolve yet (DNS not up at boot) is picked up once it
//! does. Lookups run on their own thread, since a slow DNS server must not
//! stall sampling. Addresses given as IP:port are used as they are.

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::bail;

pub const RESOLVE_EVERY: Duration = Duration::from_secs(60);

type Lookup = Arc<dyn Fn(&str) -> std::io::Result<Vec<SocketAddr>> + Send + Sync>;

pub struct Targets {
    current: Arc<Mutex<Vec<Option<SocketAddr>>>>,
}

impl Targets {
    /// Check `targets` are host:port, resolve them, and keep them resolved.
    pub fn spawn(targets: Vec<String>, every: Duration) -> anyhow::Result<Self> {
        let lookup: Lookup = Arc::new(|t: &str| t.to_socket_addrs().map(Iterator::collect));
        Self::spawn_with(targets, every, lookup)
    }

    fn spawn_with(targets: Vec<String>, every: Duration, lookup: Lookup) -> anyhow::Result<Self> {
        for t in &targets {
            check_syntax(t)?;
        }
        let resolve_all = {
            let lookup = lookup.clone();
            move |targets: &[String], current: &Mutex<Vec<Option<SocketAddr>>>| {
                for (i, t) in targets.iter().enumerate() {
                    let found = lookup(t).ok().and_then(|a| a.into_iter().next());
                    let mut cur = current.lock().unwrap();
                    match (found, cur[i]) {
                        (Some(new), Some(old)) if new != old => {
                            tracing::info!(target = %t, %old, %new, "monitor address changed")
                        }
                        (Some(new), None) => tracing::info!(target = %t, addr = %new, "sending"),
                        (None, None) => {
                            tracing::warn!(target = %t, "can't resolve yet; will retry")
                        }
                        _ => {}
                    }
                    // Keep the last good address while a lookup fails.
                    if found.is_some() {
                        cur[i] = found;
                    }
                }
            }
        };
        let current = Arc::new(Mutex::new(vec![None; targets.len()]));
        resolve_all(&targets, &current);
        let shared = current.clone();
        std::thread::Builder::new()
            .name("target-lookup".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(every);
                    resolve_all(&targets, &shared);
                }
            })?;
        Ok(Self { current })
    }

    /// The addresses to send to now (targets that haven't resolved yet are
    /// left out).
    pub fn current(&self) -> Vec<SocketAddr> {
        self.current
            .lock()
            .unwrap()
            .iter()
            .flatten()
            .copied()
            .collect()
    }
}

/// Reject a target that can never work (no port, a bad port) at start-up,
/// rather than retrying it forever.
fn check_syntax(target: &str) -> anyhow::Result<()> {
    if target.parse::<SocketAddr>().is_ok() {
        return Ok(());
    }
    let Some((host, port)) = target.rsplit_once(':') else {
        bail!("{target}: expected host:port");
    };
    if host.is_empty() || port.parse::<u16>().is_err() {
        bail!("{target}: expected host:port");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn wait_for(targets: &Targets, want: &[SocketAddr]) -> bool {
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while std::time::Instant::now() < deadline {
            if targets.current() == want {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    }

    #[test]
    fn follows_a_monitor_that_moves_and_waits_for_dns() {
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        // First lookup fails (DNS not up yet), then 10.0.0.1, then 10.0.0.2.
        let lookup: Lookup = Arc::new(move |_: &str| match c.fetch_add(1, Ordering::SeqCst) {
            0 => Err(std::io::Error::other("no DNS yet")),
            1 | 2 => Ok(vec!["10.0.0.1:9876".parse().unwrap()]),
            _ => Ok(vec!["10.0.0.2:9876".parse().unwrap()]),
        });
        let t = Targets::spawn_with(
            vec!["monitor.example:9876".into()],
            Duration::from_millis(20),
            lookup,
        )
        .expect("an unresolvable name doesn't stop the agent");
        assert!(t.current().is_empty(), "nothing to send to yet");
        assert!(wait_for(&t, &["10.0.0.1:9876".parse().unwrap()]));
        assert!(
            wait_for(&t, &["10.0.0.2:9876".parse().unwrap()]),
            "picked up the move"
        );
    }

    #[test]
    fn keeps_the_last_address_while_lookups_fail() {
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        let lookup: Lookup = Arc::new(move |_: &str| {
            if c.fetch_add(1, Ordering::SeqCst) == 0 {
                Ok(vec!["10.0.0.1:9876".parse().unwrap()])
            } else {
                Err(std::io::Error::other("DNS down"))
            }
        });
        let t =
            Targets::spawn_with(vec!["m:9876".into()], Duration::from_millis(10), lookup).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        assert!(calls.load(Ordering::SeqCst) > 3);
        assert_eq!(
            t.current(),
            ["10.0.0.1:9876".parse::<SocketAddr>().unwrap()]
        );
    }

    #[test]
    fn bad_targets_are_rejected_at_start() {
        for bad in [
            "monitor",
            "monitor:",
            ":9876",
            "monitor:port",
            "monitor:99999",
        ] {
            assert!(check_syntax(bad).is_err(), "{bad}");
        }
        for good in [
            "monitor:9876",
            "10.0.0.1:9876",
            "[::1]:9876",
            "[2001:db8::7]:1",
        ] {
            assert!(check_syntax(good).is_ok(), "{good}");
        }
    }
}
