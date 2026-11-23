//! uid → user name through the system's user database (NSS: `/etc/passwd`,
//! systemd's dynamic and homed users, LDAP/SSSD, …), as configured in
//! `/etc/nsswitch.conf`.
//!
//! A directory lookup can be slow, or hang while a server is unreachable, so
//! lookups run on their own thread and the sampling loop only reads a cache.
//! A uid shows as a number until its name arrives.
//!
//! musl's libc has no NSS modules, so a static musl build resolves only
//! users in `/etc/passwd` (or through nscd, if it's running).

use std::collections::{HashMap, HashSet};
use std::ffi::CStr;
use std::sync::{Arc, Mutex, mpsc};

pub struct UserNames {
    names: Arc<Mutex<HashMap<u32, String>>>,
    requested: HashSet<u32>,
    lookups: mpsc::Sender<u32>,
}

impl UserNames {
    pub fn spawn() -> std::io::Result<Self> {
        let names = Arc::new(Mutex::new(HashMap::new()));
        let (lookups, rx) = mpsc::channel::<u32>();
        let shared = names.clone();
        std::thread::Builder::new()
            .name("user-lookup".into())
            .spawn(move || {
                for uid in rx {
                    match lookup(uid) {
                        Some(name) => {
                            shared.lock().unwrap().insert(uid, name);
                        }
                        None => {
                            shared.lock().unwrap().remove(&uid);
                        }
                    }
                }
            })?;
        Ok(Self {
            names,
            requested: HashSet::new(),
            lookups,
        })
    }

    /// The name for `uid` if known. The first call for a uid starts a lookup.
    pub fn get(&mut self, uid: u32) -> Option<String> {
        if self.requested.insert(uid) {
            let _ = self.lookups.send(uid);
        }
        self.names.lock().unwrap().get(&uid).cloned()
    }

    /// Look every uid up again on its next `get` (names rarely change, but
    /// users can be renamed or come and go).
    pub fn refresh(&mut self) {
        self.requested.clear();
    }
}

/// `getpwuid_r`, growing the buffer as needed.
fn lookup(uid: u32) -> Option<String> {
    // SAFETY: sysconf has no preconditions.
    let hint = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let mut buf = vec![0u8; if hint > 0 { hint as usize } else { 1024 }];
    loop {
        // SAFETY: `pwd` and `result` are written by getpwuid_r; `buf` outlives
        // the borrow of `pwd.pw_name`, which points into it.
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let rc = unsafe {
            libc::getpwuid_r(
                uid,
                &mut pwd,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut result,
            )
        };
        if rc == libc::ERANGE && buf.len() < 1 << 20 {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if rc != 0 || result.is_null() || pwd.pw_name.is_null() {
            return None;
        }
        let name = unsafe { CStr::from_ptr(pwd.pw_name) };
        return Some(name.to_string_lossy().into_owned());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn looks_up_users_like_the_system() {
        assert_eq!(lookup(0).as_deref(), Some("root"));
        assert_eq!(lookup(u32::MAX - 7), None);
        // This process's own user resolves, whatever database it's in.
        let me = unsafe { libc::getuid() };
        assert!(lookup(me).is_some());
    }

    #[test]
    fn names_arrive_from_the_background_thread() {
        let mut users = UserNames::spawn().unwrap();
        assert_eq!(users.get(0), None, "not resolved on the first call");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while users.get(0).is_none() {
            assert!(
                std::time::Instant::now() < deadline,
                "lookup never finished"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(users.get(0).as_deref(), Some("root"));
    }
}
