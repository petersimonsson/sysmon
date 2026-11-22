//! The journalctl the agent runs for --logs doesn't outlive it.

use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

/// Whether `pid` is still running (and not just a zombie).
fn running(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|s| {
        s.rsplit(')')
            .next()
            .is_some_and(|r| !r.trim_start().starts_with('Z'))
    })
}

#[test]
fn journalctl_stops_when_the_agent_is_killed() {
    let dir = std::env::temp_dir().join(format!("sysmon-pdeath-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // A stand-in journalctl, found first on PATH, that says where it is and
    // then waits like `journalctl --follow` with nothing to show.
    let fake = dir.join("journalctl");
    std::fs::write(
        &fake,
        format!(
            "#!/bin/sh\necho $$ > {}\nexec sleep 60\n",
            dir.join("pid").display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!(
        "{}:{}",
        dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let mut agent = std::process::Command::new(env!("CARGO_BIN_EXE_sysmon-agent"))
        .args(["-t", "127.0.0.1:9", "--logs", "--logs-unencrypted"])
        .env("PATH", path)
        .env_remove("STATE_DIRECTORY")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let pid: u32 = loop {
        if let Some(p) = std::fs::read_to_string(dir.join("pid"))
            .ok()
            .and_then(|s| s.trim().parse().ok())
        {
            break p;
        }
        assert!(Instant::now() < deadline, "journalctl never started");
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(running(pid));

    // SIGKILL: the agent gets no chance to clean up itself.
    agent.kill().unwrap();
    agent.wait().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while running(pid) {
        assert!(Instant::now() < deadline, "journalctl outlived the agent");
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = std::fs::remove_dir_all(&dir);
}
