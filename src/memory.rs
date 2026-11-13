//! The optional memory feature in the service: its switch (`memory` in `service.toml`, off by
//! default; the installer's "Memory" option or `net-pin feature memory on`) and the thread that runs
//! the on-demand loop (`ram::daemon`) while it is on. Switching it off puts every managed family
//! back on (the recorded originals stay, so switching it on again manages them again); stopping
//! the service leaves them as they are (the next start re-applies them).
use crate::ram;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Features {
    pub memory: bool,
}

impl Features {
    pub fn path() -> std::path::PathBuf { crate::paths::data_dir().join("service.toml") }

    /// Users may read it (the tray shows the memory menu only while it is on).
    pub fn load() -> Self {
        std::fs::read_to_string(Self::path()).ok()
            .and_then(|s| toml::from_str(s.trim_start_matches('\u{feff}')).ok()).unwrap_or_default()
    }

    /// Service or admin only (the folder is admin-only).
    pub fn save(&self) -> Result<()> {
        crate::paths::ensure_may_write_data_dir()?;
        std::fs::create_dir_all(crate::paths::data_dir())?;
        let p = Self::path();
        let tmp = p.with_extension("toml.tmp");
        std::fs::write(&tmp, toml::to_string_pretty(self)?)?;
        std::fs::rename(&tmp, &p)?;
        Ok(())
    }
}

static ON: AtomicBool = AtomicBool::new(false);
static QUIT: AtomicBool = AtomicBool::new(false);
/// The running daemon loop's sender, for the pipe.
pub static SLOT: LazyLock<ram::pipe::Slot> = LazyLock::new(|| Arc::new(Mutex::new(None)));

pub fn on() -> bool { ON.load(Ordering::SeqCst) }

/// Saves the switch and starts / stops the loop (within half a second).
pub fn set(on: bool) -> Result<String> {
    let mut f = Features::load();
    f.memory = on;
    f.save()?;
    ON.store(on, Ordering::SeqCst);
    crate::log(format!("memory feature {}", if on { "on" } else { "off" }));
    Ok(format!("memory {}", if on { "on" } else { "off: managed families are back on" }))
}

fn pause(d: Duration) {
    let until = Instant::now() + d;
    while Instant::now() < until && !QUIT.load(Ordering::SeqCst) && on() { std::thread::sleep(Duration::from_millis(500)); }
}

/// One run of the loop, until the feature is switched off or the service stops.
fn run_once() -> Result<()> {
    let done = Arc::new(AtomicBool::new(false));
    let d = done.clone();
    let r = ram::daemon::run(move |tx| {
        *SLOT.lock().unwrap() = Some(tx.clone());
        // The loop listens on a channel; turn "off" / "quit" into its Stop message.
        std::thread::spawn(move || {
            while on() && !QUIT.load(Ordering::SeqCst) && !d.load(Ordering::SeqCst) { std::thread::sleep(Duration::from_millis(500)); }
            let _ = tx.send(ram::daemon::Msg::Stop);
        });
    }, false);
    done.store(true, Ordering::SeqCst);
    *SLOT.lock().unwrap() = None;
    r
}

/// Keel does the same job (its memory feature); two managers of one family would each record the
/// other's changes as originals. While Keel's service is installed, this feature waits.
fn keel_installed() -> bool {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .is_ok_and(|m| m.open_service("Keel", ServiceAccess::QUERY_STATUS).is_ok())
}

/// Starts the feature's thread (the service, `net-pin daemon`); `stop()` ends it.
pub fn spawn() -> std::thread::JoinHandle<()> {
    ON.store(Features::load().memory, Ordering::SeqCst);
    QUIT.store(false, Ordering::SeqCst);
    std::thread::spawn(|| {
        let mut wait = Duration::from_secs(10);
        let mut said = false;
        while !QUIT.load(Ordering::SeqCst) {
            if !on() { std::thread::sleep(Duration::from_millis(500)); continue; }
            if keel_installed() {
                if !std::mem::replace(&mut said, true) { ram::daemon::log("waiting: Keel is installed and manages app families itself"); }
                pause(Duration::from_secs(60));
                continue;
            }
            said = false;
            let r = std::panic::catch_unwind(run_once);
            *SLOT.lock().unwrap() = None;
            if QUIT.load(Ordering::SeqCst) { break; }
            if !on() {
                for l in ram::daemon::release_all() { ram::daemon::log(l); }
                wait = Duration::from_secs(10);
                continue;
            }
            // Still on: the loop failed. Again after a pause (10 s, doubling up to 10 min).
            let msg = match r { Ok(Ok(())) => "stopped".to_string(), Ok(Err(e)) => format!("{e:#}"), Err(_) => "panic".into() };
            ram::daemon::log(format!("{msg}; again in {} s", wait.as_secs()));
            pause(wait);
            wait = (wait * 2).min(Duration::from_secs(600));
        }
    })
}

/// Ends the feature's thread without putting families back (the service is stopping).
pub fn stop(h: std::thread::JoinHandle<()>) {
    QUIT.store(true, Ordering::SeqCst);
    let _ = h.join();
}

#[cfg(test)]
mod tests {
    #[test]
    fn off_unless_chosen() {
        assert!(!super::Features::default().memory);
        let f: super::Features = toml::from_str("").unwrap();
        assert!(!f.memory);
        let f: super::Features = toml::from_str("memory = true").unwrap();
        assert!(f.memory);
    }
}
