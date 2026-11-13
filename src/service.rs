//! The service's work: re-applies the config after every network change
//! (interface, address and route notifications from IP Helper, no polling; plus a 5-minute check
//! for adapters that appeared without a notification), and answers the tray and the `net-pin`
//! command on the control pipe.
use crate::model::Config;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::IpHelper::*;
use windows::Win32::Networking::WinSock::AF_INET;

/// Notifications must stop this long before acting (a link coming up sends a burst).
const QUIET: Duration = Duration::from_secs(3);
/// At most one reconcile this often (our own changes notify too; the second pass is a no-op).
const MIN_GAP: Duration = Duration::from_secs(10);
const CHECK_EVERY: Duration = Duration::from_secs(300);

static EVENTS: AtomicU64 = AtomicU64::new(0);
/// Serializes reconcile / config writes between the watch loop and pipe requests.
static WORK: Mutex<()> = Mutex::new(());

unsafe extern "system" fn on_change(_: *const core::ffi::c_void, _: *const core::ffi::c_void, _: MIB_NOTIFICATION_TYPE) {
    EVENTS.fetch_add(1, Ordering::SeqCst);
}
unsafe extern "system" fn on_iface(c: *const core::ffi::c_void, r: *const MIB_IPINTERFACE_ROW, t: MIB_NOTIFICATION_TYPE) { unsafe { on_change(c, r.cast(), t) } }
unsafe extern "system" fn on_route(c: *const core::ffi::c_void, r: *const MIB_IPFORWARD_ROW2, t: MIB_NOTIFICATION_TYPE) { unsafe { on_change(c, r.cast(), t) } }
unsafe extern "system" fn on_addr(c: *const core::ffi::c_void, r: *const MIB_UNICASTIPADDRESS_ROW, t: MIB_NOTIFICATION_TYPE) { unsafe { on_change(c, r.cast(), t) } }

struct Notifications(Vec<HANDLE>);

impl Notifications {
    fn register() -> Result<Self> {
        let mut v = Vec::new();
        unsafe {
            let mut h = HANDLE::default();
            NotifyIpInterfaceChange(AF_INET, Some(on_iface), None, false, &mut h).ok().context("NotifyIpInterfaceChange")?;
            v.push(h);
            let mut h = HANDLE::default();
            NotifyRouteChange2(AF_INET, Some(on_route), std::ptr::null(), false, &mut h).ok().context("NotifyRouteChange2")?;
            v.push(h);
            let mut h = HANDLE::default();
            NotifyUnicastIpAddressChange(AF_INET, Some(on_addr), None, false, &mut h).ok().context("NotifyUnicastIpAddressChange")?;
            v.push(h);
        }
        Ok(Self(v))
    }
}

impl Drop for Notifications {
    fn drop(&mut self) { for h in &self.0 { unsafe { let _ = CancelMibChangeNotify2(*h); } } }
}

/// One pass: brings the system to the config.
fn pass(why: &str) {
    let _w = WORK.lock().unwrap();
    match crate::reconcile() {
        Ok((0, 0)) => {}
        Ok((ok, bad)) => crate::log(format!("{why}: {ok} change(s), {bad} failed")),
        Err(e) => crate::log(format!("{why}: {e:#}")),
    }
}

/// Gives back the pages a pass touched (the firewall COM DLLs are most of them); RAM is scarce.
fn trim() {
    use windows::Win32::System::Threading::{GetCurrentProcess, SetProcessWorkingSetSize};
    unsafe { let _ = SetProcessWorkingSetSize(GetCurrentProcess(), usize::MAX, usize::MAX); }
}

/// The loop; returns once `stop` is set.
pub fn watch(stop: &AtomicBool) -> Result<()> {
    let _n = Notifications::register()?;
    pass("start");
    trim();
    let (mut seen, mut changed_at, mut last_pass) = (EVENTS.load(Ordering::SeqCst), None::<Instant>, Instant::now());
    let mut next_check = Instant::now() + CHECK_EVERY;
    while !stop.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(500));
        let now_events = EVENTS.load(Ordering::SeqCst);
        if now_events != seen { seen = now_events; changed_at = Some(Instant::now()); }
        let settled = changed_at.is_some_and(|t| t.elapsed() >= QUIET) && last_pass.elapsed() >= MIN_GAP;
        if settled || Instant::now() >= next_check {
            pass(if settled { "network change" } else { "check" });
            trim();
            changed_at = None;
            last_pass = Instant::now();
            next_check = Instant::now() + CHECK_EVERY;
        }
    }
    Ok(())
}

/// The whole service until `stop` is set (the SCM, or `net-pin daemon` in a console): the pipe,
/// and the watch loop, restarted after a failure or panic (10 s, doubling up to 10 min).
pub fn run(stop: &AtomicBool) -> Result<()> {
    crate::paths::create_data_dir()?;
    crate::log(format!("service {} started", crate::VERSION));
    crate::pipe::serve(handler());
    let memory = crate::memory::spawn();
    let mut wait = Duration::from_secs(10);
    while !stop.load(Ordering::SeqCst) {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| watch(stop)));
        let msg = match r { Ok(Ok(())) => break, Ok(Err(e)) => format!("{e:#}"), Err(_) => "panic".into() };
        crate::log(format!("watch stopped: {msg}; again in {} s", wait.as_secs()));
        let until = Instant::now() + wait;
        while Instant::now() < until && !stop.load(Ordering::SeqCst) { std::thread::sleep(Duration::from_millis(500)); }
        wait = (wait * 2).min(Duration::from_secs(600));
    }
    crate::memory::stop(memory);
    crate::log("service stopped");
    Ok(())
}

// ------------------------------------------------------------------ pipe

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "kebab-case")]
pub enum Request {
    /// The current report and the config.
    Status,
    /// Re-apply now.
    Apply,
    /// Change the network for general internet (empty = Windows decides).
    SetInternet { network: String },
    /// Turn routing on or off (off restores metrics, removes routes, disables rules).
    SetEnabled { enabled: bool },
    /// Replace the whole config (the `net-pin` command's vpn / route / set changes).
    SetConfig { config: Config },
    /// Switch an optional feature of the service (only `memory`).
    SetFeature { name: String, on: bool },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Reply {
    pub ok: bool,
    pub message: String,
    pub version: String,
    pub config: Option<Config>,
    pub level: String,
    pub summary: String,
    pub pins: Vec<crate::model::Pin>,
    pub internet: Option<String>,
    pub follow: Option<String>,
    pub networks: Vec<String>,
    pub pending: Vec<String>,
    pub problems: Vec<String>,
    pub notes: Vec<String>,
    /// The optional memory feature is on.
    pub memory: bool,
}

fn status(ok: bool, message: impl Into<String>) -> Reply {
    let mut r = Reply { ok, message: message.into(), version: crate::VERSION.into(), memory: crate::memory::on(), ..Default::default() };
    match crate::report() {
        Ok(rep) => {
            r.level = crate::level(&rep).into();
            r.summary = crate::summary(&rep);
            r.pins = crate::model::pins(&rep.cfg, &rep.snap);
            r.internet = rep.plan.internet;
            r.follow = rep.plan.follow;
            r.pending = rep.plan.actions.iter().map(|a| a.to_string()).collect();
            r.problems = rep.plan.problems.clone();
            r.notes = rep.plan.notes.clone();
            r.networks = rep.cfg.networks.iter().map(|n| n.name.clone()).collect();
            r.config = Some(rep.cfg);
        }
        Err(e) => r.summary = format!("{e:#}"),
    }
    r
}

/// Locked VPNs, and the networks they use, may not be changed through the pipe (its clients are
/// ordinary users): only by an admin editing `config.toml`.
pub fn check_config(old: &Config, new: &Config) -> Result<()> {
    for v in old.vpns.iter().filter(|v| v.locked) {
        anyhow::ensure!(new.vpns.iter().any(|n| n == v),
            "{} is locked: change it by editing {} as administrator, then `net-pin apply`", v.name, crate::config_path().display());
        anyhow::ensure!(old.network(&v.via) == new.network(&v.via),
            "network {:?} is used by the locked VPN {}: change it by editing {} as administrator", v.via, v.name, crate::config_path().display());
    }
    Ok(())
}

fn change(f: impl FnOnce(&mut Config)) -> Result<String> {
    let _w = WORK.lock().unwrap();
    let old = crate::load_config()?;
    let mut cfg = old.clone();
    f(&mut cfg);
    check_config(&old, &cfg)?;
    crate::save_config(&cfg)?;
    crate::log(format!("config changed: internet {}, {}", if cfg.internet.is_empty() { "Windows default" } else { &cfg.internet }, if cfg.enabled { "on" } else { "off" }));
    let (ok, bad) = crate::reconcile()?;
    Ok(format!("saved and applied: {ok} change(s){}", if bad > 0 { format!(", {bad} failed (see the log)") } else { String::new() }))
}

fn answer(req: Request) -> Reply {
    let r: Result<String> = match req {
        Request::Status => Ok("ok".into()),
        Request::Apply => {
            let _w = WORK.lock().unwrap();
            crate::reconcile().map(|(ok, bad)| format!("{ok} change(s), {bad} failed"))
        }
        Request::SetInternet { network } => change(|c| c.internet = network),
        Request::SetEnabled { enabled } => change(|c| c.enabled = enabled),
        Request::SetConfig { config } => change(|c| *c = config),
        Request::SetFeature { name, on } if name == "memory" => crate::memory::set(on),
        Request::SetFeature { name, .. } => Err(anyhow::anyhow!("no feature {name:?} (only memory)")),
    };
    match r { Ok(m) => status(true, m), Err(e) => status(false, format!("{e:#}")) }
}

pub fn handler() -> crate::pipe::Handler {
    Arc::new(|body: Value| {
        if let Some(b) = crate::ram::pipe::body_of(&body) { return crate::ram::pipe::handle(&crate::memory::SLOT, b); }
        let r = match serde_json::from_value::<Request>(body) {
            Ok(req) => answer(req),
            Err(e) => Reply { message: format!("bad request: {e}"), ..Default::default() },
        };
        serde_json::to_value(r).unwrap_or(Value::Null)
    })
}

/// Client side (tray, `net-pin`).
pub fn call(req: &Request) -> Result<Reply> {
    Ok(serde_json::from_value(crate::pipe::call(&serde_json::to_value(req)?)?)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_vpns_and_their_networks_stay() {
        let mut old = Config::default();
        crate::model::preset("tailscale-wifi", &mut old).unwrap();
        let mut new = old.clone();
        new.vpns.clear();
        assert!(check_config(&old, &new).is_err(), "removed");
        let mut new = old.clone();
        new.vpns[0].via = "lan".into();
        assert!(check_config(&old, &new).is_err(), "moved");
        let mut new = old.clone();
        new.networks[0].kind = crate::model::Kind::Any;
        assert!(check_config(&old, &new).is_err(), "its network redefined");
        let mut new = old.clone();
        new.internet = "wifi".into();
        new.enabled = false;
        assert!(check_config(&old, &new).is_ok(), "everything else is free");
    }

    #[test]
    fn requests_round_trip() {
        let v = serde_json::to_value(Request::SetInternet { network: "wifi".into() }).unwrap();
        assert_eq!(v, serde_json::json!({ "cmd": "set-internet", "network": "wifi" }));
        assert!(matches!(serde_json::from_value::<Request>(serde_json::json!({ "cmd": "status" })).unwrap(), Request::Status));
    }
}
