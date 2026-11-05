//! net-pin: on a PC with several networks up at once (Wi-Fi, wired LAN, tethering, ...), pick the
//! network for general internet, pin each VPN's outer connection to a network with an optional
//! fail-closed kill switch, and route chosen destinations over a chosen network.
//!
//! The engine is `model` (pure planner), `sys` and `fw`; `service` runs it on every network change. Files in `%ProgramData%\net-pin`
//! (service / admin only): `config.toml`, `state.json` (values recorded before the first change),
//! `status.json`, `net-pin.log`.
pub mod fw;
pub mod model;
pub mod paths;
pub mod pipe;
pub mod service;
pub mod svc;
pub mod sys;

use anyhow::{Context, Result};
use model::{Action, Config, Plan, Snapshot, State};
use std::path::PathBuf;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn config_path() -> PathBuf { paths::data_dir().join("config.toml") }
pub fn state_path() -> PathBuf { paths::data_dir().join("state.json") }
pub fn status_path() -> PathBuf { paths::data_dir().join("status.json") }
pub fn log_path() -> PathBuf { paths::data_dir().join("net-pin.log") }

const LOG_MAX: u64 = 1 << 20;

/// One line in `net-pin.log` when this process may write there (service, admin console).
pub fn log(msg: impl AsRef<str>) {
    if !paths::may_write_data_dir() { return; }
    use std::io::Write;
    let p = log_path();
    if std::fs::metadata(&p).is_ok_and(|m| m.len() > LOG_MAX) { let _ = std::fs::rename(&p, p.with_extension("log.1")); }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&p) {
        let _ = writeln!(f, "{} {}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"), msg.as_ref());
    }
}

/// A console tool that never shows a window (the tray has no console).
pub fn hidden(exe: &str) -> std::process::Command {
    use std::os::windows::process::CommandExt;
    let mut c = std::process::Command::new(exe);
    c.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    c
}

/// `config.toml`, or the defaults (which change nothing) when there is none.
pub fn load_config() -> Result<Config> {
    match std::fs::read_to_string(config_path()) {
        Ok(s) => toml::from_str(s.trim_start_matches('\u{feff}')).with_context(|| format!("{}", config_path().display())),
        Err(_) => Ok(Config::default()),
    }
}

/// Writes `config.toml` (service or admin; the folder is admin-only).
pub fn save_config(cfg: &Config) -> Result<()> {
    paths::ensure_may_write_data_dir()?;
    std::fs::create_dir_all(paths::data_dir())?;
    let p = config_path();
    let tmp = p.with_extension("toml.tmp");
    std::fs::write(&tmp, toml::to_string_pretty(cfg)?)?;
    std::fs::rename(&tmp, &p)?;
    Ok(())
}

pub fn load_state() -> State {
    std::fs::read_to_string(state_path()).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

fn save_state(s: &State) -> Result<()> {
    let tmp = state_path().with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_string_pretty(s)?)?;
    std::fs::rename(&tmp, state_path())?;
    Ok(())
}

pub struct Report {
    pub cfg: Config,
    pub snap: Snapshot,
    pub state: State,
    pub plan: Plan,
}

/// Reads everything and plans (no admin needed).
pub fn report() -> Result<Report> {
    let cfg = load_config()?;
    let snap = sys::snapshot()?;
    let state = load_state();
    let plan = model::plan(&cfg, &snap, &state);
    Ok(Report { cfg, snap, state, plan })
}

/// Brings the system to the config (admin): records originals first, then runs each action;
/// a failed action is logged and the rest still run. Returns (done, failed).
pub fn reconcile() -> Result<(usize, usize)> {
    paths::ensure_may_write_data_dir()?;
    let r = report()?;
    if r.plan.actions.is_empty() { write_status(&r); return Ok((0, 0)); }
    let (mut ok, mut bad) = run(&r)?;
    // Old rules go once the new ones exist (`model::plan`): a second pass for those only.
    if bad == 0 {
        let r2 = report()?;
        if r2.plan.actions.iter().all(|a| matches!(a, Action::RemoveRule { .. })) && !r2.plan.actions.is_empty() {
            let (o, b) = run(&r2)?;
            (ok, bad) = (ok + o, bad + b);
        }
    }
    write_status(&report()?);
    Ok((ok, bad))
}

fn run(r: &Report) -> Result<(usize, usize)> {
    // Record before acting (crash-safe undo); routes go into the record before they exist.
    let rec = model::record(&r.state, &r.snap, &r.plan.actions, sys::policy().1);
    std::fs::create_dir_all(paths::data_dir())?;
    save_state(&rec).context("cannot record the original values; nothing changed")?;
    let (mut ok, mut bad) = (0, 0);
    let mut kept = rec.clone();
    for a in &r.plan.actions {
        match sys::apply(a) {
            Ok(()) => { ok += 1; log(format!("{a}")); }
            Err(e) => { bad += 1; log(format!("FAILED {a}: {e:#}")); }
        }
        if let Action::RemoveRoute(x) = a { kept.routes.retain(|o| o != x && !(o.prefix == x.prefix && o.len == x.len && o.index == x.index)); }
    }
    save_state(&kept)?;
    Ok((ok, bad))
}

/// Puts everything back as recorded and removes net-pin's rules and routes (admin).
pub fn undo() -> Result<Vec<String>> {
    paths::ensure_may_write_data_dir()?;
    let mut done = Vec::new();
    let r = report()?;
    let mut cfg = Config { enabled: false, keep_all_connected: false, ..r.cfg.clone() };
    for v in &mut cfg.vpns { v.locked = false; }
    let off = model::plan(&cfg, &r.snap, &r.state);
    for a in off.actions.iter().filter(|a| !matches!(a, Action::DisableRule { .. } | Action::RemoveRule { .. })) {
        match sys::apply(a) { Ok(()) => done.push(a.to_string()), Err(e) => done.push(format!("FAILED {a}: {e:#}")) }
    }
    done.push(format!("removed {} firewall rule(s)", fw::remove_all()?));
    if r.state.policy_recorded {
        sys::restore_policy(r.state.policy_key_existed, r.state.policy_old)?;
        done.push(format!("restored {} ({:?})", sys::POLICY_NAME, r.state.policy_old));
    }
    let _ = std::fs::remove_file(state_path());
    let _ = std::fs::remove_file(status_path());
    for d in &done { log(d); }
    Ok(done)
}

/// For the tray icon: ok, blocked (a kill-switched VPN's network is down, so it is held offline),
/// problem, off.
pub fn level(r: &Report) -> &'static str {
    if !r.cfg.enabled { return "off"; }
    if !r.plan.problems.is_empty() || !r.plan.actions.is_empty() { return "problem"; }
    let held = r.cfg.vpns.iter().any(|v| v.kill_switch && !r.snap.is_up(&r.cfg, &v.via));
    if held { "blocked" } else { "ok" }
}

/// One line: where things go now (or why nothing is done).
pub fn summary(r: &Report) -> String {
    model::summary(&r.cfg, &r.snap, &r.plan)
}

pub fn write_status(r: &Report) {
    let st = serde_json::json!({
        "version": VERSION,
        "time": chrono::Local::now().to_rfc3339(),
        "enabled": r.cfg.enabled,
        "mode": if r.cfg.enabled { "on" } else { "off" },
        "level": level(r),
        "summary": summary(r),
        "pins": model::pins(&r.cfg, &r.snap),
        "internet": r.plan.internet,
        "follow": r.plan.follow,
        "egress": r.snap.default_egress(&r.cfg).map(|a| a.alias.clone()),
        "pending": r.plan.actions.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
        "problems": r.plan.problems,
        "notes": r.plan.notes,
        "networks": r.cfg.networks.iter().map(|n| n.name.clone()).collect::<Vec<_>>(),
    });
    let _ = std::fs::write(status_path(), serde_json::to_string_pretty(&st).unwrap_or_default());
}
