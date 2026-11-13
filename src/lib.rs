//! net-pin: on a PC with several networks up at once (Wi-Fi, wired LAN, tethering, ...), pick the
//! network for general internet, pin each VPN's outer connection to a network with an optional
//! fail-closed kill switch, and route chosen destinations over a chosen network.
//!
//! The engine is `model` (pure planner), `sys` and `fw`; `service` runs it on every network change. Files in `%ProgramData%\net-pin`
//! (service / admin only): `config.toml`, `state.json` (values recorded before the first change),
//! `status.json`, `net-pin.log`; with the optional memory feature (`memory`, `ram`) also `service.toml`
//! and `ondemand.json`.
pub mod fw;
pub mod memory;
pub mod model;
pub mod paths;
pub mod pipe;
pub mod ram;
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
    // Feature threads log at the same time; one line at a time.
    static ONE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _one = ONE.lock().unwrap_or_else(|e| e.into_inner());
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

/// Reads everything and plans (no admin needed). Programs with `*` are planned as the files they
/// match now (a VPN's version folder changes with its updates); `cfg` keeps the patterns.
pub fn report() -> Result<Report> {
    let cfg = load_config()?;
    let snap = sys::snapshot()?;
    let state = load_state();
    let (expanded, missing) = expand_programs(&cfg);
    let mut plan = model::plan(&expanded, &snap, &state);
    plan.notes.extend(missing.into_iter().map(|m| format!("no program matches {m}")));
    Ok(Report { cfg, snap, state, plan })
}

/// The config with each VPN's `*` programs replaced by the files they match, and the patterns
/// that match nothing.
pub fn expand_programs(cfg: &model::Config) -> (model::Config, Vec<String>) {
    let mut out = cfg.clone();
    let mut missing = Vec::new();
    for v in &mut out.vpns {
        let mut list = Vec::new();
        for p in v.all_programs() {
            if !p.contains('*') { list.push(p); continue; }
            let found = expand_path(&p);
            if found.is_empty() { missing.push(p); }
            list.extend(found);
        }
        v.set_programs(list);
    }
    (out, missing)
}

/// Files matching `pat`, where `*` matches within one path component.
fn expand_path(pat: &str) -> Vec<String> {
    let parts: Vec<&str> = pat.split(['\\', '/']).filter(|s| !s.is_empty()).collect();
    let Some((first, rest)) = parts.split_first() else { return Vec::new() };
    let mut at = vec![std::path::PathBuf::from(format!("{first}\\"))];
    for part in rest {
        let mut next = Vec::new();
        for dir in &at {
            if !part.contains('*') { next.push(dir.join(part)); continue; }
            let Ok(rd) = std::fs::read_dir(dir) else { continue };
            for e in rd.flatten() {
                if model::glob(part, &e.file_name().to_string_lossy()) { next.push(e.path()); }
            }
        }
        at = next;
    }
    let mut v: Vec<String> = at.into_iter().filter(|p| p.is_file()).map(|p| p.display().to_string()).collect();
    v.sort();
    v
}

/// Running programs with a path, once each, by file name: (name, path).
pub fn running_programs() -> Vec<(String, String)> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::*;
    use windows::Win32::System::Threading::*;
    let mut out: Vec<(String, String)> = Vec::new();
    unsafe {
        let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else { return out };
        let mut e = PROCESSENTRY32W { dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
        let mut more = Process32FirstW(snap, &mut e).is_ok();
        let map = device_map();
        while more {
            let pid = e.th32ProcessID;
            let mut path = None;
            if let Ok(h) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                let mut buf = [0u16; 1024];
                let mut n = buf.len() as u32;
                if QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, windows::core::PWSTR(buf.as_mut_ptr()), &mut n).is_ok() {
                    path = Some(String::from_utf16_lossy(&buf[..n as usize]));
                }
                let _ = CloseHandle(h);
            }
            // Services a user may not open (a VPN's own service, often) still have a kernel image name.
            if path.is_none() && pid > 4 { path = nt_image_path(pid).map(|p| nt_to_dos(&p, &map)); }
            if let Some(path) = path && !out.iter().any(|x| x.1.eq_ignore_ascii_case(&path)) {
                let name = path.rsplit('\\').next().unwrap_or(&path).to_string();
                out.push((name, path));
            }
            more = Process32NextW(snap, &mut e).is_ok();
        }
        let _ = CloseHandle(snap);
    }
    out.sort_by_key(|x| x.0.to_lowercase());
    out
}

/// A process's image as an NT path (`\Device\HarddiskVolumeN\...`), without opening it.
fn nt_image_path(pid: u32) -> Option<String> {
    use windows::Wdk::System::SystemInformation::{NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS};
    use windows::Win32::Foundation::UNICODE_STRING;
    #[repr(C)]
    struct IdInfo { pid: usize, name: UNICODE_STRING }
    let mut buf = vec![0u16; 1024];
    let mut info = IdInfo { pid: pid as usize, name: UNICODE_STRING { Length: 0, MaximumLength: (buf.len() * 2) as u16, Buffer: windows::core::PWSTR(buf.as_mut_ptr()) } };
    // 88 = SystemProcessIdInformation
    let st = unsafe { NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS(88), (&mut info as *mut IdInfo).cast(), size_of::<IdInfo>() as u32, std::ptr::null_mut()) };
    if st.0 < 0 { return None; }
    let s = String::from_utf16_lossy(&buf[..info.name.Length as usize / 2]);
    if s.is_empty() { None } else { Some(s) }
}

/// `\Device\HarddiskVolumeN` -> `C:` for every mounted drive letter.
fn device_map() -> Vec<(String, String)> {
    use windows::Win32::Storage::FileSystem::QueryDosDeviceW;
    let mut v = Vec::new();
    for l in b'A'..=b'Z' {
        let drive = format!("{}:", l as char);
        let mut buf = [0u16; 512];
        let n = unsafe { QueryDosDeviceW(&windows::core::HSTRING::from(drive.as_str()), Some(&mut buf)) };
        if n > 0 {
            let end = buf.iter().position(|&c| c == 0).unwrap_or(0);
            v.push((String::from_utf16_lossy(&buf[..end]), drive));
        }
    }
    v
}

fn nt_to_dos(nt: &str, map: &[(String, String)]) -> String {
    for (dev, drive) in map {
        if let Some(rest) = nt.strip_prefix(dev.as_str()) && rest.starts_with('\\') { return format!("{drive}{rest}"); }
    }
    nt.to_string()
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
