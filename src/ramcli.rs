//! `net-pin ram ...`: the optional memory feature's commands (ported from Keel's `keel ram`).
use anyhow::{Result, bail};
use net_pin::ram::{cleanup, daemon, events, family, observe, ondemand, pipe, prefs::Prefs, scan, single, trayicons, userside};

const HELP: &str = "\
net-pin ram - memory hogs, their launchers, app families, leaks, on-demand families

The memory feature is optional: `net-pin feature memory on|off` (or the installer's Memory option)
switches the service's part (on-demand families) and the tray's memory samples. scan, family,
cleanup, sample, leaks and tray-icons work without it.

USAGE (nothing here needs an administrator prompt; cleanup only writes scripts)
  net-pin ram scan [--top N] [--sort private|ws] [--json <path>] [--no-size]
        top N processes (default 25) by private bytes (default) or working set, with
        parent, session, hosted services, launchers (Run/RunOnce, services, scheduled tasks,
        Startup folder) and current TCP/UDP endpoints; then families: everything one vendor /
        product suite installed (processes, services, drivers, Run items, tasks, products,
        folders) with memory and disk totals. --json writes the full report;
        --no-size skips measuring folder sizes.
  net-pin ram family <name> [--no-size]
        every member of the families whose name contains <name>
  net-pin ram sample                  record one sample now (memory, handles, GPU memory per adapter)
  net-pin ram watch                   record a sample every 5 minutes and display / power / TDR
                                         events until stopped (the tray does this while memory is on)
  net-pin ram leaks [--hours N]       processes whose memory / handles / GPU memory keep growing
                                         over the last N hours (default 6), with their family
        samples: %LOCALAPPDATA%\\net-pin\\samples\\YYYYMMDD.jsonl
  net-pin ram history on|off          keep a week of samples across restarts (off: this session
                                         and the one before)
  net-pin ram fast on|off             sample every minute instead of every 5 minutes
  net-pin ram tray-icons [--prune]    entries per app in Settings > Taskbar > Other system tray
                                         icons; --prune keeps one per app that has 10+ (backup first)
  net-pin ram cleanup <name> [--out <dir>]
        writes disable.ps1 + undo.ps1 (+ plan.json) for one family; changes nothing itself.
        disable.ps1 backs up first, then disables services / tasks / startup items (never deletes,
        never touches drivers). Run it yourself in an admin PowerShell. Default folder:
        %LOCALAPPDATA%\\net-pin\\cleanup\\<family>-<time>

ON-DEMAND FAMILIES (need the service with memory on)
  net-pin ram ondemand                families under on-demand control and whether they are on
  net-pin ram ondemand <family> off   keep its services Disabled, tasks and startup items off
  net-pin ram ondemand <family> follow --app <exe> [--app <exe>]
                                       off, but on while one of these apps runs (and 20 s after)
  net-pin ram ondemand <family> start | stop   switch on / off now
  net-pin ram ondemand <family> normal   put everything back as it was and stop managing it
        Originals are saved before any change (%ProgramData%\\net-pin\\ondemand.json). Drivers
        and protected families are never switched. Something that turns a managed service or task
        back on is switched off again within 5 minutes (logged in net-pin.log).
  net-pin ram daemon                * the on-demand loop alone in this console (stop the service
                                         first; test with NETPIN_DATA=<scratch dir>)
  net-pin ram help
";

fn opt(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

fn on_off(s: Option<&String>) -> Result<bool> {
    match s.map(String::as_str) { Some("on") => Ok(true), Some("off") => Ok(false), _ => bail!("expected on or off") }
}

fn cmd_scan(args: &[String]) -> Result<()> {
    let top = match opt(args, "--top") { Some(n) => n.parse()?, None => 25 };
    let sort = match opt(args, "--sort").as_deref() {
        None | Some("private") => scan::SortBy::Private,
        Some("ws") => scan::SortBy::WorkingSet,
        Some(x) => bail!("unknown --sort {x} (private | ws)"),
    };
    let report = scan::run(top, sort, !args.iter().any(|a| a == "--no-size"))?;
    scan::print(&report);
    if let Some(path) = opt(args, "--json") {
        std::fs::write(&path, serde_json::to_string_pretty(&report)?)?;
        println!("\nfull report: {path}");
    }
    Ok(())
}

/// Writes a text file as UTF-8 with BOM and CRLF (what Windows PowerShell 5.1 reads correctly).
fn write_ps(path: &std::path::Path, text: &str) -> Result<()> {
    let body = text.replace("\r\n", "\n").replace('\n', "\r\n");
    std::fs::write(path, [b"\xEF\xBB\xBF".as_slice(), body.as_bytes()].concat())?;
    Ok(())
}

/// Samples and records display / power / driver events until stopped; one instance per user
/// session (the tray's observer holds the same lock).
fn cmd_watch() -> Result<()> {
    let Some(_one) = single::acquire(events::LOCK) else {
        bail!("memory samples are already recorded in this session (the tray, or another `net-pin ram watch`)")
    };
    println!("sampling every {} min into {}, events into {} (Ctrl+C to stop)",
        observe::INTERVAL_SECS / 60, observe::dir().display(), events::dir().display());
    events::watch()
}

/// The one family whose name (or key) is `q`, or the only one containing it.
fn pick_family(q: &str) -> Result<family::Family> {
    let report = scan::run(0, scan::SortBy::Private, false)?;
    let ql = q.to_lowercase();
    let exact: Vec<_> = report.families.iter().filter(|f| f.name.to_lowercase() == ql || f.key == ql).collect();
    let hits: Vec<_> = if exact.is_empty() { report.families.iter().filter(|f| f.name.to_lowercase().contains(&ql)).collect() } else { exact };
    match hits.as_slice() {
        [f] => Ok(family::Family { members: f.members.clone(), counts: f.counts.clone(), uninstallers: f.uninstallers.clone(), name: f.name.clone(), key: f.key.clone(), ..**f }),
        [] => bail!("no family matches {q}"),
        many => bail!("{q} matches several families: {}", many.iter().map(|f| f.name.as_str()).collect::<Vec<_>>().join(", ")),
    }
}

fn print_ondemand(st: &ondemand::State) {
    if st.entries.is_empty() { println!("no on-demand families"); return; }
    println!("{:<28} {:<7} {:<4} {:>4} {:>5} {:>8}  APPS", "FAMILY", "MODE", "NOW", "SVC", "TASKS", "STARTUP");
    for e in &st.entries {
        println!("{:<28} {:<7} {:<4} {:>4} {:>5} {:>8}  {}", scan::clip(&e.family, 28), format!("{:?}", e.mode).to_lowercase(),
            if e.on { "on" } else { "off" }, e.services.len(), e.tasks.iter().filter(|t| t.enabled).count(), e.startup.len(), e.apps.join(", "));
    }
}

fn cmd_ondemand(args: &[String]) -> Result<()> {
    let Some(q) = args.first().filter(|a| !a.starts_with("--")) else {
        match pipe::call(&ondemand::Request::Status) {
            Ok(r) if r.ok => print_ondemand(&r.state),
            Ok(r) => { println!("{}\nlast saved state:", r.message); print_ondemand(&daemon::load()); }
            Err(e) => { println!("{e:#}\nlast saved state:"); print_ondemand(&daemon::load()); }
        }
        return Ok(());
    };
    let action = args.get(1).map(String::as_str).unwrap_or("");
    let f = pick_family(q)?;
    let parts = ondemand::parts(&f).map_err(anyhow::Error::msg)?;
    let apps: Vec<String> = args.windows(2).filter(|w| w[0] == "--app").map(|w| w[1].clone()).collect();
    let req = match action {
        "off" => ondemand::Request::Set { family: f.name.clone(), key: f.key.clone(), mode: Some(ondemand::Mode::Off), apps },
        "follow" => {
            if apps.is_empty() {
                bail!("follow needs the app that switches {} on: --app <exe> (repeatable). Its startup items start: {}",
                    f.name, if parts.app_hints.is_empty() { "-".into() } else { parts.app_hints.join(", ") });
            }
            ondemand::Request::Set { family: f.name.clone(), key: f.key.clone(), mode: Some(ondemand::Mode::Follow), apps }
        }
        "normal" => ondemand::Request::Set { family: f.name.clone(), key: f.key.clone(), mode: None, apps },
        "start" | "stop" => ondemand::Request::Turn { key: f.key.clone(), on: action == "start" },
        _ => bail!("usage: net-pin ram ondemand <family> off | follow --app <exe> | normal | start | stop"),
    };
    // A new family takes the service a scan.
    let r = pipe::call_wait(&req, std::time::Duration::from_secs(60))?;
    println!("{}", r.message);
    match action {
        "off" | "follow" if r.ok && !parts.hkcu.is_empty() => { userside::user_off(&f.key, &parts.hkcu)?; println!("your startup items: {} off", parts.hkcu.len()); }
        "normal" => userside::user_restore(&f.key)?,
        _ => {}
    }
    if r.ok && matches!(action, "off" | "follow" | "stop") {
        println!("services stopped; leftover processes in the family's folders are closed (see {})", net_pin::log_path().display());
    }
    print_ondemand(&r.state);
    if !r.ok { bail!("not done"); }
    Ok(())
}

fn cmd_cleanup(args: &[String]) -> Result<()> {
    let Some(q) = args.first().filter(|a| !a.starts_with("--")) else { bail!("usage: net-pin ram cleanup <family name> [--out <dir>]") };
    let f = &pick_family(q)?;
    let plan = cleanup::plan(f);
    print!("{}", cleanup::summary(&plan));
    if plan.actions.is_empty() { println!("nothing to do; no scripts written"); return Ok(()); }
    let now = chrono::Local::now();
    let dir = match opt(args, "--out") {
        Some(d) => std::path::PathBuf::from(d),
        None => net_pin::paths::user_data_dir().join("cleanup")
            .join(format!("{}-{}", cleanup::safe(&f.name), now.format("%Y%m%d-%H%M%S"))),
    };
    std::fs::create_dir_all(&dir)?;
    let stamp = now.to_rfc3339();
    write_ps(&dir.join("disable.ps1"), &cleanup::disable_script(&plan, &stamp))?;
    write_ps(&dir.join("undo.ps1"), &cleanup::undo_script(&plan, &stamp))?;
    std::fs::write(dir.join("plan.json"), serde_json::to_string_pretty(&plan)?)?;
    println!("\nwritten to {}\nreview disable.ps1, then run it in an admin PowerShell; undo.ps1 reverts it.", dir.display());
    Ok(())
}

fn set_pref(args: &[String], f: impl FnOnce(&mut Prefs, bool)) -> Result<()> {
    let on = on_off(args.first())?;
    let mut p = Prefs::load();
    f(&mut p, on);
    p.save()?;
    println!("saved {} (used from the next sample)", Prefs::path().display());
    Ok(())
}

pub fn main(args: &[String]) -> Result<()> {
    match args.first().map(String::as_str) {
        Some("scan") => cmd_scan(&args[1..]),
        Some("family") => {
            let Some(q) = args.get(1).filter(|a| !a.starts_with("--")) else { bail!("usage: net-pin ram family <name>") };
            let report = scan::run(0, scan::SortBy::Private, !args.iter().any(|a| a == "--no-size"))?;
            if !scan::print_family(&report.families, q) { bail!("no family matches {q}"); }
            Ok(())
        }
        Some("cleanup") => cmd_cleanup(&args[1..]),
        Some("sample") => {
            let s = observe::take()?;
            // Into the running tray's session, not a new one (which would push an older one out).
            observe::join_latest_session();
            let path = observe::store(&s, Prefs::load().keep_memory_history)?;
            println!("{} processes recorded -> {}", s.p.len(), path.display());
            Ok(())
        }
        Some("watch") => cmd_watch(),
        Some("leaks") => {
            let hours: f64 = match opt(args, "--hours") { Some(h) => h.parse()?, None => 6.0 };
            let samples = observe::load(hours);
            // Families only for live pids that appear in the report (costs a few seconds).
            let family_of = if samples.is_empty() { Default::default() } else {
                scan::run(0, scan::SortBy::Private, false)?.families.iter()
                    .flat_map(|f| f.members.iter().filter_map(|m| m.pid).map(|pid| (pid, f.name.clone()))).collect()
            };
            observe::print_report(&samples, &events::load(hours), hours, &family_of);
            Ok(())
        }
        Some("history") => set_pref(&args[1..], |p, on| p.keep_memory_history = on),
        Some("fast") => set_pref(&args[1..], |p, on| p.fast_samples = on),
        Some("ondemand") => cmd_ondemand(&args[1..]),
        Some("tray-icons") => {
            if args.iter().any(|a| a == "--prune") {
                match trayicons::prune()? {
                    (0, _) => println!("no app has {}+ tray-settings entries; nothing to do", trayicons::MIN_DUPLICATES),
                    (n, f) => println!("removed {n} duplicate entries; backup: {}", f.map(|p| p.display().to_string()).unwrap_or_default()),
                }
            }
            for (exe, n) in trayicons::counts().into_iter().take(10) { println!("{n:>5}  {exe}"); }
            Ok(())
        }
        // Foreground on-demand loop for testing in an admin console (Ctrl+C stops it; state stays).
        Some("daemon") => {
            net_pin::paths::ensure_may_write_data_dir()?;
            anyhow::ensure!(!net_pin::svc::running(), "the net-pin service runs (and owns the pipe): stop it first");
            daemon::run(|_| {}, true)
        }
        None | Some("help" | "-h" | "--help") => { print!("{HELP}"); Ok(()) }
        Some(x) => bail!("unknown command ram {x}; see `net-pin ram help`"),
    }
}
