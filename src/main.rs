//! `net-pin`: the command on the PATH. Reads need no admin. Changes go to the service over its pipe
//! (any interactive user); without the service they need an admin console.
use anyhow::{Result, bail};
use net_pin::model::{self, Config, Kind, Network, RouteRule, Vpn, VpnKind};
use net_pin::service::{self, Request};

const HELP: &str = "net-pin - choose which network (Wi-Fi, wired LAN, tethering, ...) carries what on Windows

USAGE (* = admin console)
  net-pin status                 adapters and their networks, routes, rules, pending changes
  net-pin plan                   only what apply would change
  net-pin apply                  re-apply now
  net-pin on | off               off: metrics restored, routes removed, kill switches disabled
                                 (locked ones stay)
  net-pin internet <network>     where general internet goes while several networks are up
  net-pin internet default       let Windows decide
  net-pin network                list networks and their adapters
  net-pin network add <name> kind=wireless|ethernet|cellular|any [alias=<name>] [description=<text>]
                                 (an adapter joins the most specific matching network)
  net-pin network remove <name>
  net-pin vpn                    list VPNs
  net-pin vpn <name> via <network>
  net-pin vpn <name> kill-switch on|off
  net-pin vpn add <name> exe=<path> [adapter=<description>] [via=<network>] [kill-switch=on|off]
                     [kind=default-route|server] [servers=a.b.c.d,...]
  net-pin vpn remove <name>
  net-pin route                  list destination routes
  net-pin route add <a.b.c.d/n> via <network>
  net-pin route remove <a.b.c.d/n>
  net-pin preset                 list presets;  net-pin preset <name>   apply one
  net-pin set keep-connected on|off | top-metric 1-4
  net-pin config                 print the config
  net-pin log [lines]            the end of the log
  net-pin undo                 * put everything back as recorded (stop the service first)
  net-pin service install|uninstall|start|stop     *  (the installer runs install / uninstall)
  net-pin daemon               * run the service in this console (NETPIN_DATA=<dir> to test)
  net-pin version | help

Names, aliases and descriptions take * wildcards. Adapter names and descriptions are in `status`.
Default-route VPNs (Tailscale, WireGuard, NordLynx) bind to the network with the best 0.0.0.0/0
route, so they share one network. Locked VPNs (and the networks they use) change only by editing
config.toml as administrator. Config: %ProgramData%\\net-pin\\config.toml; net-pin.log there.
";

fn network(cfg: &Config, s: Option<&String>) -> Result<String> {
    let s = s.ok_or_else(|| anyhow::anyhow!("which network? see `net-pin network`"))?;
    cfg.network(s).map(|n| n.name.clone()).ok_or_else(|| anyhow::anyhow!("no network {s:?}; see `net-pin network`"))
}

fn on_off(s: Option<&String>) -> Result<bool> {
    match s.map(String::as_str) { Some("on") => Ok(true), Some("off") => Ok(false), _ => bail!("expected on or off") }
}

fn print_status(full: bool) -> Result<()> {
    let r = net_pin::report()?;
    let (cfg, snap, plan) = (&r.cfg, &r.snap, &r.plan);
    if full {
        println!("net-pin {}; service: {}", net_pin::VERSION,
            if net_pin::svc::running() { "running" } else if net_pin::svc::exists() { "stopped" } else { "not installed" });
        let src = if net_pin::config_path().exists() { net_pin::config_path().display().to_string() } else { "defaults (no config.toml)".into() };
        println!("config: {src}; routing {}", if cfg.enabled { "on" } else { "off" });
        let pol = match snap.policy { Some(0) => "0 (every connection stays up)".to_string(), Some(v) => format!("{v} (Windows may drop Wi-Fi)"), None => "not set (Windows drops Wi-Fi when Ethernet is up)".into() };
        println!("policy fMinimizeConnections: {pol}");
        println!("\nadapters:");
        let role = |a: &model::Adapter| match snap.network_of(cfg, a) {
            Some(n) => n.name.clone(),
            None if cfg.vpns.iter().any(|v| !v.adapter.is_empty() && model::glob(&v.adapter, &a.description)) => "(vpn)".into(),
            None => String::new(),
        };
        for a in &snap.adapters {
            let gw = snap.gateway(a.index).map(|g| g.to_string()).unwrap_or("-".into());
            println!("  {:<8} {:<30} {:<5} metric {:<3}{:<5} gw {:<15} {}", role(a), a.alias, if a.up { "up" } else { "down" },
                a.metric, if a.auto_metric { " auto" } else { "" }, gw, a.description);
        }
        println!("\ndefault routes (route + interface metric):");
        let mut defs: Vec<(u32, &model::Route, &model::Adapter)> = snap.routes.iter().filter(|x| x.len == 0)
            .filter_map(|x| snap.adapters.iter().find(|a| a.index == x.index).map(|a| (x.metric + a.metric, x, a))).collect();
        defs.sort_by_key(|d| d.0);
        for (m, x, a) in defs { println!("  {m:<4} {:<30} via {}", a.alias, x.next_hop); }
        let ours: Vec<String> = snap.routes.iter().filter(|x| r.state.routes.contains(x)).map(|x| x.to_string()).collect();
        println!("net-pin's routes: {}", if ours.is_empty() { "none".into() } else { ours.join("; ") });
        for rule in &snap.rules {
            println!("firewall {}: {} on {}", rule.name, if rule.enabled { "block" } else { "disabled" }, rule.aliases.join(", "));
        }
        let s = |s: &Option<String>| s.clone().unwrap_or_else(|| "Windows decides".into());
        println!("\nVPN network (lowest metric): {}; general internet: {}", s(&plan.follow), s(&plan.internet));
        println!("=> {}: {}", net_pin::level(&r).to_uppercase(), net_pin::summary(&r));
    }
    for p in &plan.problems { println!("! {p}"); }
    for n in &plan.notes { println!("  note: {n}"); }
    if plan.actions.is_empty() { println!("apply would change nothing"); }
    else { println!("apply would:"); for a in &plan.actions { println!("  {a}"); } }
    Ok(())
}

fn print_reply(r: &service::Reply) {
    println!("{}", r.message);
    println!("=> {}: {}", r.level.to_uppercase(), r.summary);
    for p in &r.problems { println!("! {p}"); }
    for p in &r.pending { println!("  pending: {p}"); }
}

/// Sends a request to the service; without it, does the same here (admin).
fn request(req: Request) -> Result<()> {
    if net_pin::svc::running() {
        let r = service::call(&req)?;
        print_reply(&r);
        if !r.ok { bail!("not done"); }
        return Ok(());
    }
    anyhow::ensure!(net_pin::paths::may_write_data_dir(),
        "the net-pin service is not running: start it (`net-pin service start`) or run this in an admin console");
    let cfg = net_pin::load_config()?;
    let new = match req {
        Request::Status | Request::Apply => None,
        Request::SetInternet { network } => Some(Config { internet: network, ..cfg.clone() }),
        Request::SetEnabled { enabled } => Some(Config { enabled, ..cfg.clone() }),
        Request::SetConfig { config } => Some(config),
    };
    if let Some(n) = new {
        service::check_config(&cfg, &n)?;
        net_pin::save_config(&n)?;
        println!("saved {}", net_pin::config_path().display());
    }
    let (ok, bad) = net_pin::reconcile()?;
    println!("{ok} change(s) made, {bad} failed (log: {})", net_pin::log_path().display());
    print_status(false)
}

/// Changes the config through `request`.
fn edit(f: impl FnOnce(&mut Config) -> Result<()>) -> Result<()> {
    let mut cfg = if net_pin::svc::running() {
        service::call(&Request::Status)?.config.ok_or_else(|| anyhow::anyhow!("the service sent no config"))?
    } else { net_pin::load_config()? };
    f(&mut cfg)?;
    request(Request::SetConfig { config: cfg })
}

fn find<'a>(cfg: &'a mut Config, name: &str) -> Result<&'a mut Vpn> {
    cfg.vpns.iter_mut().find(|v| v.name.eq_ignore_ascii_case(name)).ok_or_else(|| anyhow::anyhow!("no VPN named {name:?}; see `net-pin vpn`"))
}

fn list(items: &[String]) -> Vec<String> { items.iter().flat_map(|s| s.split(',')).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect() }

fn networks(args: &[String]) -> Result<()> {
    match (args.first().map(String::as_str), args.get(1)) {
        (None, _) => {
            let r = net_pin::report()?;
            for n in &r.cfg.networks {
                let mut how = vec![n.kind.to_string()];
                if !n.alias.is_empty() { how.push(format!("alias {:?}", n.alias)); }
                if !n.description.is_empty() { how.push(format!("description {:?}", n.description)); }
                let ads: Vec<String> = r.snap.network(&r.cfg, &n.name).iter()
                    .map(|a| format!("{} ({})", a.alias, if a.up { "up" } else { "down" })).collect();
                let mark = if r.cfg.vpns.iter().any(|v| v.locked && v.via.eq_ignore_ascii_case(&n.name)) { " [locked]" } else { "" };
                println!("{:<10} {:<40} {}{mark}", n.name, how.join(", "), if ads.is_empty() { "no adapters".into() } else { ads.join(", ") });
            }
            Ok(())
        }
        (Some("add"), Some(name)) => {
            let mut n = Network { name: name.clone(), ..Default::default() };
            for kv in &args[2..] {
                let Some((k, val)) = kv.split_once('=') else { bail!("expected key=value, got {kv}") };
                match k {
                    "kind" => n.kind = match val { "wireless" => Kind::Wireless, "ethernet" => Kind::Ethernet, "cellular" => Kind::Cellular, "any" => Kind::Any,
                                                   _ => bail!("kind is wireless, ethernet, cellular or any") },
                    "alias" => n.alias = val.into(),
                    "description" => n.description = val.into(),
                    _ => bail!("unknown key {k}"),
                }
            }
            anyhow::ensure!(!n.name.is_empty() && n.name != "default", "a network needs a name (not \"default\")");
            edit(|c| {
                // Replacing keeps the order: the first matching network takes an adapter.
                match c.networks.iter_mut().find(|x| x.name.eq_ignore_ascii_case(&n.name)) { Some(x) => *x = n, None => c.networks.push(n) }
                Ok(())
            })
        }
        (Some("remove"), Some(name)) => edit(|c| {
            let used = c.internet.eq_ignore_ascii_case(name) || c.vpns.iter().any(|v| v.via.eq_ignore_ascii_case(name))
                || c.routes.iter().any(|r| r.via.eq_ignore_ascii_case(name));
            anyhow::ensure!(!used, "network {name} is in use (internet, a VPN or a route)");
            let n = c.networks.len();
            c.networks.retain(|x| !x.name.eq_ignore_ascii_case(name));
            anyhow::ensure!(c.networks.len() < n, "no network {name}");
            Ok(())
        }),
        _ => bail!("see `net-pin help` for the network commands"),
    }
}

fn vpn(args: &[String]) -> Result<()> {
    match (args.first().map(String::as_str), args.get(1).map(String::as_str)) {
        (None, _) => {
            let cfg = net_pin::load_config()?;
            for v in &cfg.vpns {
                let kind = if v.kind == VpnKind::Server { format!(" servers {}", v.servers.join(",")) } else { String::new() };
                println!("{:<14} via {:<8} kill switch {:<3}{} exe {} adapter {:?}{kind}", v.name, v.via,
                    if v.kill_switch { "on" } else { "off" }, if v.locked { " [locked]" } else { "" }, v.exe, v.adapter);
            }
            if cfg.vpns.is_empty() { println!("no VPNs; add one with `net-pin vpn add` or a preset (`net-pin preset`)"); }
            Ok(())
        }
        (Some("add"), Some(name)) => {
            let mut v = Vpn { name: name.into(), ..Default::default() };
            let mut via = None;
            for kv in &args[2..] {
                let Some((k, val)) = kv.split_once('=') else { bail!("expected key=value, got {kv}") };
                match k {
                    "exe" => v.exe = val.into(),
                    "adapter" => v.adapter = val.into(),
                    "via" => via = Some(val.to_string()),
                    "kill-switch" => v.kill_switch = on_off(Some(&val.to_string()))?,
                    "kind" => v.kind = match val { "server" => VpnKind::Server, "default-route" => VpnKind::DefaultRoute, _ => bail!("kind is default-route or server") },
                    "servers" => v.servers = list(&[val.to_string()]),
                    _ => bail!("unknown key {k}"),
                }
            }
            anyhow::ensure!(!v.exe.is_empty() || !v.kill_switch, "a kill switch needs exe=<path>");
            for s in &v.servers { anyhow::ensure!(model::parse_prefix(s).is_some(), "bad server address {s}"); }
            edit(|c| {
                anyhow::ensure!(!c.vpns.iter().any(|x| x.name.eq_ignore_ascii_case(&v.name)), "{} exists; remove it first", v.name);
                if let Some(n) = via { v.via = network(c, Some(&n))?; }
                c.vpns.push(v);
                Ok(())
            })
        }
        (Some("remove"), Some(name)) => edit(|c| {
            let n = find(c, name)?.name.clone();
            c.vpns.retain(|x| x.name != n);
            Ok(())
        }),
        (Some(name), Some("via")) => {
            let to = args.get(2).cloned();
            edit(|c| { let n = network(c, to.as_ref())?; find(c, name)?.via = n; Ok(()) })
        }
        (Some(name), Some("kill-switch")) => {
            let on = on_off(args.get(2))?;
            edit(|c| {
                let v = find(c, name)?;
                anyhow::ensure!(!on || !v.exe.is_empty(), "{} has no exe to block", v.name);
                v.kill_switch = on;
                Ok(())
            })
        }
        _ => bail!("see `net-pin help` for the vpn commands"),
    }
}

fn route(args: &[String]) -> Result<()> {
    match args.first().map(String::as_str) {
        None => {
            for r in net_pin::load_config()?.routes { println!("{:<20} via {}", r.prefix, r.via); }
            Ok(())
        }
        Some("add") => {
            let prefix = args.get(1).ok_or_else(|| anyhow::anyhow!("route add <a.b.c.d/n> via <network>"))?.clone();
            anyhow::ensure!(model::parse_prefix(&prefix).is_some(), "bad prefix {prefix}");
            anyhow::ensure!(args.get(2).is_some_and(|a| a == "via"), "route add <a.b.c.d/n> via <network>");
            let to = args.get(3).cloned();
            edit(|c| {
                let via = network(c, to.as_ref())?;
                c.routes.retain(|r| r.prefix != prefix);
                c.routes.push(RouteRule { prefix, via });
                Ok(())
            })
        }
        Some("remove") => {
            let prefix = args.get(1).ok_or_else(|| anyhow::anyhow!("route remove <a.b.c.d/n>"))?.clone();
            edit(|c| {
                let n = c.routes.len();
                c.routes.retain(|r| r.prefix != prefix);
                anyhow::ensure!(c.routes.len() < n, "no route {prefix}");
                Ok(())
            })
        }
        _ => bail!("see `net-pin help` for the route commands"),
    }
}

fn preset(args: &[String]) -> Result<()> {
    match args.first() {
        None => { for (n, d) in model::PRESETS { println!("{n:<16} {d}"); } Ok(()) }
        Some(name) => {
            let name = name.clone();
            edit(|c| model::preset(&name, c).map_err(|e| anyhow::anyhow!(e)))
        }
    }
}

fn set(args: &[String]) -> Result<()> {
    let val = args.get(1).cloned().ok_or_else(|| anyhow::anyhow!("set <key> <value>; see `net-pin help`"))?;
    match args.first().map(String::as_str) {
        Some("keep-connected") => { let on = on_off(Some(&val))?; edit(|c| { c.keep_all_connected = on; Ok(()) }) }
        Some("top-metric") => {
            let m: u32 = val.parse()?;
            anyhow::ensure!((1..=4).contains(&m), "top-metric is 1-4 (below the 5 Windows gives a gigabit LAN)");
            edit(|c| { c.top_metric = m; Ok(()) })
        }
        _ => bail!("set keep-connected | top-metric"),
    }
}

fn internet(args: &[String]) -> Result<()> {
    let to = args.first().cloned();
    if to.as_deref() == Some("default") { return request(Request::SetInternet { network: String::new() }); }
    let cfg = if net_pin::svc::running() { service::call(&Request::Status)?.config.unwrap_or_default() } else { net_pin::load_config()? };
    request(Request::SetInternet { network: network(&cfg, to.as_ref())? })
}

fn show_log(args: &[String]) -> Result<()> {
    let n: usize = args.first().and_then(|a| a.parse().ok()).unwrap_or(30);
    let text = std::fs::read_to_string(net_pin::log_path())?;
    let lines: Vec<&str> = text.lines().collect();
    for l in &lines[lines.len().saturating_sub(n)..] { println!("{l}"); }
    Ok(())
}

fn undo() -> Result<()> {
    anyhow::ensure!(!net_pin::svc::running(),
        "the service would re-apply at the next network change: stop it first (`net-pin service stop`), or use `net-pin off`");
    for l in net_pin::undo()? { println!("{l}"); }
    Ok(())
}

/// The service in this console until Ctrl+C.
fn daemon() -> Result<()> {
    net_pin::paths::ensure_may_write_data_dir()?;
    anyhow::ensure!(!net_pin::svc::exists() || std::env::var_os(net_pin::paths::DATA_ENV).is_some(),
        "the net-pin service is installed; run this only with {}=<scratch dir>", net_pin::paths::DATA_ENV);
    let stop = std::sync::atomic::AtomicBool::new(false);
    service::run(&stop)
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rest = args.get(1..).unwrap_or(&[]);
    match args.first().map(String::as_str) {
        None | Some("status") => print_status(true),
        Some("plan") => print_status(false),
        Some("apply") => request(Request::Apply),
        Some("on") => request(Request::SetEnabled { enabled: true }),
        Some("off") => request(Request::SetEnabled { enabled: false }),
        Some("internet") => internet(rest),
        Some("network" | "networks") => networks(rest),
        Some("vpn") => vpn(rest),
        Some("route") => route(rest),
        Some("preset") => preset(rest),
        Some("set") => set(rest),
        Some("config") => {
            println!("# {}{}", net_pin::config_path().display(), if net_pin::config_path().exists() { "" } else { " (missing: defaults)" });
            print!("{}", toml::to_string_pretty(&net_pin::load_config()?)?);
            Ok(())
        }
        Some("log") => show_log(rest),
        Some("undo") => undo(),
        Some("service") => match rest.first().map(String::as_str) {
            Some("run") => net_pin::svc::dispatch(),
            Some("install") => net_pin::svc::install(),
            Some("uninstall") => net_pin::svc::uninstall(),
            Some("start") => net_pin::svc::start(),
            Some("stop") => net_pin::svc::stop(),
            _ => bail!("net-pin service install|uninstall|start|stop"),
        },
        Some("daemon") => daemon(),
        Some("version" | "--version" | "-V") => { println!("net-pin {}", net_pin::VERSION); Ok(()) }
        Some("help" | "-h" | "--help" | "/?") => { print!("{HELP}"); Ok(()) }
        Some(x) => bail!("unknown command {x}; see `net-pin help`"),
    }
}
