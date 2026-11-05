//! Network routing, pure part: the config, a snapshot of adapters / routes / rules, and the plan
//! that brings the snapshot to what the config asks for:
//!
//! - A *network* is a set of adapters, matched by kind (wireless, ethernet, cellular, any) and
//!   optionally by alias / description (`*` wildcards). Virtual, Bluetooth and VPN tunnel adapters
//!   never belong to one. Defaults: `wifi` (wireless) and `lan` (ethernet).
//! - Optionally Windows keeps every connection up (policy `fMinimizeConnections = 0`); by default
//!   it drops Wi-Fi when Ethernet is plugged in.
//! - VPNs like Tailscale and WireGuard bind their outer sockets to the interface with the best
//!   `0.0.0.0/0` route (route + interface metric). The network those VPNs should use gets the
//!   lowest interface metric, so they follow it ("follow network").
//! - General internet goes to the network the user picks: when that is not the follow network,
//!   its adapters get `0.0.0.0/1` + `128.0.0.0/1` (more specific than `/0`, so they win). Empty:
//!   Windows decides.
//! - Destination rules and server VPNs get their own routes via a network's gateway.
//! - Kill switch per VPN: firewall rules block its program on every adapter except its network
//!   and its own tunnel, so it goes offline instead of falling back to another network.
//! - A `locked` VPN keeps its kill switch even while routing is off, and cannot be changed by
//!   ordinary users (`service::check_config`): only by an admin editing `config.toml`.
//! - Rules in net-pin's firewall group that no VPN asks for are removed, but only once the
//!   program's new rules are in place (fail-closed).
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind { Wireless, Ethernet, Cellular, Any }

impl Kind {
    /// IfType (IANA): 71 IEEE 802.11, 6 Ethernet (USB tethering too), 243 / 244 WWAN.
    pub fn matches(self, if_type: u32) -> bool {
        match self {
            Kind::Wireless => if_type == 71,
            Kind::Ethernet => if_type == 6,
            Kind::Cellular => matches!(if_type, 243 | 244),
            Kind::Any => matches!(if_type, 6 | 71 | 243 | 244),
        }
    }
}

impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(match self { Kind::Wireless => "wireless", Kind::Ethernet => "ethernet", Kind::Cellular => "cellular", Kind::Any => "any" })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Network {
    pub name: String,
    pub kind: Kind,
    /// Adapter name (`*` wildcards); empty = any.
    pub alias: String,
    /// Adapter description (`*` wildcards); empty = any.
    pub description: String,
}

impl Default for Network {
    fn default() -> Self { Self { name: String::new(), kind: Kind::Any, alias: String::new(), description: String::new() } }
}

impl Network {
    pub fn new(name: &str, kind: Kind) -> Self { Self { name: name.into(), kind, ..Default::default() } }
}

/// Adapters that never belong to a network (by description).
pub const EXCLUDED: [&str; 8] = ["*Virtual*", "*Hyper-V*", "*VMware*", "*VirtualBox*", "*Bluetooth*", "*Loopback*", "*Wintun*", "*TAP-Windows*"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VpnKind {
    /// Binds to the interface with the best `0.0.0.0/0` route (Tailscale, WireGuard, NordLynx).
    DefaultRoute,
    /// Connects to fixed servers (`servers`); they get host routes via `via`.
    Server,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Vpn {
    pub name: String,
    pub kind: VpnKind,
    /// The program whose traffic the kill switch blocks off `via`.
    pub exe: String,
    /// Its tunnel adapter, by description (`*` wildcards); never blocked, never in a network.
    pub adapter: String,
    /// Network name.
    pub via: String,
    pub kill_switch: bool,
    /// Kill switch stays on while routing is off; only an admin editing config.toml changes it.
    pub locked: bool,
    /// `Server` VPNs: server addresses (`a.b.c.d` or `a.b.c.d/n`).
    pub servers: Vec<String>,
}

impl Default for Vpn {
    fn default() -> Self {
        Self { name: String::new(), kind: VpnKind::DefaultRoute, exe: String::new(), adapter: String::new(),
               via: "wifi".into(), kill_switch: false, locked: false, servers: Vec::new() }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RouteRule {
    /// `a.b.c.d/n`
    pub prefix: String,
    /// Network name.
    pub via: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Off: net-pin's routes removed, metrics restored, kill switches disabled except locked
    /// ones (the policy stays).
    pub enabled: bool,
    /// Windows keeps every connection up (Wi-Fi beside Ethernet), after a reboot.
    pub keep_all_connected: bool,
    /// Network for general internet traffic while several are up; empty = Windows decides.
    pub internet: String,
    /// Interface metric of the follow network; 1-4, below the 5 Windows gives a gigabit LAN.
    pub top_metric: u32,
    pub networks: Vec<Network>,
    pub routes: Vec<RouteRule>,
    pub vpns: Vec<Vpn>,
}

pub const TAILSCALED: &str = r"C:\Program Files\Tailscale\tailscaled.exe";

impl Default for Config {
    /// Changes nothing: networks `wifi` and `lan`, no VPNs, Windows decides.
    fn default() -> Self {
        Self { enabled: true, keep_all_connected: false, internet: String::new(), top_metric: 1,
               networks: vec![Network::new("wifi", Kind::Wireless), Network::new("lan", Kind::Ethernet)],
               routes: Vec::new(), vpns: Vec::new() }
    }
}

impl Config {
    pub fn network(&self, name: &str) -> Option<&Network> { self.networks.iter().find(|n| n.name.eq_ignore_ascii_case(name)) }
}

/// Presets: ready-made setups the `net-pin preset` command applies on top of a config.
pub const PRESETS: [(&str, &str); 1] = [
    ("tailscale-wifi", "For a PC on a wired network that Tailscale must never use: Tailscale only on Wi-Fi
                     (locked kill switch), general internet on the LAN, Wi-Fi kept up beside Ethernet"),
];

pub fn preset(name: &str, cfg: &mut Config) -> Result<(), String> {
    match name {
        "tailscale-wifi" => {
            for n in [Network::new("wifi", Kind::Wireless), Network::new("lan", Kind::Ethernet)] {
                if cfg.network(&n.name).is_none() { cfg.networks.push(n); }
            }
            cfg.keep_all_connected = true;
            cfg.internet = "lan".into();
            cfg.vpns.retain(|v| !v.name.eq_ignore_ascii_case("Tailscale"));
            cfg.vpns.insert(0, Vpn { name: "Tailscale".into(), exe: TAILSCALED.into(), adapter: "Tailscale*".into(),
                                     via: "wifi".into(), kill_switch: true, locked: true, ..Default::default() });
            Ok(())
        }
        _ => Err(format!("no preset {name:?}; presets: {}", PRESETS.iter().map(|p| p.0).collect::<Vec<_>>().join(", "))),
    }
}

// ------------------------------------------------------------------ snapshot

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Adapter {
    pub index: u32,
    pub alias: String,
    pub description: String,
    pub up: bool,
    pub metric: u32,
    pub auto_metric: bool,
    /// IANA ifType (71 wireless, 6 ethernet, 53 virtual / tunnel, 24 loopback).
    #[serde(default)]
    pub if_type: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    pub prefix: Ipv4Addr,
    pub len: u8,
    pub index: u32,
    pub next_hop: Ipv4Addr,
    pub metric: u32,
}

impl std::fmt::Display for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}/{} via {} (if {})", self.prefix, self.len, self.next_hop, self.index)
    }
}

/// One of net-pin's firewall rules (group `fw::GROUP`). `aliases` comes from the rule's description, which net-pin writes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    pub enabled: bool,
    pub program: String,
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    pub adapters: Vec<Adapter>,
    /// IPv4 routes in the active store.
    pub routes: Vec<Route>,
    pub policy: Option<u32>,
    pub rules: Vec<Rule>,
}

/// Values recorded before net-pin first changed them (`%ProgramData%\net-pin\state.json`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    pub policy_recorded: bool,
    pub policy_key_existed: bool,
    pub policy_old: Option<u32>,
    /// alias -> (automatic metric, metric)
    pub metrics: std::collections::BTreeMap<String, (bool, u32)>,
    /// Routes net-pin added (and still owns).
    pub routes: Vec<Route>,
}

// ------------------------------------------------------------------ plan

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Action {
    SetPolicy,
    SetMetric { index: u32, alias: String, metric: u32 },
    RestoreMetric { index: u32, alias: String, auto: bool, metric: u32 },
    AddRoute(Route),
    RemoveRoute(Route),
    /// Create or replace a block rule for `program` on `aliases`, enabled.
    BlockRule { name: String, program: String, aliases: Vec<String>, outbound: bool },
    DisableRule { name: String },
    /// A rule in net-pin's group that no VPN asks for any more.
    RemoveRule { name: String },
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Action::SetPolicy => write!(f, "set fMinimizeConnections = 0 (keep every connection up; after a reboot)"),
            Action::SetMetric { alias, metric, .. } => write!(f, "set {alias} interface metric {metric}"),
            Action::RestoreMetric { alias, auto, metric, .. } =>
                if *auto { write!(f, "restore {alias} automatic metric") } else { write!(f, "restore {alias} metric {metric}") },
            Action::AddRoute(r) => write!(f, "add route {r}"),
            Action::RemoveRoute(r) => write!(f, "remove route {r}"),
            Action::BlockRule { name, aliases, .. } => write!(f, "firewall {name}: block on {}", aliases.join(", ")),
            Action::DisableRule { name } => write!(f, "disable firewall {name}"),
            Action::RemoveRule { name } => write!(f, "remove firewall {name}"),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Plan {
    pub actions: Vec<Action>,
    pub problems: Vec<String>,
    pub notes: Vec<String>,
    /// Network the default-route VPNs follow (lowest metric), and where general internet goes.
    pub follow: Option<String>,
    pub internet: Option<String>,
}

pub const SPLITS: [(Ipv4Addr, u8); 2] = [(Ipv4Addr::new(0, 0, 0, 0), 1), (Ipv4Addr::new(128, 0, 0, 0), 1)];
const ANY: Ipv4Addr = Ipv4Addr::UNSPECIFIED;

/// Case-insensitive match with `*` wildcards.
pub fn glob(pat: &str, s: &str) -> bool {
    let (p, s) = (pat.to_lowercase(), s.to_lowercase());
    let parts: Vec<&str> = p.split('*').collect();
    if parts.len() == 1 { return p == s; }
    let mut rest = s.as_str();
    for (i, part) in parts.iter().enumerate() {
        if i == 0 { if !rest.starts_with(part) { return false; } rest = &rest[part.len()..]; continue; }
        if i == parts.len() - 1 { return rest.ends_with(part); }
        match rest.find(part) { Some(at) => rest = &rest[at + part.len()..], None => return false }
    }
    true
}

/// `a.b.c.d/n` or `a.b.c.d` (= /32), normalized to the network address.
pub fn parse_prefix(s: &str) -> Option<(Ipv4Addr, u8)> {
    let (a, n) = s.trim().split_once('/').map_or((s.trim(), 32), |(a, n)| (a, n.parse().unwrap_or(99)));
    let ip: Ipv4Addr = a.parse().ok()?;
    if n > 32 { return None; }
    let mask = if n == 0 { 0 } else { u32::MAX << (32 - n) };
    Some((Ipv4Addr::from(u32::from(ip) & mask), n))
}

fn is_tunnel(cfg: &Config, a: &Adapter) -> bool {
    cfg.vpns.iter().any(|v| !v.adapter.is_empty() && glob(&v.adapter, &a.description))
}

impl Snapshot {
    /// The network an adapter belongs to: of those that match it, the most specific (alias and
    /// description filters count over kind alone), the first one on a tie.
    pub fn network_of<'c>(&self, cfg: &'c Config, a: &Adapter) -> Option<&'c Network> {
        if EXCLUDED.iter().any(|p| glob(p, &a.description)) || is_tunnel(cfg, a) { return None; }
        let specific = |n: &Network| (!n.alias.is_empty()) as u8 + (!n.description.is_empty()) as u8 + (n.kind != Kind::Any) as u8;
        cfg.networks.iter().filter(|n| n.kind.matches(a.if_type)
            && (n.alias.is_empty() || glob(&n.alias, &a.alias))
            && (n.description.is_empty() || glob(&n.description, &a.description)))
            .min_by_key(|n| std::cmp::Reverse(specific(n)))
    }
    /// Adapters of a network.
    pub fn network(&self, cfg: &Config, name: &str) -> Vec<&Adapter> {
        self.adapters.iter().filter(|a| self.network_of(cfg, a).is_some_and(|n| n.name.eq_ignore_ascii_case(name))).collect()
    }
    pub fn is_up(&self, cfg: &Config, name: &str) -> bool { self.network(cfg, name).iter().any(|a| a.up) }
    /// The adapter's default gateway (next hop of its `/0` route), when it has one.
    pub fn gateway(&self, index: u32) -> Option<Ipv4Addr> {
        self.routes.iter().filter(|r| r.index == index && r.len == 0 && r.next_hop != ANY)
            .min_by_key(|r| r.metric).map(|r| r.next_hop)
    }
    /// Up adapters of a network with a gateway, first one first.
    fn exits(&self, cfg: &Config, name: &str) -> Vec<(u32, Ipv4Addr)> {
        self.network(cfg, name).into_iter().filter(|a| a.up).filter_map(|a| self.gateway(a.index).map(|g| (a.index, g))).collect()
    }
    /// Where a default-route VPN goes now: the up, non-VPN adapter with the lowest route +
    /// interface metric on `/0` (tailscaled's rule).
    pub fn default_egress(&self, cfg: &Config) -> Option<&Adapter> {
        let vpn = |a: &Adapter| is_tunnel(cfg, a) || a.description.to_lowercase().contains("wintun");
        self.routes.iter().filter(|r| r.len == 0)
            .filter_map(|r| self.adapters.iter().find(|a| a.index == r.index && a.up && !vpn(a)).map(|a| (r.metric + a.metric, a)))
            .min_by_key(|(m, _)| *m).map(|(_, a)| a)
    }
}

/// The loopback pseudo-interface: never blocked (local IPC of the VPN clients).
fn is_loopback(a: &Adapter) -> bool { a.if_type == 24 || a.description.to_lowercase().contains("loopback") }

fn rule_name(v: &Vpn, outbound: bool) -> String {
    format!("net-pin: {} {}", v.name, if outbound { "out" } else { "in" })
}

/// Whether a VPN's kill switch should be on now.
fn guarding(cfg: &Config, v: &Vpn) -> bool { v.kill_switch && (cfg.enabled || v.locked) }

pub fn plan(cfg: &Config, snap: &Snapshot, state: &State) -> Plan {
    let mut p = Plan::default();
    let known = |n: &str| cfg.network(n).is_some();
    if !(1..=4).contains(&cfg.top_metric) { p.problems.push("top_metric must be 1-4".into()); }
    if !cfg.internet.is_empty() && !known(&cfg.internet) { p.problems.push(format!("internet: no network {:?}", cfg.internet)); }
    for v in &cfg.vpns { if !known(&v.via) { p.problems.push(format!("{}: no network {:?}", v.name, v.via)); } }
    for r in &cfg.routes { if !known(&r.via) { p.problems.push(format!("route {}: no network {:?}", r.prefix, r.via)); } }

    if cfg.keep_all_connected && snap.policy != Some(0) { p.actions.push(Action::SetPolicy); }

    // Metrics: the follow network gets top_metric; adapters net-pin changed before go back.
    let followers: Vec<&Vpn> = cfg.vpns.iter().filter(|v| v.kind == VpnKind::DefaultRoute && known(&v.via)).collect();
    let follow = followers.first().map(|v| v.via.clone())
        .or_else(|| (!cfg.internet.is_empty() && known(&cfg.internet)).then(|| cfg.internet.clone()));
    if let (Some(f), Some(v)) = (&follow, followers.iter().find(|v| follow.as_ref().is_some_and(|f| !v.via.eq_ignore_ascii_case(f)))) {
        p.problems.push(format!("{} wants {} but default-route VPNs share one network ({f})", v.name, v.via));
    }
    if cfg.enabled {
        p.follow = follow.clone();
        p.internet = if cfg.internet.is_empty() { follow.clone() } else { Some(cfg.internet.clone()) };
    }
    let lead: Vec<&Adapter> = match (&follow, cfg.enabled) { (Some(f), true) => snap.network(cfg, f), _ => Vec::new() };
    for a in &snap.adapters {
        let ours = lead.iter().any(|l| l.index == a.index);
        if ours && (a.auto_metric || a.metric != cfg.top_metric) {
            p.actions.push(Action::SetMetric { index: a.index, alias: a.alias.clone(), metric: cfg.top_metric });
        } else if !ours && let Some(&(auto, m)) = state.metrics.get(&a.alias) && (a.auto_metric != auto || (!auto && a.metric != m)) {
            p.actions.push(Action::RestoreMetric { index: a.index, alias: a.alias.clone(), auto, metric: m });
        }
    }

    // Routes: desired set vs the routes net-pin recorded.
    let mut want: Vec<Route> = Vec::new();
    if cfg.enabled {
        let route = |(index, gw): (u32, Ipv4Addr), (prefix, len): (Ipv4Addr, u8)| Route { prefix, len, index, next_hop: gw, metric: 0 };
        if let Some(f) = &follow && !cfg.internet.is_empty() && !cfg.internet.eq_ignore_ascii_case(f) && known(&cfg.internet) {
            let exits = snap.exits(cfg, &cfg.internet);
            if exits.is_empty() { p.notes.push(format!("{} is not connected: general internet uses {f}", cfg.internet)); }
            for e in exits { for s in SPLITS { want.push(route(e, s)); } }
        }
        let mut targets: Vec<(String, String)> = cfg.routes.iter().map(|r| (r.prefix.clone(), r.via.clone())).collect();
        for v in cfg.vpns.iter().filter(|v| v.kind == VpnKind::Server) { for s in &v.servers { targets.push((s.clone(), v.via.clone())); } }
        for (t, net) in targets {
            match (parse_prefix(&t), snap.exits(cfg, &net).first()) {
                (None, _) => p.problems.push(format!("bad prefix {t}")),
                (Some(_), None) => p.notes.push(format!("{t}: {net} is not connected; no route")),
                (Some(pre), Some(&e)) => want.push(route(e, pre)),
            }
        }
    }
    let same = |a: &Route, b: &Route| a.prefix == b.prefix && a.len == b.len && a.index == b.index && a.next_hop == b.next_hop;
    let have: Vec<Route> = snap.routes.iter().filter(|r| state.routes.iter().any(|o| same(o, r))).copied().collect();
    for r in &have { if !want.iter().any(|w| same(w, r)) { p.actions.push(Action::RemoveRoute(*r)); } }
    for w in &want { if !snap.routes.iter().any(|r| same(w, r)) { p.actions.push(Action::AddRoute(*w)); } }

    // Kill switches.
    for v in &cfg.vpns {
        let names = [(rule_name(v, true), true), (rule_name(v, false), false)];
        if guarding(cfg, v) {
            let keep: Vec<u32> = snap.network(cfg, &v.via).iter().map(|a| a.index).collect();
            if keep.is_empty() {
                p.problems.push(format!("{}: no adapter in network {:?}; kill switch left as it is", v.name, v.via));
                continue;
            }
            block_rules(&mut p, snap, v, &keep, names);
        } else {
            for (name, _) in names {
                if snap.rules.iter().any(|r| r.name == name && r.enabled) { p.actions.push(Action::DisableRule { name }); }
            }
        }
    }

    // Rules nobody asks for. A program that should have a kill switch keeps its old rule until
    // both new rules exist and are enabled (fail-closed).
    let wanted: Vec<String> = cfg.vpns.iter().flat_map(|v| [rule_name(v, true), rule_name(v, false)]).collect();
    let in_place = |v: &Vpn| [rule_name(v, true), rule_name(v, false)].iter()
        .all(|n| snap.rules.iter().any(|r| &r.name == n && r.enabled) && !p.actions.iter().any(|a| matches!(a, Action::BlockRule { name, .. } if name == n)));
    let stale: Vec<(String, bool)> = snap.rules.iter().filter(|r| !wanted.contains(&r.name)).map(|r| {
        let mut guarded = cfg.vpns.iter().filter(|v| guarding(cfg, v) && v.exe.eq_ignore_ascii_case(&r.program));
        (r.name.clone(), guarded.all(|v| in_place(v)))
    }).collect();
    for (name, go) in stale {
        if go { p.actions.push(Action::RemoveRule { name }); }
        else { p.notes.push(format!("old firewall rule {name} kept until the new kill switch is in place")); }
    }
    p
}

/// Block rules for `v` on every adapter outside `keep`, its tunnel and loopback.
fn block_rules(p: &mut Plan, snap: &Snapshot, v: &Vpn, keep: &[u32], names: [(String, bool); 2]) {
    let mut block: Vec<String> = snap.adapters.iter()
        .filter(|a| !keep.contains(&a.index) && !is_loopback(a) && !(!v.adapter.is_empty() && glob(&v.adapter, &a.description)))
        .map(|a| a.alias.clone()).collect();
    block.sort();
    if block.is_empty() { return; } // an empty list would mean "every interface"
    for (name, outbound) in names {
        let ok = snap.rules.iter().any(|r| r.name == name && r.enabled && r.aliases == block && r.program.eq_ignore_ascii_case(&v.exe));
        if !ok { p.actions.push(Action::BlockRule { name, program: v.exe.clone(), aliases: block.clone(), outbound }); }
    }
}

/// What the plan's actions change, recorded before any of them runs. Keeps the first record.
pub fn record(state: &State, snap: &Snapshot, actions: &[Action], policy_key_existed: bool) -> State {
    let mut s = state.clone();
    for a in actions {
        match a {
            Action::SetPolicy if !s.policy_recorded => {
                (s.policy_recorded, s.policy_key_existed, s.policy_old) = (true, policy_key_existed, snap.policy);
            }
            Action::SetMetric { index, alias, .. } if !s.metrics.contains_key(alias) => {
                if let Some(ad) = snap.adapters.iter().find(|x| x.index == *index) {
                    s.metrics.insert(alias.clone(), (ad.auto_metric, ad.metric));
                }
            }
            Action::AddRoute(r) => s.routes.push(*r),
            _ => {}
        }
    }
    s
}

/// One thing pinned to a network, for the tray and `net-pin status`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Pin {
    /// "Internet", a VPN's name, or a route's prefix.
    pub what: String,
    pub network: String,
    /// The network has an adapter up.
    pub up: bool,
    /// "kill switch", "locked", "server".
    #[serde(default)]
    pub flags: Vec<String>,
}

/// What is pinned now. While routing is off, only locked VPNs (their kill switches stay on).
pub fn pins(cfg: &Config, snap: &Snapshot) -> Vec<Pin> {
    let pin = |what: &str, net: &str, flags: Vec<String>| Pin { what: what.into(), network: net.into(), up: snap.is_up(cfg, net), flags };
    let mut out = Vec::new();
    if cfg.enabled && !cfg.internet.is_empty() { out.push(pin("Internet", &cfg.internet, vec![])); }
    for v in cfg.vpns.iter().filter(|v| cfg.enabled || (v.locked && v.kill_switch)) {
        let mut f = Vec::new();
        if v.kind == VpnKind::Server { f.push("server".to_string()); }
        if v.kill_switch { f.push("kill switch".into()); }
        if v.locked { f.push("locked".into()); }
        out.push(pin(&v.name, &v.via, f));
    }
    if cfg.enabled { for r in &cfg.routes { out.push(pin(&r.prefix, &r.via, vec![])); } }
    out
}

/// One short line for the tray and the log; the details are in `pins`.
pub fn summary(cfg: &Config, snap: &Snapshot, p: &Plan) -> String {
    let pins = pins(cfg, snap);
    if !cfg.enabled {
        return if pins.is_empty() { "Off".into() } else { format!("Off; {} locked kill switch(es) still on", pins.len()) };
    }
    if let Some(x) = p.problems.first() { return x.clone(); }
    if pins.is_empty() { return "Nothing pinned".into(); }
    let mut down: Vec<&str> = pins.iter().filter(|p| !p.up).map(|p| p.network.as_str()).collect();
    down.dedup();
    if down.is_empty() { format!("{} pinned, all up", pins.len()) } else { format!("{} pinned; {} down", pins.len(), down.join(", ")) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ad(index: u32, alias: &str, desc: &str, up: bool, metric: u32, if_type: u32) -> Adapter {
        Adapter { index, alias: alias.into(), description: desc.into(), up, metric, auto_metric: true, if_type }
    }
    fn r(prefix: &str, index: u32, gw: &str, metric: u32) -> Route {
        let (p, l) = parse_prefix(prefix).unwrap();
        Route { prefix: p, len: l, index, next_hop: gw.parse().unwrap(), metric }
    }
    /// Wi-Fi (12) and LAN (7) both up with gateways, Tailscale tunnel (30), a corporate VPN (40),
    /// Wi-Fi Direct (50), loopback (1).
    fn both_up() -> Snapshot {
        Snapshot {
            adapters: vec![ad(12, "Wi-Fi", "Wireless Network Adapter", true, 40, 71), ad(7, "Ethernet", "USB GbE Ethernet Adapter", true, 5, 6),
                           ad(30, "Tailscale", "Tailscale Tunnel", true, 5, 53), ad(40, "Ethernet 2", "Corp VPN Virtual Miniport", false, 1, 6),
                           ad(50, "Local Area Connection* 8", "Microsoft Wi-Fi Direct Virtual Adapter", false, 25, 71),
                           ad(1, "Loopback Pseudo-Interface 1", "Software Loopback Interface 1", true, 75, 24)],
            routes: vec![r("0.0.0.0/0", 12, "192.168.1.1", 0), r("0.0.0.0/0", 7, "10.0.0.1", 0)],
            policy: None,
            rules: vec![],
        }
    }
    fn tailscale() -> Config { let mut c = Config::default(); preset("tailscale-wifi", &mut c).unwrap(); c }
    fn adds(p: &Plan) -> Vec<String> { p.actions.iter().filter_map(|a| if let Action::AddRoute(r) = a { Some(r.to_string()) } else { None }).collect() }
    fn blocks(p: &Plan) -> Vec<Vec<String>> {
        p.actions.iter().filter_map(|a| if let Action::BlockRule { aliases, .. } = a { Some(aliases.clone()) } else { None }).collect()
    }

    #[test]
    fn globs_and_prefixes() {
        assert!(glob("USB GbE*", "usb gbe ethernet adapter"));
        assert!(glob("*Tunnel", "Tailscale Tunnel") && glob("Wi-Fi", "WI-FI") && !glob("Tailscale*", "WireGuard Tunnel"));
        assert_eq!(parse_prefix("10.1.2.3/8"), Some(("10.0.0.0".parse().unwrap(), 8)));
        assert_eq!(parse_prefix("1.2.3.4"), Some(("1.2.3.4".parse().unwrap(), 32)));
        assert_eq!(parse_prefix("1.2.3.4/33"), None);
    }

    #[test]
    fn networks_by_kind_without_virtual_adapters() {
        let s = both_up();
        let cfg = Config::default();
        let names = |n: &str| s.network(&cfg, n).iter().map(|a| a.alias.clone()).collect::<Vec<_>>();
        assert_eq!(names("wifi"), ["Wi-Fi"]);
        assert_eq!(names("lan"), ["Ethernet"]);
        // A specific network wins over the generic one listed before it (USB tethering is Ethernet too).
        let mut custom = cfg.clone();
        custom.networks.push(Network { name: "usb".into(), kind: Kind::Ethernet, description: "USB GbE*".into(), ..Default::default() });
        assert_eq!(s.network(&custom, "usb").len(), 1);
        assert!(s.network(&custom, "lan").is_empty());
    }

    #[test]
    fn default_changes_nothing() {
        let p = plan(&Config::default(), &both_up(), &State::default());
        assert_eq!(p.actions, vec![]);
        assert!(p.problems.is_empty());
        assert_eq!(p.internet, None);
    }

    #[test]
    fn tailscale_preset_is_net_pin_0_2_0() {
        let p = plan(&tailscale(), &both_up(), &State::default());
        assert!(p.problems.is_empty(), "{:?}", p.problems);
        assert!(p.actions.contains(&Action::SetPolicy));
        assert!(p.actions.contains(&Action::SetMetric { index: 12, alias: "Wi-Fi".into(), metric: 1 }));
        assert_eq!(adds(&p), ["0.0.0.0/1 via 10.0.0.1 (if 7)", "128.0.0.0/1 via 10.0.0.1 (if 7)"]);
        // tailscaled blocked on everything but Wi-Fi, its tunnel and loopback, both directions.
        let b = vec!["Ethernet".to_string(), "Ethernet 2".into(), "Local Area Connection* 8".into()];
        assert_eq!(blocks(&p), vec![b.clone(), b]);
    }

    #[test]
    fn internet_over_wifi_needs_no_splits() {
        let mut cfg = tailscale();
        cfg.internet = "wifi".into();
        let mut snap = both_up();
        snap.routes.push(r("0.0.0.0/1", 7, "10.0.0.1", 0));
        let state = State { routes: vec![r("0.0.0.0/1", 7, "10.0.0.1", 0)], ..Default::default() };
        let p = plan(&cfg, &snap, &state);
        assert!(adds(&p).is_empty());
        assert!(p.actions.contains(&Action::RemoveRoute(r("0.0.0.0/1", 7, "10.0.0.1", 0))));
        // A /1 route net-pin did not record is someone else's.
        assert!(!plan(&cfg, &snap, &State::default()).actions.iter().any(|a| matches!(a, Action::RemoveRoute(_))));
    }

    #[test]
    fn wireguard_on_lan_moves_the_follow_network_and_splits_wifi() {
        let wg = Vpn { name: "WireGuard".into(), adapter: "WireGuard Tunnel*".into(), via: "lan".into(), ..Default::default() };
        let cfg = Config { internet: "wifi".into(), vpns: vec![wg], ..Config::default() };
        let p = plan(&cfg, &both_up(), &State::default());
        assert_eq!(p.follow.as_deref(), Some("lan"));
        assert!(p.actions.contains(&Action::SetMetric { index: 7, alias: "Ethernet".into(), metric: 1 }));
        assert_eq!(adds(&p), ["0.0.0.0/1 via 192.168.1.1 (if 12)", "128.0.0.0/1 via 192.168.1.1 (if 12)"]);
    }

    #[test]
    fn default_route_vpns_share_one_network() {
        let mut cfg = tailscale();
        cfg.vpns.push(Vpn { name: "NordLynx".into(), via: "lan".into(), ..Default::default() });
        let p = plan(&cfg, &both_up(), &State::default());
        assert!(p.problems[0].contains("share one network (wifi)"), "{:?}", p.problems);
    }

    #[test]
    fn locked_kill_switch_stays_while_off() {
        let mut cfg = tailscale();
        cfg.enabled = false;
        let p = plan(&cfg, &both_up(), &State::default());
        assert_eq!(blocks(&p).len(), 2, "locked: still enforced");
        assert!(!p.actions.iter().any(|a| matches!(a, Action::SetMetric { .. } | Action::AddRoute(_))));
        cfg.vpns[0].locked = false;
        assert!(blocks(&plan(&cfg, &both_up(), &State::default())).is_empty());
    }

    #[test]
    fn unknown_network_is_a_problem_and_leaves_the_kill_switch() {
        let mut cfg = tailscale();
        cfg.vpns[0].via = "phone".into();
        let p = plan(&cfg, &both_up(), &State::default());
        assert!(p.problems.iter().any(|x| x.contains("no network \"phone\"")));
        assert!(blocks(&p).is_empty());
    }

    #[test]
    fn server_vpn_and_rules_get_host_routes() {
        let mut cfg = tailscale();
        cfg.vpns.push(Vpn { name: "OpenVPN".into(), kind: VpnKind::Server, via: "lan".into(), servers: vec!["203.0.113.7".into()], ..Default::default() });
        cfg.routes.push(RouteRule { prefix: "10.20.0.0/16".into(), via: "lan".into() });
        let a = adds(&plan(&cfg, &both_up(), &State::default()));
        assert!(a.contains(&"203.0.113.7/32 via 10.0.0.1 (if 7)".to_string()));
        assert!(a.contains(&"10.20.0.0/16 via 10.0.0.1 (if 7)".to_string()));
    }

    #[test]
    fn applied_state_is_stable_and_off_undoes_it() {
        let mut cfg = tailscale();
        cfg.vpns[0].locked = false;
        let mut snap = both_up();
        let p = plan(&cfg, &snap, &State::default());
        let state = record(&State::default(), &snap, &p.actions, false);
        snap.policy = Some(0);
        snap.adapters[0].metric = 1; snap.adapters[0].auto_metric = false;
        for a in &p.actions { if let Action::AddRoute(x) = a { snap.routes.push(*x); } }
        snap.rules = p.actions.iter().filter_map(|a| if let Action::BlockRule { name, program, aliases, .. } = a {
            Some(Rule { name: name.clone(), enabled: true, program: program.clone(), aliases: aliases.clone() }) } else { None }).collect();
        assert_eq!(plan(&cfg, &snap, &state).actions, vec![]);
        assert_eq!(state.metrics["Wi-Fi"], (true, 40));

        let off = plan(&Config { enabled: false, ..cfg }, &snap, &state);
        assert!(off.actions.contains(&Action::RestoreMetric { index: 12, alias: "Wi-Fi".into(), auto: true, metric: 40 }));
        assert_eq!(off.actions.iter().filter(|a| matches!(a, Action::RemoveRoute(_))).count(), 2);
        assert_eq!(off.actions.iter().filter(|a| matches!(a, Action::DisableRule { .. })).count(), 2);
        assert!(!off.actions.contains(&Action::SetPolicy));
    }

    #[test]
    fn lan_down_means_no_splits_and_a_note() {
        let mut snap = both_up();
        snap.adapters[1].up = false;
        let p = plan(&tailscale(), &snap, &State::default());
        assert!(adds(&p).is_empty());
        assert!(p.notes[0].contains("lan is not connected"));
    }

    fn rule(name: &str, aliases: &[&str]) -> Rule {
        Rule { name: name.into(), enabled: true, program: TAILSCALED.into(), aliases: aliases.iter().map(|a| a.to_string()).collect() }
    }

    #[test]
    fn old_rules_go_only_after_the_new_ones_exist() {
        let mut snap = both_up();
        snap.rules = vec![rule("old out", &[]), rule("old in", &[])];
        let p = plan(&tailscale(), &snap, &State::default());
        assert!(!p.actions.iter().any(|a| matches!(a, Action::RemoveRule { .. })), "kept while the new rules are pending");
        let b = ["Ethernet", "Ethernet 2", "Local Area Connection* 8"];
        snap.rules.push(rule("net-pin: Tailscale out", &b));
        snap.rules.push(rule("net-pin: Tailscale in", &b));
        let p = plan(&tailscale(), &snap, &State::default());
        assert_eq!(p.actions.iter().filter(|a| matches!(a, Action::RemoveRule { .. })).count(), 2);
        // Wi-Fi gone: the new rules cannot be built, so the old ones stay.
        let mut gone = snap.clone();
        gone.adapters.retain(|a| a.alias != "Wi-Fi");
        gone.rules.truncate(2);
        assert!(!plan(&tailscale(), &gone, &State::default()).actions.iter().any(|a| matches!(a, Action::RemoveRule { .. })));
    }

    #[test]
    fn pins_list_what_goes_where() {
        let mut cfg = tailscale();
        cfg.routes.push(RouteRule { prefix: "10.0.0.0/8".into(), via: "lan".into() });
        let p = pins(&cfg, &both_up());
        let rows: Vec<(String, String, bool)> = p.iter().map(|p| (p.what.clone(), p.network.clone(), p.up)).collect();
        assert_eq!(rows, [("Internet".into(), "lan".into(), true), ("Tailscale".into(), "wifi".into(), true), ("10.0.0.0/8".into(), "lan".into(), true)]);
        assert_eq!(p[1].flags, ["kill switch", "locked"]);
        assert_eq!(summary(&cfg, &both_up(), &Plan::default()), "3 pinned, all up");
        cfg.enabled = false;
        assert_eq!(pins(&cfg, &both_up()).len(), 1, "only the locked VPN while off");
        assert_eq!(summary(&Config::default(), &both_up(), &Plan::default()), "Nothing pinned");
    }

    #[test]
    fn config_round_trips_as_toml() {
        let c = tailscale();
        let s = toml::to_string_pretty(&c).unwrap();
        assert_eq!(toml::from_str::<Config>(&s).unwrap(), c);
        assert_eq!(toml::from_str::<Config>("").unwrap(), Config::default());
    }
}
