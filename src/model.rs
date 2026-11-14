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
    /// The program whose traffic the kill switch blocks off `via` (first of `all_programs()`).
    pub exe: String,
    /// More programs for the kill switch; `*` matches within one folder level (a version folder).
    pub programs: Vec<String>,
    /// Its tunnel adapters, by description (`*` wildcards, comma-separated); never blocked, never in a network.
    pub adapter: String,
    /// Network name.
    pub via: String,
    pub kill_switch: bool,
    /// Kill switch stays on while routing is off; only an admin editing config.toml changes it.
    pub locked: bool,
    /// `Server` VPNs: server addresses (`a.b.c.d` or `a.b.c.d/n`).
    pub servers: Vec<String>,
    /// Remote ports the kill switch blocks for every program (`udp 51820`): tunnels in the kernel
    /// (NordLynx, WireGuard) send from Windows itself, not from a program.
    pub ports: Vec<String>,
    /// Exact physical interface for private IPv4 relay host exceptions.
    pub relay_interface: String,
    /// Exact RFC1918 host addresses; all ports/protocols are exempt on relay_interface.
    pub relay_hosts: Vec<String>,
}

impl Default for Vpn {
    fn default() -> Self {
        Self { name: String::new(), kind: VpnKind::DefaultRoute, exe: String::new(), programs: Vec::new(), adapter: String::new(),
               via: "wifi".into(), kill_switch: false, locked: false, servers: Vec::new(), ports: Vec::new(), relay_interface: String::new(), relay_hosts: Vec::new() }
    }
}

impl Vpn {
    /// `exe` and `programs`, without blanks or repeats.
    pub fn all_programs(&self) -> Vec<String> {
        let mut v: Vec<String> = Vec::new();
        for p in std::iter::once(&self.exe).chain(&self.programs) {
            let p = p.trim().trim_matches('"').to_string();
            if !p.is_empty() && !v.iter().any(|x| x.eq_ignore_ascii_case(&p)) { v.push(p); }
        }
        v
    }
    /// Sets `exe` and `programs` from one list.
    pub fn set_programs(&mut self, list: Vec<String>) {
        let mut it = list.into_iter();
        self.exe = it.next().unwrap_or_default();
        self.programs = it.collect();
    }
    pub fn adapter_patterns(&self) -> Vec<String> {
        self.adapter.split([',', ';']).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
    }
    /// Whether `a` is one of its tunnel adapters.
    pub fn is_tunnel(&self, a: &Adapter) -> bool { self.adapter_patterns().iter().any(|p| glob(p, &a.description)) }
}

/// `udp 51820`, `tcp 1194,1195`, `udp:51820` -> (protocol number, ports). Pure; tested.
pub fn parse_ports(s: &str) -> Option<(u8, String)> {
    let s = s.trim().to_lowercase();
    let (proto, rest) = s.split_once([' ', ':', '/'])?;
    let proto = match proto.trim() { "udp" => 17, "tcp" => 6, _ => return None };
    let ports: Vec<u16> = rest.split([',', ' ']).filter(|p| !p.is_empty()).map(|p| p.parse().ok()).collect::<Option<_>>()?;
    if ports.is_empty() || ports.contains(&0) { return None; }
    Some((proto, ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",")))
}

/// Ports nobody should block for every program on a network (web, DNS, DHCP, time).
const COMMON_PORTS: [&str; 6] = ["53", "67", "68", "80", "123", "443"];

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
pub const PRESETS: [(&str, &str); 2] = [
    ("tailscale-wifi", "For a PC on a wired network that Tailscale must never use: Tailscale only on Wi-Fi
                     (locked kill switch), general internet on the LAN, Wi-Fi kept up beside Ethernet"),
    ("nordvpn-wifi", "NordVPN only on Wi-Fi with its kill switch: its service programs and NordLynx's
                     udp 51820 are blocked on every other network; its server route moves to Wi-Fi"),
];

pub const NORDVPN_SERVICE: &str = r"C:\Program Files\NordVPN\nordvpn-service.exe";

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
        "nordvpn-wifi" => {
            if cfg.network("wifi").is_none() { cfg.networks.push(Network::new("wifi", Kind::Wireless)); }
            cfg.keep_all_connected = true;
            cfg.vpns.retain(|v| !v.name.eq_ignore_ascii_case("NordVPN"));
            cfg.vpns.push(Vpn { name: "NordVPN".into(), kind: VpnKind::Server, exe: NORDVPN_SERVICE.into(),
                                programs: vec![r"C:\Program Files\NordVPN\*\nordvpn-service-app.exe".into(),
                                               r"C:\Program Files\NordVPN\*\Resources\Binaries\64bit\openvpn-nordvpn.exe".into()],
                                adapter: "NordLynx*, OpenVPN Data Channel Offload*".into(), via: "wifi".into(),
                                kill_switch: true, ports: vec!["udp 51820".into()], ..Default::default() });
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

fn all_addresses() -> String { "*".into() }

/// One of net-pin's firewall rules (group `fw::GROUP`). `aliases` comes from the rule's description, which net-pin writes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    pub enabled: bool,
    /// Empty: every program.
    pub program: String,
    pub aliases: Vec<String>,
    /// Protocol number (6 TCP, 17 UDP) and remote ports, for port rules.
    #[serde(default)]
    pub ports: Option<(u8, String)>,
    #[serde(default = "all_addresses")]
    pub remote_addresses: String,
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
    /// Create or replace a block rule for `program` (empty: every program) on `aliases`, enabled;
    /// with `ports`, only that protocol and those remote ports.
    BlockRule { name: String, program: String, aliases: Vec<String>, outbound: bool, ports: Option<(u8, String)>, remote_addresses: String },
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
    cfg.vpns.iter().any(|v| v.is_tunnel(a))
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

/// One kill-switch rule: name, program (empty: every program), outbound, ports.
struct RuleSpec {
    name: String, program: String, outbound: bool, ports: Option<(u8, String)>,
    aliases: Vec<String>, remote_addresses: String,
}

/// Complement of exact private IPv4 hosts, including all IPv6. Invalid input fails closed.
fn relay_complement(hosts: &[String]) -> Option<String> {
    if hosts.is_empty() { return None; }
    let mut values = Vec::new();
    for host in hosts {
        let ip = host.parse::<Ipv4Addr>().ok()?;
        if !ip.is_private() { return None; }
        values.push(u32::from(ip));
    }
    values.sort_unstable();
    values.dedup();
    let mut ranges = Vec::new();
    let mut start = 0u64;
    for value in values {
        if start < value as u64 {
            ranges.push(format!("{}-{}", Ipv4Addr::from(start as u32), Ipv4Addr::from(value - 1)));
        }
        start = value as u64 + 1;
    }
    if start <= u32::MAX as u64 {
        ranges.push(format!("{}-255.255.255.255", Ipv4Addr::from(start as u32)));
    }
    ranges.push("::/0".into());
    Some(ranges.join(","))
}

/// A VPN's kill-switch rules: `net-pin: <vpn> out|in` for its first program, `... out #2` for the
/// next ones, `net-pin: <vpn> udp 51820 out` per port entry. Bad or common port entries are left
/// out and reported in `problems`.
fn rule_specs(v: &Vpn, snap: &Snapshot, keep: &[u32], problems: &mut Vec<String>) -> Vec<RuleSpec> {
    let dir = |o: bool| if o { "out" } else { "in" };
    let mut out = Vec::new();
    for (i, prog) in v.all_programs().iter().enumerate() {
        for o in [true, false] {
            let name = if i == 0 { format!("net-pin: {} {}", v.name, dir(o)) } else { format!("net-pin: {} {} #{}", v.name, dir(o), i + 1) };
            out.push((name, prog.clone(), o, None));
        }
    }
    for spec in &v.ports {
        match parse_ports(spec) {
            None => problems.push(format!("{}: bad port entry {spec:?} (e.g. udp 51820)", v.name)),
            Some((_, ports)) if ports.split(',').any(|x| COMMON_PORTS.contains(&x)) =>
                problems.push(format!("{}: {spec:?} would block common traffic for every program; left out", v.name)),
            Some(pp) => out.push((format!("net-pin: {} {} out", v.name, spec.trim().to_lowercase().replace(':', " ")), String::new(), true, Some(pp))),
        }
    }
    let mut aliases: Vec<String> = snap.adapters.iter()
        .filter(|a| !keep.contains(&a.index) && !is_loopback(a) && !v.is_tunnel(a))
        .map(|a| a.alias.clone()).collect();
    aliases.sort();
    let configured = !v.relay_hosts.is_empty();
    let relay = relay_complement(&v.relay_hosts).filter(|_| {
        snap.adapters.iter().any(|a| a.alias == v.relay_interface && a.if_type == 6
            && !keep.contains(&a.index) && !v.is_tunnel(a))
    });
    if configured && relay.is_none() {
        problems.push(format!("{}: relay exception requires exact private IPv4 hosts and an existing non-VPN Ethernet interface; full block retained", v.name));
    }
    let mut scoped = Vec::new();
    for (name, program, outbound, ports) in out {
        // Global/kernel-port rules never receive relay exceptions.
        if let Some(addresses) = relay.as_ref().filter(|_| !program.is_empty() && ports.is_none()) {
            scoped.push(RuleSpec { name: format!("{name} relay external"), program: program.clone(), outbound,
                ports: None, aliases: vec![v.relay_interface.clone()], remote_addresses: addresses.clone() });
            let others: Vec<String> = aliases.iter().filter(|a| **a != v.relay_interface).cloned().collect();
            if !others.is_empty() {
                scoped.push(RuleSpec { name: format!("{name} relay other interfaces"), program, outbound,
                    ports: None, aliases: others, remote_addresses: "*".into() });
            }
        } else if !aliases.is_empty() {
            scoped.push(RuleSpec { name, program, outbound, ports, aliases: aliases.clone(), remote_addresses: "*".into() });
        }
    }
    scoped
}

/// Host routes a `Server` VPN added itself on another network while its tunnel is up: `/32`s via
/// the gateway of an adapter in a network other than `via` (its server, routed by the best route,
/// which net-pin's `/1` splits may have put there). net-pin adds the same host route via `via`.
fn learned_servers(cfg: &Config, snap: &Snapshot, state: &State, v: &Vpn) -> Vec<String> {
    if v.kind != VpnKind::Server || !snap.adapters.iter().any(|a| a.up && v.is_tunnel(a)) { return Vec::new(); }
    let other: Vec<u32> = snap.adapters.iter()
        .filter(|a| snap.network_of(cfg, a).is_some_and(|n| !n.name.eq_ignore_ascii_case(&v.via))).map(|a| a.index).collect();
    let mut out: Vec<String> = snap.routes.iter()
        .filter(|r| r.len == 32 && other.contains(&r.index) && r.next_hop != ANY && snap.gateway(r.index) == Some(r.next_hop))
        .filter(|r| !state.routes.iter().any(|o| o.prefix == r.prefix && o.len == 32 && o.index == r.index))
        .map(|r| format!("{}/32", r.prefix)).collect();
    out.sort();
    out.dedup();
    out
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
        for v in cfg.vpns.iter().filter(|v| v.kind == VpnKind::Server) {
            for s in &v.servers { targets.push((s.clone(), v.via.clone())); }
            for s in learned_servers(cfg, snap, state, v) {
                p.notes.push(format!("{}: server {s} moved to {}", v.name, v.via));
                targets.push((s, v.via.clone()));
            }
        }
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

    // Kill switches: one rule per program and direction, one outbound rule per port entry.
    let mut specs: Vec<(&Vpn, Vec<RuleSpec>)> = Vec::new();
    for v in &cfg.vpns {
        let keep: Vec<u32> = snap.network(cfg, &v.via).iter().map(|a| a.index).collect();
        let rules = rule_specs(v, snap, &keep, &mut p.problems);
        if guarding(cfg, v) {
            let keep: Vec<u32> = snap.network(cfg, &v.via).iter().map(|a| a.index).collect();
            if keep.is_empty() {
                p.problems.push(format!("{}: no adapter in network {:?}; kill switch left as it is", v.name, v.via));
            } else if rules.is_empty() {
                p.problems.push(format!("{}: the kill switch has no program or port to block", v.name));
            } else {
                block_rules(&mut p, snap, &rules);
            }
        } else {
            for rule in &rules {
                let name = &rule.name;
                if snap.rules.iter().any(|r| &r.name == name && r.enabled) { p.actions.push(Action::DisableRule { name: name.clone() }); }
            }
        }
        specs.push((v, rules));
    }

    // Rules nobody asks for (a removed VPN, program or port). An old rule that guarded the same
    // program or ports stays until the VPN's new rules all exist and are enabled (fail-closed).
    let wanted: Vec<&String> = specs.iter().flat_map(|(_, r)| r.iter().map(|x| &x.name)).collect();
    let in_place = |v: &Vpn, rules: &[RuleSpec]| !snap.network(cfg, &v.via).is_empty() && !rules.is_empty() && rules.iter()
        .all(|spec| snap.rules.iter().any(|r| rule_matches(r, spec)));
    let stale: Vec<(String, bool)> = snap.rules.iter().filter(|r| !wanted.contains(&&r.name)).map(|r| {
        let mut guarded = specs.iter().filter(|(v, _)| guarding(cfg, v)
            && (v.all_programs().iter().any(|prog| prog.eq_ignore_ascii_case(&r.program))
                || (r.program.is_empty() && v.ports.iter().any(|port| parse_ports(port) == r.ports))));
        (r.name.clone(), guarded.all(|(v, rules)| in_place(v, rules)))
    }).collect();
    for (name, go) in stale {
        if go { p.actions.push(Action::RemoveRule { name }); }
        else { p.notes.push(format!("old firewall rule {name} kept until the new kill switch is in place")); }
    }
    p
}

/// Block rules for `v` on every adapter outside `keep`, its tunnels and loopback.
fn block_rules(p: &mut Plan, snap: &Snapshot, rules: &[RuleSpec]) {
    for spec in rules {
        let ok = snap.rules.iter().any(|r| rule_matches(r, spec));
        if !ok {
            p.actions.push(Action::BlockRule { name: spec.name.clone(), program: spec.program.clone(),
                aliases: spec.aliases.clone(), outbound: spec.outbound, ports: spec.ports.clone(),
                remote_addresses: spec.remote_addresses.clone() });
        }
    }
}

fn rule_matches(r: &Rule, spec: &RuleSpec) -> bool {
    r.name == spec.name && r.enabled && r.aliases == spec.aliases
        && r.program.eq_ignore_ascii_case(&spec.program) && r.ports == spec.ports
        && same_addresses(&r.remote_addresses, &spec.remote_addresses)
}

/// Normalize Windows' remote-address spelling into merged inclusive address ranges.
fn address_ranges(input: &str) -> Option<Vec<(u8, u128, u128)>> {
    use std::net::IpAddr;
    fn address(s: &str) -> Option<(u8, u128)> {
        match s.trim().parse::<IpAddr>().ok()? {
            IpAddr::V4(ip) => Some((4, u32::from(ip) as u128)),
            IpAddr::V6(ip) => Some((6, u128::from(ip))),
        }
    }
    let mut ranges = Vec::new();
    for item in input.split(',').map(str::trim) {
        if item == "*" {
            ranges.extend([(4, 0, u32::MAX as u128), (6, 0, u128::MAX)]);
        } else if let Some((left, right)) = item.split_once('-') {
            let (af, first) = address(left)?;
            let (bf, last) = address(right)?;
            if af != bf || first > last { return None; }
            ranges.push((af, first, last));
        } else if let Some((host, mask)) = item.split_once('/') {
            let (af, ip) = address(host)?;
            let bits = if af == 4 { 32 } else { 128 };
            let prefix: u32 = match mask.trim().parse::<u32>() {
                Ok(n) if n <= bits => n,
                Ok(_) => return None,
                Err(_) => {
                    let (mf, value) = address(mask)?;
                    if mf != af { return None; }
                    let m = if af == 4 { (value as u32).leading_ones() } else { value.leading_ones() };
                    let expected = if m == 0 { 0 } else { u128::MAX << (bits - m) };
                    let expected = if af == 4 { expected & u32::MAX as u128 } else { expected };
                    if value != expected { return None; }
                    m
                }
            };
            let full = if af == 4 { u32::MAX as u128 } else { u128::MAX };
            let hostmask = if prefix == 0 { full } else if prefix == bits { 0 } else { full >> prefix };
            let first = ip & (full ^ hostmask);
            ranges.push((af, first, first | hostmask));
        } else {
            let (af, ip) = address(item)?;
            ranges.push((af, ip, ip));
        }
    }
    ranges.sort_unstable();
    let mut merged: Vec<(u8, u128, u128)> = Vec::new();
    for (af, start, end) in ranges {
        if let Some(last) = merged.last_mut()
            && last.0 == af && start <= last.2.saturating_add(1) {
            last.2 = last.2.max(end);
        } else {
            merged.push((af, start, end));
        }
    }
    if merged.is_empty() { None } else { Some(merged) }
}

fn same_addresses(a: &str, b: &str) -> bool {
    match (address_ranges(a), address_ranges(b)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
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

    #[test]
    fn remote_address_normalization_accepts_windows_spellings() {
        assert!(same_addresses("192.168.1.5, ::/0", "0:0:0:0:0:0:0:0/0,192.168.1.5-192.168.1.5"));
        assert!(same_addresses("192.168.1.0/24", "192.168.1.0/255.255.255.0"));
        assert!(same_addresses("192.168.1.0/24", "192.168.1.0-192.168.1.127,192.168.1.128-192.168.1.255"));
        assert!(same_addresses("*", "0.0.0.0/0,::/::"));
        assert!(same_addresses("::1/128", "::1"));
        assert!(!same_addresses("192.168.1.0/24", "192.168.1.0/25"));
        assert!(!same_addresses("192.168.1.0/255.0.255.0", "192.168.1.0/24"));
        assert!(!same_addresses("", ""));
    }

    #[test]
    fn old_config_has_no_relay_exceptions() {
        let v: Vpn = toml::from_str("name = \"N\"").unwrap();
        assert!(v.relay_hosts.is_empty());
        assert!(v.relay_interface.is_empty());
        assert!(Vpn::default().relay_hosts.is_empty());
    }
    fn relay_config() -> Config {
        let mut cfg = tailscale();
        cfg.vpns[0].relay_interface = "Ethernet".into();
        cfg.vpns[0].relay_hosts = vec!["192.168.50.1".into(), "192.168.50.5".into()];
        cfg
    }

    fn planned_rules(p: &Plan) -> Vec<Rule> {
        p.actions.iter().filter_map(|a| match a {
            Action::BlockRule { name, program, aliases, ports, remote_addresses, .. } => Some(Rule {
                name: name.clone(), enabled: true, program: program.clone(), aliases: aliases.clone(),
                ports: ports.clone(), remote_addresses: remote_addresses.clone(),
            }), _ => None
        }).collect()
    }

    #[test]
    fn relay_hosts_complement_and_input_validation() {
        assert_eq!(relay_complement(&relay_config().vpns[0].relay_hosts).unwrap(),
            "0.0.0.0-192.168.50.0,192.168.50.2-192.168.50.4,192.168.50.6-255.255.255.255,::/0");
        for bad in ["0.0.0.0", "8.8.8.8", "::1", "192.168.50.0/24", "*", "127.0.0.1", "169.254.1.1"] {
            assert!(relay_complement(&[bad.into()]).is_none(), "{bad}");
        }
        assert!(relay_complement(&[]).is_none());
        let one = relay_complement(&["10.0.0.1".into()]).unwrap();
        assert_eq!(one, relay_complement(&["10.0.0.1".into(), "10.0.0.1".into()]).unwrap());
    }

    #[test]
    fn relay_only_exact_ethernet_and_actual_addresses_are_compared() {
        let cfg = relay_config();
        let mut snap = both_up();
        let p = plan(&cfg, &snap, &State::default());
        let rules = planned_rules(&p);
        assert_eq!(rules.len(), 4);
        for rule in &rules {
            if rule.name.ends_with("relay external") {
                assert_eq!(rule.aliases, ["Ethernet"]);
                assert!(rule.remote_addresses.ends_with(",::/0"));
            } else {
                assert_eq!(rule.remote_addresses, "*");
                assert!(!rule.aliases.contains(&"Ethernet".into()));
                assert!(!rule.aliases.contains(&"Wi-Fi".into()));
            }
        }
        snap.rules = rules;
        assert!(planned_rules(&plan(&cfg, &snap, &State::default())).is_empty());
        snap.rules[0].remote_addresses = "10.0.0.0/8".into(); // external tampering must be repaired
        assert_eq!(planned_rules(&plan(&cfg, &snap, &State::default())).len(), 1);
    }

    #[test]
    fn relay_migration_is_fail_closed_and_clear_restores_full_block() {
        let cfg = relay_config();
        let mut snap = both_up();
        snap.rules = planned_rules(&plan(&tailscale(), &snap, &State::default()));
        let p = plan(&cfg, &snap, &State::default());
        assert!(!p.actions.iter().any(|a| matches!(a, Action::RemoveRule { .. })));
        snap.rules.extend(planned_rules(&p));
        let ready = plan(&cfg, &snap, &State::default());
        assert_eq!(ready.actions.iter().filter(|a| matches!(a, Action::RemoveRule { .. })).count(), 2);
        snap.rules.retain(|r| r.name.contains("relay "));
        let mut cleared = cfg;
        cleared.vpns[0].relay_hosts.clear();
        let p = plan(&cleared, &snap, &State::default());
        assert!(p.problems.is_empty());
        assert_eq!(planned_rules(&p).len(), 2);
        assert!(!p.actions.iter().any(|a| matches!(a, Action::RemoveRule { .. })));
        assert!(planned_rules(&p).iter().all(|r| r.remote_addresses == "*"));
    }

    #[test]
    fn relay_invalid_inputs_or_missing_interface_keep_full_block() {
        for interface in ["", "Missing", "Wi-Fi", "Tailscale", "Ether*"] {
            let mut cfg = relay_config();
            cfg.vpns[0].relay_interface = interface.into();
            let p = plan(&cfg, &both_up(), &State::default());
            assert!(!p.problems.is_empty(), "{interface}");
            assert_eq!(planned_rules(&p).len(), 2);
            assert!(planned_rules(&p).iter().all(|r| r.remote_addresses == "*"));
        }
        let mut cfg = relay_config();
        cfg.vpns[0].relay_hosts.push("8.8.8.8".into());
        let p = plan(&cfg, &both_up(), &State::default());
        assert!(!p.problems.is_empty());
        assert!(planned_rules(&p).iter().all(|r| r.remote_addresses == "*"));
    }

    #[test]
    fn relay_missing_wifi_or_invalid_config_does_not_retire_old_guards() {
        let mut cfg = relay_config();
        let mut snap = both_up();
        snap.rules = planned_rules(&plan(&tailscale(), &snap, &State::default()));
        snap.adapters.retain(|a| a.alias != "Wi-Fi");
        let p = plan(&cfg, &snap, &State::default());
        assert!(!p.actions.iter().any(|a| matches!(a, Action::RemoveRule { .. })));
        let mut snap = both_up();
        snap.rules = planned_rules(&plan(&cfg, &snap, &State::default()));
        cfg.vpns[0].relay_interface = "Missing".into();
        let p = plan(&cfg, &snap, &State::default());
        assert!(!p.actions.iter().any(|a| matches!(a, Action::RemoveRule { .. })));
        assert!(planned_rules(&p).iter().all(|r| r.remote_addresses == "*"));
    }

    #[test]
    fn relay_wifi_down_keeps_external_block() {
        let cfg = relay_config();
        let mut snap = both_up();
        snap.adapters.iter_mut().find(|a| a.alias == "Wi-Fi").unwrap().up = false;
        let rules = planned_rules(&plan(&cfg, &snap, &State::default()));
        assert_eq!(rules.len(), 4);
        assert!(rules.iter().filter(|r| r.name.ends_with("external")).all(|r| r.remote_addresses.ends_with("::/0")));
    }
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
        snap.rules = p.actions.iter().filter_map(|a| if let Action::BlockRule { name, program, aliases, ports, remote_addresses, .. } = a {
            Some(Rule { name: name.clone(), enabled: true, program: program.clone(), aliases: aliases.clone(), ports: ports.clone(), remote_addresses: remote_addresses.clone() }) } else { None }).collect();
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
        Rule { name: name.into(), enabled: true, program: TAILSCALED.into(), aliases: aliases.iter().map(|a| a.to_string()).collect(), ports: None, remote_addresses: "*".into() }
    }

    #[test]
    fn port_entries() {
        assert_eq!(parse_ports("udp 51820"), Some((17, "51820".into())));
        assert_eq!(parse_ports("TCP:1194, 1195"), Some((6, "1194,1195".into())));
        assert_eq!(parse_ports("51820"), None);
        assert_eq!(parse_ports("udp x"), None);
    }

    /// NordVPN preset (one program found), NordLynx connected, general internet on the LAN, and
    /// NordVPN's server route taken by the LAN's /1 split.
    fn nord() -> (Config, Snapshot) {
        let mut cfg = Config::default();
        preset("nordvpn-wifi", &mut cfg).unwrap();
        cfg.internet = "lan".into();
        cfg.vpns[0].programs = vec![r"C:\Program Files\NordVPN\8.15.2.0\nordvpn-service-app.exe".into()];
        let mut snap = both_up();
        snap.adapters.push(ad(37, "NordLynx", "NordLynx Tunnel", true, 1, 53));
        snap.routes.push(r("185.1.2.3/32", 7, "10.0.0.1", 0));
        snap.routes.push(r("10.0.0.20/32", 7, "0.0.0.0", 0)); // the LAN's own address: on-link
        (cfg, snap)
    }

    #[test]
    fn nordvpn_kill_switch_blocks_its_service_and_the_kernel_port() {
        let (cfg, snap) = nord();
        let p = plan(&cfg, &snap, &State::default());
        let rules: Vec<(String, String, Option<(u8, String)>, Vec<String>)> = p.actions.iter().filter_map(|a| match a {
            Action::BlockRule { name, program, ports, aliases, .. } => Some((name.clone(), program.clone(), ports.clone(), aliases.clone())), _ => None }).collect();
        let names: Vec<&str> = rules.iter().map(|r| r.0.as_str()).collect();
        assert_eq!(names, ["net-pin: NordVPN out", "net-pin: NordVPN in", "net-pin: NordVPN out #2", "net-pin: NordVPN in #2", "net-pin: NordVPN udp 51820 out"]);
        assert!(rules[0].1.ends_with("nordvpn-service.exe"));
        assert_eq!((rules[4].1.as_str(), rules[4].2.clone()), ("", Some((17, "51820".into()))));
        assert!(rules.iter().all(|r| !r.3.contains(&"NordLynx".to_string()) && !r.3.contains(&"Wi-Fi".to_string())));
        assert!(rules[0].3.contains(&"Ethernet".to_string()));
    }

    #[test]
    fn nordvpn_server_route_moves_to_its_network() {
        let (cfg, snap) = nord();
        assert_eq!(adds(&plan(&cfg, &snap, &State::default())).iter().filter(|a| a.starts_with("185.")).collect::<Vec<_>>(),
                   ["185.1.2.3/32 via 192.168.1.1 (if 12)"]);
        let mut down = snap.clone();
        down.adapters.last_mut().unwrap().up = false;
        assert!(!adds(&plan(&cfg, &down, &State::default())).iter().any(|a| a.starts_with("185.")));
    }

    #[test]
    fn removed_port_rule_goes_and_common_ports_are_refused() {
        let (mut cfg, mut snap) = nord();
        snap.rules.push(Rule { name: "net-pin: NordVPN udp 1194 out".into(), enabled: true, program: String::new(),
                               aliases: vec!["Ethernet".into()], ports: Some((17, "1194".into())), remote_addresses: "*".into() });
        cfg.vpns[0].ports.push("tcp 443".into());
        let p = plan(&cfg, &snap, &State::default());
        assert!(p.actions.contains(&Action::RemoveRule { name: "net-pin: NordVPN udp 1194 out".into() }));
        assert!(p.problems.iter().any(|x| x.contains("tcp 443")));
    }

    #[test]
    fn old_vpn_entries_load() {
        let v: Vpn = toml::from_str("name = \"N\"\nexe = 'C:\\a.exe'\nadapter = \"A*, B*\"\n").unwrap();
        assert_eq!((v.all_programs(), v.adapter_patterns()), (vec![r"C:\a.exe".to_string()], vec!["A*".to_string(), "B*".into()]));
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
