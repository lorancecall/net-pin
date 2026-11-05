# net-pin

Pin traffic to a network on Windows.

Windows makes it hard to say "this goes over Wi-Fi, that goes over Ethernet". It drops Wi-Fi when a
cable is plugged in, sends everything over the lowest-metric connection, and lets VPN clients pick
their own way out. net-pin lets you decide.

## Features

- **Internet:** general traffic goes over the network you pick.
- **VPNs:** each VPN's tunnel goes over the network you pick, with an optional fail-closed **kill
  switch**. If that network is down, the VPN goes offline instead of falling back to another network.
- **Routes:** chosen IPs or ranges go over the network you pick.
- **Networks:** `wifi` and `lan` out of the box. Add your own, such as USB tethering or cellular.
- **Keep both up:** optionally keep Wi-Fi connected while Ethernet is plugged in.
- **Safe:** it uses only standard Windows routes, interface metrics and firewall rules, with no
  drivers. Every changed value is recorded first and restored on uninstall.
- **Light:** a small background service re-applies your setup when the network changes, plus a tray
  icon and a `net-pin` command.

## Install

Download `net-pin-setup-<version>.exe` from [Releases](../../releases) and run it (admin).
A fresh install changes nothing until you configure it.

## Quick start

```powershell
net-pin status                      # adapters, networks, routes, what would change
net-pin internet lan                # general internet over Ethernet
net-pin route add 10.0.0.0/8 via lan
net-pin preset tailscale-wifi       # Tailscale only on Wi-Fi (locked), internet on LAN
```

## Examples

| Goal | Command |
|---|---|
| Keep Tailscale off the wired network | `net-pin preset tailscale-wifi` |
| Internet over Wi-Fi, internal ranges over LAN | `net-pin internet wifi` + `net-pin route add 10.0.0.0/8 via lan` |
| Game servers over Ethernet | `net-pin route add <server range> via lan` |
| A VPN only on Wi-Fi, never elsewhere | `net-pin vpn add WireGuard exe=<path> adapter="WireGuard Tunnel*" via=wifi kill-switch=on` |
| Use USB tethering as a network | `net-pin network add phone kind=ethernet description="Remote NDIS*"` |
| Pause everything | `net-pin off` (`net-pin on` to resume) |

## Commands

```text
net-pin status | plan | apply | on | off
net-pin internet <network> | default
net-pin network [add <name> kind=wireless|ethernet|cellular|any [alias=..] [description=..] | remove <name>]
net-pin vpn [add <name> exe=.. [adapter=..] [via=..] [kill-switch=on|off] [kind=default-route|server] [servers=..]]
net-pin vpn <name> via <network> | kill-switch on|off | remove
net-pin route [add <a.b.c.d/n> via <network> | remove <a.b.c.d/n>]
net-pin preset [<name>]
net-pin set keep-connected on|off | top-metric 1-4
net-pin config | log [n] | undo | service install|uninstall|start|stop | help
```

Names and descriptions accept `*` wildcards. Settings are stored in `C:\ProgramData\net-pin\config.toml`.

## How it works

| What | How |
|---|---|
| VPN network | That network's adapters get the lowest interface metric |
| Internet network | Its adapters get `0.0.0.0/1` + `128.0.0.0/1`, which beat the default route |
| Routes | A route to the prefix via the network's gateway |
| Kill switch | Windows Firewall blocks the VPN's program on every other adapter |
| Keep both up | Sets the `fMinimizeConnections = 0` policy (takes effect after a reboot) |

## Limits

- IPv4 only.
- Routing is by network and destination, not by app. For per-app VPN use, turn on your VPN client's
  split tunneling, and use net-pin to choose which network its tunnel uses.
- Default-route VPNs (Tailscale, WireGuard, NordLynx) share one network.

## Build

You need Rust and Inno Setup 6. Run `.\build.ps1`, which writes `dist\net-pin-setup-<version>.exe`.

## License

MIT
