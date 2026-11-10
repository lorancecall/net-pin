# Changelog

## 0.3.3

- Kill switch: a VPN can name several programs (`programs=`, one rule per program and direction;
  `*` stands for a folder that changes with updates) and ports (`ports=udp:51820`), blocked for
  every program off its network. Tunnels inside Windows (NordLynx, WireGuard) send from the
  kernel, so a rule on a program alone did not stop them. Rules of a removed program or port go
  once the VPN's new rules are in place; common ports (53, 67, 68, 80, 123, 443) are refused.
- Server VPNs: while their tunnel is up, the host route they add to their server on another
  network is copied to their own network, so `internet lan` no longer pulls them onto the LAN.
- `adapter=` takes several patterns, comma-separated.
- `net-pin vpn <name> set key=value ...` changes an existing VPN; `net-pin programs [filter]` lists
  running programs with their paths (including services a user cannot open).
- New preset `nordvpn-wifi`.

## 0.3.2

- Status shows what is pinned where as a list: one row per pin in the tray menu, a table in
  `net-pin status` (`--all` adds adapters, routes and firewall rules).
- Setup no longer asks about Tailscale; `net-pin preset` explains the ready-made setups.

## 0.3.1

- Removed the coexistence check with another network tool and the `netpin.ps1` file it relied on.

## 0.3.0

First public release.

- Named networks (`wifi`, `lan`, or your own by adapter kind, name or description).
- General internet, each VPN's tunnel and chosen destinations go over the network you pick.
- Per-VPN kill switch (fail-closed); `locked` VPNs can only be changed by an administrator.
- Preset `tailscale-wifi`, offered at setup.
- `net-pin` command on the PATH, a small background service and a tray icon.
- Every changed value is recorded first and restored on uninstall.
