# Changelog

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
