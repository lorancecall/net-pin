# Changelog

## 0.3.0

First public release.

- Named networks (`wifi`, `lan`, or your own by adapter kind, name or description).
- General internet, each VPN's tunnel and chosen destinations go over the network you pick.
- Per-VPN kill switch (fail-closed); `locked` VPNs can only be changed by an administrator.
- Preset `tailscale-wifi`, offered at setup.
- `net-pin` command on the PATH, a small background service and a tray icon.
- Every changed value is recorded first and restored on uninstall.
