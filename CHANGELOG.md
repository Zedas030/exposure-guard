# Changelog

## 1.0.0 - 2026-11-05

First release.

- FRITZ!Box via TR-064 + UPnP IGD (read-only, enforced): port forwardings split into manual and UPnP with device and
  first-seen time, MyFRITZ! sharings, UPnP status, remote access, MyFRITZ! account, provider management, firmware,
  public IPv4 / IPv6 / prefix with change detection. DS-Lite lines are detected: the shared provider IPv4 is
  never scanned, the router's LAN IPv6 counts as router address, the prefix falls back to the LAN /64.
- External probe for a small VPS: scans only guard-signed targets (public IPv4, router WAN IPv6, every global IPv6
  address seen in the LAN), top ports daily, all TCP ports weekly, UDP on the router, service/version detection, TLS;
  results sealed to the guard (libsodium sealed box) and signed (Ed25519); pulled over SSH with a forced command.
- Public IP cross-check: router view vs. the source address the probe sees.
- Passive LAN inventory (router host list, ARP, NDP, one ICMPv6 echo to ff02::1), vendor lookup offline.
- Weekly gentle LAN web check (TCP connect at -T2 with rate cap, one GET per start page): plain-HTTP logins,
  default-login / unauthenticated products, TLS certificates. No login attempts.
- Tailscale: nodes, key expiry, exit nodes, subnet routes (LocalAPI); ACL/policy and device checks (OAuth, read-only).
- Baseline on first run, drift alerts for critical changes, acknowledgements bound to the finding's state (YAML or CLI).
- Self-monitoring: failing checks, unreachable or stale probe, IP mismatch -> warning and status `unknown`/`degraded`,
  never "ok"; outbox for notifications while Home Assistant is down.
- Home Assistant notify + sensors, dead man's switch automation, Prometheus metrics, Grafana dashboard, read-only web UI,
  initial and weekly reports (HTML + Markdown).
- Docker Compose deployment (unprivileged, read-only, resource limits, log rotation, autostart); unit and end-to-end tests.
