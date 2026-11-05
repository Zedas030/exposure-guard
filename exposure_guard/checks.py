"""Turn collected facts (router, inventory) into findings with assessment and concrete action."""
from __future__ import annotations

from .findings import Finding
from .inventory import label


def router_findings(snap: dict, devices: dict, store) -> list[Finding]:
    out: list[Finding] = []
    dev = snap.get("device", {})

    # ---- port mappings ----------------------------------------------------------------------
    for m in snap.get("port_mappings", []):
        proto, port = m["protocol"].lower(), m["external_port"]
        key = f"map:{m['origin']}:{proto}/{port}:{m['internal_client']}:{m['internal_port']}"
        first = store.observe(key, "port_mapping", m)
        who = label(devices, ip=m["internal_client"])
        upnp = m["origin"] == "upnp"
        how = "opened via UPnP by the device itself" if upnp else "manual port forwarding"
        msg = (f"Port {port}/{proto} is forwarded from the internet to {who}:{m['internal_port']} - {how}"
               f" (first seen {first}). Description: '{m['description'] or '-'}'"
               + ("" if m["enabled"] else " (entry disabled)") + "."
               + (" Note: the line is DS-Lite, so this IPv4 forwarding is not reachable from the internet over IPv4 -"
                  " but the device asked for exposure; check its IPv6 sharing too." if snap.get("dslite") else ""))
        action = ("Check whether the device really needs to be reachable from the internet. If not: delete the "
                  "forwarding in FRITZ!Box > Internet > Permit Access and untick 'Permit independent port sharing' "
                  "for this device. Prefer Tailscale for own access." if upnp else
                  "Verify the forwarding is still needed and the service behind it is patched and authenticated; "
                  "remove it otherwise (FRITZ!Box > Internet > Permit Access).")
        out.append(Finding(
            id=f"map:{proto}/{port}", source="fritz", kind="port_mapping",
            severity="critical" if m["enabled"] else "medium",
            title=f"{'UPnP' if upnp else 'Manual'} port forwarding {port}/{proto} -> {m['internal_client']}",
            message=msg, action=action,
            detail=dict(m, first_seen=first, device=who),
            state_key=[m["origin"], m["internal_client"], m["internal_port"], m["enabled"]],
        ))

    for s in snap.get("myfritz_services", []):
        if not s.get("enabled"):
            continue
        name = s["name"] or s["host"] or s["ipv4"]
        first = store.observe(f"myfritz:{name}:{s['port']}", "myfritz_service", s)
        out.append(Finding(
            id=f"myfritz:{name}:{s['port']}", source="fritz", kind="port_mapping", severity="critical",
            title=f"MyFRITZ! sharing '{name}' ({s['scheme'] or 'port'} {s['port']})",
            message=f"A MyFRITZ! sharing publishes {s['ipv4'] or s['ipv6'] or s['host']} port {s['port']} "
                    f"(first seen {first}).",
            action="Remove the sharing if not needed (FRITZ!Box > Internet > Permit Access > MyFRITZ!).",
            detail=dict(s, first_seen=first), state_key=[s["ipv4"], s["ipv6"], s["port"], s["scheme"]]))

    # ---- UPnP / remote access ---------------------------------------------------------------
    upnp = snap.get("upnp", {})
    if upnp.get("enabled"):
        out.append(Finding(
            id="router:upnp", source="fritz", kind="config", severity="medium",
            title="UPnP status/port sharing is enabled on the router",
            message="Devices may open ports to the internet by themselves (UPnP IGD). "
                    "Exposure Guard watches every such mapping, but the safest default is to forbid it.",
            action="FRITZ!Box > Home Network > Network > Network Settings: keep 'Transmit status information over "
                   "UPnP' only if needed, and untick 'Permit independent port sharing' for every device in "
                   "Internet > Permit Access unless it really needs it.",
            state_key=[True]))
    ra = snap.get("remote_access", {})
    if ra.get("enabled"):
        out.append(Finding(
            id="router:remote-access", source="fritz", kind="config", severity="medium",
            title=f"FRITZ!Box remote access (HTTPS) open on port {ra.get('port')}",
            message="The router login page is reachable from the internet "
                    f"(Let's Encrypt: {'on' if ra.get('letsencrypt') else 'off'}, state {ra.get('letsencrypt_state') or '-'}). "
                    "Risk: password guessing and vulnerabilities in the router web UI.",
            action="Keep it only if needed; use a long unique password and 2FA, or reach the router via Tailscale "
                   "instead and switch off 'Internet access to the FRITZ!Box via HTTPS'.",
            state_key=[ra.get("port"), ra.get("letsencrypt")]))
    mf = snap.get("myfritz", {})
    if mf.get("enabled"):
        out.append(Finding(
            id="router:myfritz", source="fritz", kind="config", severity="low",
            title="MyFRITZ! account active",
            message="The router registers its public address with AVM's MyFRITZ! service (dynamic DNS name).",
            action="Fine if you use it; otherwise disable it in FRITZ!Box > Internet > MyFRITZ! Account.",
            state_key=[True]))
    pm = snap.get("provider_management", {})
    if pm.get("url"):
        out.append(Finding(
            id="router:provider-management", source="fritz", kind="config", severity="info",
            title="Provider remote management (TR-069) configured",
            message=f"The cable provider manages the router via TR-069 (ACS {pm['url']}). Normal for cable "
                    "routers; you cannot switch it off on a provider-managed box.",
            action="No action; keep an eye on firmware updates rolled out by the provider.",
            state_key=[pm["url"]]))

    if snap.get("dslite"):
        out.append(Finding(
            id="router:ds-lite", source="fritz", kind="config", severity="info",
            title="Internet line uses DS-Lite (no own public IPv4)",
            message="The router's WAN address is IPv6; IPv4 goes through the provider's shared carrier-grade NAT. "
                    "Nothing in the LAN is reachable from the internet over IPv4 - exposure happens over IPv6 only "
                    "(router remote access, IPv6 sharings). The shared IPv4 is never scanned.",
            action="No action. Keep an eye on IPv6 sharings: they are the only way in.",
            state_key=[True]))

    # ---- firmware ---------------------------------------------------------------------------
    if dev.get("firmware"):
        upd = dev.get("update_available")
        out.append(Finding(
            id="router:firmware", source="fritz", kind="firmware", severity="high" if upd else "info",
            title=f"{dev.get('model') or 'FRITZ!Box'} firmware {dev['firmware']}"
                  + (f" - update {dev.get('update_version')} available" if upd else ""),
            message="FRITZ!OS version as reported by the router." + (" A newer version is available." if upd else ""),
            action="Install the update (FRITZ!Box > System > Update)." if upd else "No action.",
            state_key=[dev["firmware"], upd]))
    return out


def device_findings(devices: dict, known: dict) -> list[Finding]:
    """One finding per device that is not in the baseline/known list. Baseline handling (first run) is done by the
    engine; here every device yields an 'unknown device' finding unless listed in config known_devices."""
    out = []
    known_l = {k.lower(): v for k, v in (known or {}).items()}
    for mac, d in devices.items():
        if mac in known_l:
            continue
        who = label(devices, mac=mac)
        out.append(Finding(
            id=f"device:{mac}", source="inventory", kind="device", severity="critical",
            title=f"Unknown device in the LAN: {d.get('hostname') or d.get('vendor') or mac}",
            message=f"New device {who}, first seen {d.get('first_seen')}, seen by: {', '.join(d['sources'])}"
                    + (f", interface {d['interface']}" if d.get("interface") else "")
                    + (", guest network" if d.get("guest") else "")
                    + (". Randomised MAC (phone/tablet privacy address or VM)." if d.get("random_mac") else "."),
            action="Identify the device. If it is yours, acknowledge it (exposure-guard ack device:<mac> \"what it is\"). "
                   "If not: block it in FRITZ!Box > Home Network > Network (Block internet access / remove) and "
                   "change the Wi-Fi password.",
            detail={"mac": mac, "ips": d["ips"], "ipv6": d["ipv6"], "hostname": d["hostname"], "vendor": d["vendor"],
                    "first_seen": d.get("first_seen"), "sources": d["sources"]},
            state_key=[mac]))
    return out
