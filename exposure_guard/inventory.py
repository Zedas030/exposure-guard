"""LAN inventory, collected passively: FRITZ!Box host list, the host's ARP/NDP neighbour tables,
plus one ICMPv6 echo to the all-nodes multicast group to learn global IPv6 addresses (one packet per device)."""
from __future__ import annotations

import ipaddress
import os
import select
import socket
import struct
import subprocess
import time

from . import oui
from .util import eui64_iid, is_global, log, mac_from_eui64, norm_mac, random_mac


def read_arp(path: str = "/proc/net/arp") -> dict[str, str]:
    """ip -> mac from the kernel ARP table (only complete entries)."""
    out = {}
    try:
        with open(path) as fh:
            next(fh, None)
            for line in fh:
                parts = line.split()
                if len(parts) >= 4 and parts[2] != "0x0":
                    mac = norm_mac(parts[3])
                    if mac and mac != "00:00:00:00:00:00":
                        out[parts[0]] = mac
    except OSError:
        pass
    return out


def read_ndp() -> dict[str, str]:
    """global IPv6 -> mac from `ip -6 neigh`."""
    out = {}
    try:
        res = subprocess.run(["ip", "-6", "neigh", "show"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return out
    for line in res.stdout.splitlines():
        parts = line.split()
        if not parts or "lladdr" not in parts or "FAILED" in parts:
            continue
        addr, mac = parts[0], norm_mac(parts[parts.index("lladdr") + 1])
        if mac and is_global(addr):
            out[addr] = mac
    return out


def own_global_v6(interface: str) -> list[str]:
    try:
        res = subprocess.run(["ip", "-6", "-o", "addr", "show", "dev", interface, "scope", "global"],
                             capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return []
    addrs = []
    for line in res.stdout.splitlines():
        parts = line.split()
        if "inet6" in parts:
            a = parts[parts.index("inet6") + 1].split("/")[0]
            if is_global(a) and "temporary" not in parts and "deprecated" not in parts:
                addrs.append(a)
    return addrs


def multicast_echo(interface: str, source: str, wait: float = 3.0) -> set[str]:
    """Send ONE ICMPv6 echo request to ff02::1 from our global address and collect the global
    source addresses of the replies. Uses an unprivileged ICMP datagram socket."""
    found: set[str] = set()
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_ICMPV6)
    except OSError as exc:
        log.warning("ICMPv6 ping socket not available: %s", exc)
        return found
    try:
        ifindex = socket.if_nametoindex(interface)
        sock.bind((source, 0, 0, 0))
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, ifindex)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
        packet = struct.pack("!BBHHH", 128, 0, 0, 0, 1) + b"exposure-guard"
        sock.sendto(packet, ("ff02::1", 0, 0, ifindex))
        end = time.monotonic() + wait
        while (left := end - time.monotonic()) > 0:
            r, _, _ = select.select([sock], [], [], left)
            if not r:
                break
            data, addr = sock.recvfrom(2048)
            if data and data[0] == 129 and is_global(addr[0]):
                found.add(addr[0].split("%")[0])
    except OSError as exc:
        log.warning("IPv6 multicast echo failed: %s", exc)
    finally:
        sock.close()
    return found


def unicast_touch(addrs, interface: str) -> None:
    """One echo per address so the kernel resolves neighbours (gives us their MAC in `ip -6 neigh`)."""
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_ICMPV6)
    except OSError:
        return
    try:
        for a in addrs:
            try:
                sock.sendto(struct.pack("!BBHHH", 128, 0, 0, 0, 2) + b"eg", (a, 0, 0, 0))
            except OSError:
                pass
            time.sleep(0.05)
        time.sleep(1.0)
    finally:
        sock.close()


def collect(cfg, fritz_snapshot: dict | None, store) -> dict:
    """Merge all sources into {mac: device}. Records first-seen per MAC and per global IPv6 address."""
    inv = cfg["inventory"]
    net = ipaddress.ip_network(cfg["network"]["lan_cidr"], strict=False)
    devices: dict[str, dict] = {}

    def dev(mac: str) -> dict:
        d = devices.setdefault(mac, {"mac": mac, "ips": [], "ipv6": [], "hostname": "", "sources": [],
                                     "active": False, "interface": "", "guest": False})
        return d

    if inv["use_fritz_hosts"] and fritz_snapshot:
        for h in fritz_snapshot.get("hosts", []):
            d = dev(h["mac"])
            if h["ip"] and h["ip"] not in d["ips"]:
                d["ips"].append(h["ip"])
            d["hostname"] = d["hostname"] or h["hostname"]
            d["active"] = d["active"] or h["active"]
            d["interface"], d["guest"] = h["interface"], h["guest"]
            d["model"] = h.get("model", "")
            d["sources"].append("fritz")
    if inv["use_neighbors"]:
        for ip, mac in read_arp().items():
            try:
                if ipaddress.ip_address(ip) not in net:
                    continue
            except ValueError:
                continue
            d = dev(mac)
            if ip not in d["ips"]:
                d["ips"].append(ip)
            d["active"] = True
            if "arp" not in d["sources"]:
                d["sources"].append("arp")

    v6_found: dict[str, str] = {}
    if inv["ipv6_discovery"]:
        iface = cfg["network"]["interface"]
        own = own_global_v6(iface)
        replies: set[str] = set()
        if own:
            replies = multicast_echo(iface, own[0])
            unicast_touch(sorted(replies - set(own)), iface)
        ndp = read_ndp()
        for a in replies | set(ndp):
            mac = ndp.get(a) or mac_from_eui64(a)
            v6_found[a] = mac
        for a in own:
            v6_found[a] = "self"
    for addr, mac in v6_found.items():
        if mac and mac != "self":
            d = dev(mac)
            if addr not in d["ipv6"]:
                d["ipv6"].append(addr)
            if "ndp" not in d["sources"]:
                d["sources"].append("ndp")
        store.observe(f"v6:{addr}", "ipv6", {"mac": mac, "stable": eui64_iid(addr) or mac == "self"})

    for mac, d in devices.items():
        d["vendor"] = oui.vendor(mac)
        d["random_mac"] = random_mac(mac)
        d["first_seen"] = store.observe(f"dev:{mac}", "device", {k: d[k] for k in ("ips", "hostname", "vendor")})
    return {"devices": devices, "ipv6": v6_found}


def ipv6_targets(cfg, store, now_ts: float) -> list[dict]:
    """Global IPv6 addresses seen in the LAN recently -> targets for the external probe."""
    from .util import parse_iso
    keep = cfg["inventory"]["ipv6_keep_hours"] * 3600
    out = []
    for o in store.observations("ipv6"):
        last = parse_iso(o["last_seen"])
        if not last or now_ts - last.timestamp() > keep:
            continue
        addr = o["key"][3:]
        first = parse_iso(o["first_seen"])
        stable = bool(o["data"].get("stable")) or (first and now_ts - first.timestamp() > 7 * 86400)
        out.append({"addr": addr, "mac": o["data"].get("mac", ""), "stable": bool(stable)})
    out.sort(key=lambda t: (not t["stable"], t["addr"]))
    return out[: cfg["inventory"]["max_ipv6_targets"]]


def label(devices: dict, ip: str = "", mac: str = "") -> str:
    """'192.0.2.45 (hostname, Vendor)' for alert texts."""
    d = devices.get(mac) if mac else None
    if not d and ip:
        d = next((x for x in devices.values() if ip in x["ips"] or ip in x["ipv6"]), None)
    if not d:
        return ip or mac or "unknown device"
    bits = [b for b in (d.get("hostname"), d.get("vendor")) if b]
    who = ip or (d["ips"][0] if d["ips"] else d["mac"])
    return f"{who} ({', '.join(bits)}, MAC {d['mac']})" if bits else f"{who} (MAC {d['mac']})"


def env_hostname() -> str:
    return os.environ.get("HOSTNAME", "")
