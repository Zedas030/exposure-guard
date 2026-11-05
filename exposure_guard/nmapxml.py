"""Parse nmap XML output (-oX) into plain dicts, including ssl-cert / ssl-enum-ciphers script tables."""
from __future__ import annotations

import xml.etree.ElementTree as ET


def _table(el) -> dict:
    out: dict = {}
    for child in el:
        key = child.get("key")
        if child.tag == "elem":
            val = child.text or ""
            if key is None:
                out.setdefault("_list", []).append(val)
            else:
                out[key] = val
        elif child.tag == "table":
            sub = _table(child)
            if key is None:
                out.setdefault("_list", []).append(sub)
            else:
                out[key] = sub
    return out


def parse(xml_text: str) -> dict:
    root = ET.fromstring(xml_text)
    hosts = []
    for h in root.findall("host"):
        status = h.find("status")
        addrs = {a.get("addrtype"): a.get("addr") for a in h.findall("address")}
        addr = addrs.get("ipv4") or addrs.get("ipv6") or ""
        ports = []
        for p in h.findall("ports/port"):
            st = p.find("state")
            svc = p.find("service")
            scripts = {}
            for s in p.findall("script"):
                scripts[s.get("id")] = {"output": s.get("output", ""), "data": _table(s)}
            ports.append({
                "proto": p.get("protocol"), "port": int(p.get("portid")),
                "state": st.get("state") if st is not None else "",
                "reason": st.get("reason", "") if st is not None else "",
                "service": svc.get("name", "") if svc is not None else "",
                "product": svc.get("product", "") if svc is not None else "",
                "version": svc.get("version", "") if svc is not None else "",
                "extrainfo": svc.get("extrainfo", "") if svc is not None else "",
                "tunnel": svc.get("tunnel", "") if svc is not None else "",
                "scripts": scripts,
            })
        hosts.append({
            "addr": addr, "family": "v6" if "ipv6" in addrs else "v4",
            "status": status.get("state") if status is not None else "",
            "ports": ports,
            "timed_out": h.get("endtime") is None and status is None,
        })
    runstats = root.find("runstats/finished")
    return {
        "args": root.get("args", ""),
        "start": int(root.get("start") or 0),
        "end": int(runstats.get("time") or 0) if runstats is not None else 0,
        "exit": runstats.get("exit", "") if runstats is not None else "",
        "errormsg": runstats.get("errormsg", "") if runstats is not None else "",
        "hosts": hosts,
    }


def tls_info(port: dict) -> dict | None:
    """Condensed TLS facts from ssl-cert / ssl-enum-ciphers, or None if the port had no TLS scripts."""
    sc = port.get("scripts", {})
    cert = sc.get("ssl-cert", {}).get("data")
    enum = sc.get("ssl-enum-ciphers", {}).get("data")
    if not cert and not enum:
        return None
    info: dict = {}
    if cert:
        subj, issuer = cert.get("subject", {}), cert.get("issuer", {})
        validity, pubkey = cert.get("validity", {}), cert.get("pubkey", {})
        info.update({
            "subject": subj.get("commonName", ""), "issuer": issuer.get("commonName", "") or issuer.get("organizationName", ""),
            "self_signed": bool(subj) and subj == issuer,
            "not_after": validity.get("notAfter", ""), "not_before": validity.get("notBefore", ""),
            "key_type": pubkey.get("type", ""), "key_bits": int(pubkey.get("bits") or 0),
            "sig_algo": cert.get("sig_algo", ""),
            "san": (cert.get("extensions", {}) and _san(cert)) or "",
        })
    if enum:
        protos = [k for k in enum if k.startswith(("TLSv", "SSLv"))]
        info["protocols"] = sorted(protos)
        info["grade"] = enum.get("least strength", "")
        weak = []
        for proto in protos:
            for c in (enum[proto].get("ciphers", {}).get("_list", []) or []):
                if isinstance(c, dict) and c.get("strength", "A") not in ("A", "B"):
                    weak.append(f"{proto}:{c.get('name')}({c.get('strength')})")
        info["weak_ciphers"] = weak[:20]
    return info


def _san(cert: dict) -> str:
    for ext in (cert.get("extensions", {}).get("_list", []) or []):
        if isinstance(ext, dict) and ext.get("name") == "X509v3 Subject Alternative Name":
            return ext.get("value", "")
    return ""
