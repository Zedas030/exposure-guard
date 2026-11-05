"""TLS assessment. External ports come with nmap ssl-cert/ssl-enum-ciphers data; LAN ports are checked here
with at most three gentle handshakes (normal, TLS 1.0-only, TLS 1.1-only) - no cipher enumeration against IoT."""
from __future__ import annotations

import re
import socket
import ssl
from datetime import datetime, timezone

from .findings import SEV_RANK, Finding
from .util import now

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
except ImportError:  # pragma: no cover - cryptography is a hard dependency in the image
    x509 = None


def _ctx(min_v=None, max_v=None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    if min_v:
        ctx.minimum_version = min_v
    if max_v:
        ctx.maximum_version = max_v
    return ctx


def handshake(host: str, port: int, timeout: float = 5, min_v=None, max_v=None):
    """Returns (protocol, cipher, der_cert) or raises OSError/ssl.SSLError."""
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with _ctx(min_v, max_v).wrap_socket(raw, server_hostname=None) as s:
            return s.version(), s.cipher(), s.getpeercert(binary_form=True)


def lan_tls_info(host: str, port: int, timeout: float = 5) -> dict | None:
    try:
        proto, cipher, der = handshake(host, port, timeout)
    except (OSError, ssl.SSLError, ValueError):
        return None
    info: dict = {"protocols": [proto] if proto else [], "cipher": cipher[0] if cipher else ""}
    if der and x509:
        try:
            cert = x509.load_der_x509_certificate(der)
            subj = cert.subject.rfc4514_string()
            iss = cert.issuer.rfc4514_string()
            cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            icn = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            pub = cert.public_key()
            info.update({
                "subject": cn[0].value if cn else subj, "issuer": icn[0].value if icn else iss,
                "self_signed": subj == iss,
                "not_after": cert.not_valid_after_utc.isoformat(), "not_before": cert.not_valid_before_utc.isoformat(),
                "key_type": "rsa" if isinstance(pub, rsa.RSAPublicKey) else "ec" if isinstance(pub, ec.EllipticCurvePublicKey) else type(pub).__name__,
                "key_bits": getattr(pub, "key_size", 0),
                "sig_algo": cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "",
            })
        except Exception:  # noqa: BLE001 - malformed IoT certs must not break the run
            pass
    for name, ver in (("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)):
        try:
            got, _, _ = handshake(host, port, timeout, ver, ver)
            if got and got not in info["protocols"]:
                info["protocols"].append(got)
        except (OSError, ssl.SSLError, ValueError):
            pass
    return info


def _parse_time(value: str) -> datetime | None:
    if not value:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S"):
        try:
            dt = datetime.strptime(value.replace("+00:00", "+0000"), fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        dt = datetime.fromisoformat(value)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def assess(info: dict, warn_days: int) -> tuple[str, list[str], float | None]:
    """-> (severity, issues, days_left)."""
    issues: list[tuple[str, str]] = []
    days = None
    na = _parse_time(info.get("not_after", ""))
    if na:
        days = (na - now()).total_seconds() / 86400
        if days < 0:
            issues.append(("high", f"certificate EXPIRED {-days:.0f} days ago ({na:%Y-%m-%d})"))
        elif days < warn_days:
            issues.append(("medium", f"certificate expires in {days:.0f} days ({na:%Y-%m-%d})"))
    old = [p for p in info.get("protocols", []) if p in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1")]
    if old:
        issues.append(("medium", f"outdated protocol(s) accepted: {', '.join(sorted(set(old)))}"))
    if info.get("weak_ciphers"):
        issues.append(("medium", f"weak cipher suites: {', '.join(info['weak_ciphers'][:4])}"))
    grade = info.get("grade", "")
    if grade and grade not in ("A", "B") and not info.get("weak_ciphers"):
        issues.append(("medium", f"nmap cipher grade {grade}"))
    if info.get("key_type") == "rsa" and 0 < info.get("key_bits", 0) < 2048:
        issues.append(("medium", f"RSA key only {info['key_bits']} bit"))
    if "sha1" in info.get("sig_algo", "").lower() or "md5" in info.get("sig_algo", "").lower():
        issues.append(("medium", f"weak certificate signature {info['sig_algo']}"))
    if info.get("self_signed"):
        issues.append(("low", "self-signed certificate (clients cannot verify the server)"))
    if not issues:
        return "info", [], days
    sev = min((s for s, _ in issues), key=lambda s: SEV_RANK[s])
    return sev, [t for _, t in issues], days


def tls_finding(fid: str, source: str, where: str, info: dict, warn_days: int, external: bool) -> Finding:
    sev, issues, days = assess(info, warn_days)
    facts = (f"subject '{info.get('subject', '?')}', issuer '{info.get('issuer', '?')}', valid until "
             f"{info.get('not_after', '?')[:10]}, key {info.get('key_type', '?')} {info.get('key_bits') or '?'} bit, "
             f"protocols {', '.join(info.get('protocols', [])) or '?'}")
    if issues:
        msg = f"TLS on {where}: " + "; ".join(issues) + f". ({facts})"
        action = ("Renew/replace the certificate (e.g. Let's Encrypt), disable TLS 1.0/1.1 and weak ciphers in the "
                  "service or device settings; update the firmware if the device offers no such options.")
    else:
        msg, action = f"TLS on {where} looks fine ({facts}).", "No action."
    return Finding(id=fid, source=source, kind="tls", severity=sev,
                   title=f"TLS {where}: " + (issues[0] if issues else "ok"),
                   message=msg, action=action,
                   detail=dict(info, days_left=round(days, 1) if days is not None else None, external=external),
                   state_key=[sev, sorted(re.sub(r"[\d\-]+", "#", i.split(" (")[0]) for i in issues)])
