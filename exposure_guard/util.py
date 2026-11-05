"""Small helpers shared by all modules (time, hashing, JSON, logging)."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import re
import tempfile
from datetime import datetime, timezone

log = logging.getLogger("exposure_guard")


def setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def now() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime | None = None) -> str:
    return (dt or now()).astimezone(timezone.utc).isoformat(timespec="seconds")


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def ts(dt: datetime | None) -> float:
    return dt.timestamp() if dt else 0.0


def short_hash(*parts) -> str:
    """Stable 12-hex-digit hash over JSON-serialised parts (used as state fingerprint)."""
    raw = json.dumps(parts, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


def atomic_write(path: str, data: str | bytes, mode: int = 0o644) -> None:
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data.encode() if isinstance(data, str) else data)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")


def norm_mac(mac: str | None) -> str:
    mac = (mac or "").strip().lower().replace("-", ":")
    return mac if MAC_RE.match(mac) else ""


def random_mac(mac: str) -> bool:
    """Locally administered bit set -> randomised / private MAC (phones, VMs, containers)."""
    mac = norm_mac(mac)
    return bool(mac) and bool(int(mac[:2], 16) & 0x02)


def ip_family(addr: str) -> str:
    try:
        return "v6" if ipaddress.ip_address(addr.split("%")[0]).version == 6 else "v4"
    except ValueError:
        return ""


def is_global(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr.split("%")[0]).is_global
    except ValueError:
        return False


def eui64_iid(addr: str) -> bool:
    """True if the IPv6 interface identifier is EUI-64 derived (contains ff:fe) - a stable address."""
    try:
        packed = ipaddress.IPv6Address(addr.split("%")[0]).packed
    except ValueError:
        return False
    return packed[11] == 0xFF and packed[12] == 0xFE


def mac_from_eui64(addr: str) -> str:
    if not eui64_iid(addr):
        return ""
    p = ipaddress.IPv6Address(addr.split("%")[0]).packed[8:]
    b = bytes([p[0] ^ 0x02, p[1], p[2], p[5], p[6], p[7]])
    return ":".join(f"{x:02x}" for x in b)


def human_age(seconds: float) -> str:
    seconds = int(max(0, seconds))
    if seconds < 90:
        return f"{seconds} s"
    if seconds < 5400:
        return f"{seconds // 60} min"
    if seconds < 172800:
        return f"{seconds / 3600:.1f} h"
    return f"{seconds / 86400:.1f} d"
