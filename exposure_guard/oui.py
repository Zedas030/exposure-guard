"""MAC vendor lookup from the IEEE registry shipped by Debian's ieee-data package (offline)."""
from __future__ import annotations

import csv
import functools
import os

from .util import norm_mac, random_mac

PATHS = ["/usr/share/ieee-data/oui.csv", "/usr/share/ieee-data/mam.csv", "/usr/share/ieee-data/oui36.csv"]
EXTRA = os.environ.get("EXPOSURE_GUARD_OUI", "")


@functools.lru_cache(maxsize=1)
def _table() -> dict[str, str]:
    table: dict[str, str] = {}
    for path in [p for p in PATHS + ([EXTRA] if EXTRA else []) if p and os.path.exists(p)]:
        try:
            with open(path, encoding="utf-8", errors="replace", newline="") as fh:
                for row in csv.reader(fh):
                    if len(row) >= 3 and row[0] != "Registry":
                        table[row[1].strip().upper()] = row[2].strip()
        except OSError:
            continue
    return table


def vendor(mac: str) -> str:
    mac = norm_mac(mac)
    if not mac:
        return ""
    if random_mac(mac):
        return "(randomised MAC)"
    hexmac = mac.replace(":", "").upper()
    t = _table()
    for n in (9, 7, 6):  # MA-S (36 bit), MA-M (28 bit), MA-L (24 bit)
        v = t.get(hexmac[:n])
        if v:
            return v
    return ""
