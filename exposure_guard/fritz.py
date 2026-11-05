"""FRITZ!Box: read-only TR-064 (authenticated) and UPnP IGD (unauthenticated) queries.

Only Get* actions are ever sent. The tool never changes router settings."""
from __future__ import annotations

import html
import re
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

from .util import norm_mac

SOAP = ('<?xml version="1.0" encoding="utf-8"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:{action} xmlns:u="{st}">{args}'
        '</u:{action}></s:Body></s:Envelope>')

ALLOWED_PREFIXES = ("Get", "X_AVM-DE_Get", "X_GetHostListPath")


class FritzError(Exception):
    pass


class SoapFault(FritzError):
    def __init__(self, code: str, desc: str):
        super().__init__(f"UPnP error {code}: {desc}")
        self.code = code


def _parse_services(desc_xml: str) -> dict[str, str]:
    """serviceType -> controlURL from a device description."""
    out = {}
    for m in re.finditer(r"<service>(.*?)</service>", desc_xml, re.S):
        block = m.group(1)
        st = re.search(r"<serviceType>([^<]+)</serviceType>", block)
        cu = re.search(r"<controlURL>([^<]+)</controlURL>", block)
        if st and cu:
            out[st.group(1).strip()] = cu.group(1).strip()
    return out


def _parse_response(body: str) -> dict[str, str]:
    fault = re.search(r"<errorCode>(\d+)</errorCode>.*?<errorDescription>([^<]*)</errorDescription>", body, re.S)
    if fault:
        raise SoapFault(fault.group(1), fault.group(2))
    return {k: html.unescape(v) for k, v in re.findall(r"<(New[A-Za-z0-9_\-]+)>([^<]*)</\1>", body)}


class _Soap:
    def __init__(self, base: str, desc_path: str, timeout: float, opener=None):
        self.base, self.timeout = base.rstrip("/"), timeout
        self.opener = opener or urllib.request.build_opener()
        with self.opener.open(self.base + desc_path, timeout=timeout) as r:
            self.services = _parse_services(r.read(2_000_000).decode("utf-8", "replace"))

    def find(self, short: str) -> str | None:
        for st in self.services:
            if st.split(":service:")[-1] == short:
                return st
        return None

    def has(self, short: str) -> bool:
        return self.find(short) is not None

    def call(self, short: str, action: str, **args) -> dict[str, str]:
        if not action.startswith(ALLOWED_PREFIXES):
            raise FritzError(f"refusing non-read action {action}")  # hard guard: read-only tool
        st = self.find(short)
        if not st:
            raise FritzError(f"service {short} not offered")
        body = SOAP.format(action=action, st=st, args="".join(f"<{k}>{html.escape(str(v))}</{k}>" for k, v in args.items()))
        req = urllib.request.Request(self.base + self.services[st], data=body.encode(),
                                     headers={"Content-Type": 'text/xml; charset="utf-8"', "SOAPAction": f'"{st}#{action}"'})
        try:
            with self.opener.open(req, timeout=self.timeout) as r:
                return _parse_response(r.read(3_000_000).decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            text = exc.read(200_000).decode("utf-8", "replace") if exc.fp else ""
            if exc.code == 500 and "errorCode" in text:
                return _parse_response(text)
            if exc.code == 401:
                raise FritzError("TR-064 login rejected (check FRITZ_USER/FRITZ_PASSWORD and the user's rights)") from exc
            raise FritzError(f"HTTP {exc.code} for {short}#{action}") from exc

    def get(self, path: str) -> str:
        with self.opener.open(self.base + path, timeout=self.timeout) as r:
            return r.read(5_000_000).decode("utf-8", "replace")


class TR064(_Soap):
    def __init__(self, host: str, port: int, user: str, password: str, timeout: float = 10):
        base = f"http://{host}:{port}"
        pm = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        pm.add_password(None, base, user, password)
        opener = urllib.request.build_opener(urllib.request.HTTPDigestAuthHandler(pm))
        super().__init__(base, "/tr64desc.xml", timeout, opener)
        self.prefix = "urn:dslforum-org:service:"


class IGD(_Soap):
    """UPnP Internet Gateway Device - what devices themselves see and use to open ports. No login."""

    def __init__(self, host: str, port: int, timeout: float = 10):
        last = None
        for desc in ("/igd2desc.xml", "/igddesc.xml"):
            try:
                super().__init__(f"http://{host}:{port}", desc, timeout)
                if self.services:
                    return
            except (urllib.error.URLError, OSError) as exc:
                last = exc
        raise FritzError(f"UPnP IGD description not reachable ({last})")

    def wan_service(self) -> str | None:
        for short in ("WANIPConnection:2", "WANIPConnection:1", "WANPPPConnection:1"):
            if self.has(short):
                return short
        return None


# ----------------------------------------------------------------------------------- collection
def _mappings(soap: _Soap, service: str, limit: int = 256) -> list[dict]:
    out = []
    count = None
    try:
        count = int(soap.call(service, "GetPortMappingNumberOfEntries").get("NewPortMappingNumberOfEntries") or 0)
    except (SoapFault, FritzError, ValueError):
        count = None  # IGD has no count action -> iterate until error 713 (SpecifiedArrayIndexInvalid)
    for i in range(min(count, limit) if count is not None else limit):
        try:
            m = soap.call(service, "GetGenericPortMappingEntry", NewPortMappingIndex=i)
        except SoapFault as exc:
            if exc.code in ("713", "714", "402"):
                break
            raise
        out.append({
            "protocol": (m.get("NewProtocol") or "").upper(),
            "external_port": int(m.get("NewExternalPort") or 0),
            "remote_host": m.get("NewRemoteHost") or "",
            "internal_client": m.get("NewInternalClient") or "",
            "internal_port": int(m.get("NewInternalPort") or 0),
            "enabled": (m.get("NewEnabled") or "1") in ("1", "true"),
            "description": m.get("NewPortMappingDescription") or "",
            "lease": int(m.get("NewLeaseDuration") or 0),
        })
    return out


def parse_host_list(xml_text: str) -> list[dict]:
    hosts = []
    root = ET.fromstring(xml_text)
    for item in root.iter("Item"):
        get = lambda tag: (item.findtext(tag) or "").strip()  # noqa: E731
        mac = norm_mac(get("MACAddress"))
        if not mac:
            continue
        hosts.append({
            "mac": mac, "ip": get("IPAddress"), "hostname": get("HostName"),
            "active": get("Active") == "1", "interface": get("InterfaceType"),
            "guest": get("X_AVM-DE_Guest") == "1", "vpn": get("X_AVM-DE_VPN") == "1",
            "model": get("X_AVM-DE_Model"), "friendly_name": get("X_AVM-DE_FriendlyName"),
            "wan_access": get("X_AVM-DE_WANAccess"),
        })
    return hosts


def collect(cfg) -> dict:
    """Read everything the checks need. Raises FritzError if the authenticated part fails."""
    fb = cfg["fritzbox"]
    snap: dict = {"errors": []}
    user, pw = cfg.secret("fritzbox", "user_env"), cfg.secret("fritzbox", "password_env")
    if not user or not pw:
        raise FritzError("FRITZ_USER / FRITZ_PASSWORD missing in .env")
    tr = TR064(fb["host"], fb["port"], user, pw, fb["timeout"])

    def safe(short, action, **kw):
        if not tr.has(short):
            return None
        try:
            return tr.call(short, action, **kw)
        except SoapFault as exc:
            snap["errors"].append(f"{short}#{action}: {exc}")
            return None

    info = tr.call("DeviceInfo:1", "GetInfo")  # also proves the login works
    snap["device"] = {"model": info.get("NewModelName", ""), "firmware": info.get("NewSoftwareVersion", ""),
                      "uptime": int(info.get("NewUpTime") or 0)}
    ui = safe("UserInterface:1", "GetInfo") or {}
    snap["device"]["update_available"] = ui.get("NewUpgradeAvailable") == "1"
    snap["device"]["update_version"] = ui.get("NewX_AVM-DE_Version", "")

    # public addresses
    wan = "WANIPConnection:1" if tr.has("WANIPConnection:1") else "WANPPPConnection:1"
    ext = safe(wan, "GetExternalIPAddress") or {}
    wan_info = safe(wan, "GetInfo") or {}
    snap["router_mac"] = norm_mac(wan_info.get("NewMACAddress", ""))
    v6 = safe(wan, "X_AVM-DE_GetExternalIPv6Address") or {}
    snap["ipv6"] = v6.get("NewExternalIPv6Address", "")
    external_addr = ext.get("NewExternalIPAddress", "")
    snap["dslite"] = ":" in external_addr
    if snap["dslite"]:
        # DS-Lite (common on cable): the WAN address is IPv6; the public IPv4 is shared via the provider's
        # AFTR (carrier-grade NAT) - not ours, never a scan target, and unreachable from the internet.
        snap["ipv4"] = ""
        snap["ipv6"] = snap["ipv6"] or external_addr
    else:
        snap["ipv4"] = external_addr
    pfx = safe(wan, "X_AVM-DE_GetIPv6Prefix") or {}
    snap["ipv6_prefix"] = (f"{pfx.get('NewIPv6Prefix')}/{pfx.get('NewPrefixLength')}"
                           if pfx.get("NewIPv6Prefix") else "")

    # remote access / MyFRITZ / provider management
    ra = safe("X_AVM-DE_RemoteAccess:1", "GetInfo") or {}
    snap["remote_access"] = {"enabled": ra.get("NewEnabled") == "1", "port": ra.get("NewPort", ""),
                             "letsencrypt": ra.get("NewLetsEncryptEnabled") == "1",
                             "letsencrypt_state": ra.get("NewLetsEncryptState", "")}
    mf = safe("X_AVM-DE_MyFritz:1", "GetInfo") or {}
    snap["myfritz"] = {"enabled": mf.get("NewEnabled") == "1", "state": mf.get("NewDeviceRegistered", "") or
                       mf.get("NewState", ""), "dyndns": bool(mf.get("NewDynDNSName"))}
    services = []
    n = int((safe("X_AVM-DE_MyFritz:1", "GetNumberOfServices") or {}).get("NewNumberOfServices") or 0)
    for i in range(min(n, 64)):
        s = safe("X_AVM-DE_MyFritz:1", "GetServiceByIndex", NewIndex=i) or {}
        if s:
            services.append({"name": s.get("NewName", ""), "enabled": s.get("NewEnabled") == "1",
                             "scheme": s.get("NewScheme", ""), "port": s.get("NewPort", ""),
                             "url_path": s.get("NewURLPath", ""), "ipv4": s.get("NewIPv4Address", ""),
                             "ipv6": s.get("NewIPv6Address", ""), "ipv6_iid": s.get("NewIPv6InterfaceID", ""),
                             "mac": norm_mac(s.get("NewMACAddress", "")), "host": s.get("NewHostName", ""),
                             "status": s.get("NewStatus", "")})
    snap["myfritz_services"] = services
    ms = safe("ManagementServer:1", "GetInfo") or {}
    snap["provider_management"] = {"url": ms.get("NewURL", ""), "periodic_inform": ms.get("NewPeriodicInformEnable") == "1"}
    up = safe("X_AVM-DE_UPnP:1", "GetInfo") or {}
    snap["upnp"] = {"enabled": up.get("NewEnable") == "1", "media_server": up.get("NewUPnPMediaServer") == "1"}

    # port mappings: TR-064 (authenticated) list and UPnP IGD list, compared to tell manual from UPnP
    tr_maps = []
    for svc in ("WANIPConnection:1", "WANPPPConnection:1"):
        if tr.has(svc):
            try:
                tr_maps += _mappings(tr, svc)
            except FritzError as exc:
                snap["errors"].append(f"{svc} mappings: {exc}")
    igd_maps, igd_ok = [], False
    try:
        igd = IGD(fb["host"], fb["port"], fb["timeout"])
        svc = igd.wan_service()
        if svc:
            igd_maps, igd_ok = _mappings(igd, svc), True
    except (FritzError, OSError) as exc:
        snap["errors"].append(f"UPnP IGD: {exc}")
    snap["igd_ok"] = igd_ok
    snap["port_mappings"] = classify_mappings(tr_maps, igd_maps)

    # host list (device inventory)
    snap["hosts"] = []
    try:
        path = tr.call("Hosts:1", "X_AVM-DE_GetHostListPath").get("NewX_AVM-DE_HostListPath", "")
        if path:
            snap["hosts"] = parse_host_list(tr.get(path))
    except (FritzError, ET.ParseError, OSError) as exc:
        snap["errors"].append(f"host list: {exc}")
        snap["hosts_error"] = str(exc)
    return snap


def classify_mappings(tr_maps: list[dict], igd_maps: list[dict]) -> list[dict]:
    """UPnP-created mappings are visible through the IGD service; everything only in TR-064 is manual."""
    key = lambda m: (m["protocol"], m["external_port"], m["internal_client"], m["internal_port"])  # noqa: E731
    upnp_keys = {key(m) for m in igd_maps}
    out, seen = [], set()
    for m in igd_maps:
        k = key(m)
        if k in seen:
            continue
        seen.add(k)
        out.append(dict(m, origin="upnp"))
    for m in tr_maps:
        k = key(m)
        if k in seen:
            continue
        seen.add(k)
        out.append(dict(m, origin="upnp" if k in upnp_keys else "manual"))
    return sorted(out, key=lambda m: (m["protocol"], m["external_port"]))
