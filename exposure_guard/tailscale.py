"""Tailscale: nodes, key expiry, exit nodes and subnet routes from the local tailscaled (LocalAPI, read-only),
plus ACL/policy and device checks via the Tailscale API if a read-only OAuth client is configured."""
from __future__ import annotations

import http.client
import json
import socket
import urllib.parse
import urllib.request
from datetime import timedelta

from .findings import Finding
from .util import now, parse_iso


class _UnixConn(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float = 10):
        super().__init__("local-tailscaled.sock", timeout=timeout)
        self.path_ = path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self.path_)
        self.sock = s


def local_status(sock_path: str) -> dict:
    conn = _UnixConn(sock_path)
    try:
        conn.request("GET", "/localapi/v0/status", headers={"Host": "local-tailscaled.sock"})
        r = conn.getresponse()
        body = r.read()
        if r.status != 200:
            raise RuntimeError(f"tailscaled LocalAPI HTTP {r.status}: {body[:200]!r}")
        return json.loads(body)
    finally:
        conn.close()


def nodes_from_status(st: dict) -> list[dict]:
    users = {str(k): v for k, v in (st.get("User") or {}).items()}
    out = []
    for is_self, n in [(True, st.get("Self") or {})] + [(False, p) for p in (st.get("Peer") or {}).values()]:
        if not n:
            continue
        u = users.get(str(n.get("UserID")), {})
        out.append({
            "id": n.get("ID") or n.get("PublicKey", "")[:24], "host": n.get("HostName", ""),
            "dns": (n.get("DNSName") or "").rstrip("."), "os": n.get("OS", ""), "ips": n.get("TailscaleIPs") or [],
            "self": is_self, "online": bool(n.get("Online")), "key_expiry": n.get("KeyExpiry") or "",
            "expired": bool(n.get("Expired")), "exit_node_option": bool(n.get("ExitNodeOption")),
            "exit_node_in_use": bool(n.get("ExitNode")), "routes": [r for r in (n.get("PrimaryRoutes") or [])],
            "tags": n.get("Tags") or [], "user": u.get("LoginName", ""), "last_seen": n.get("LastSeen", ""),
            "shared_in": bool(n.get("ShareeNode")),
        })
    return out


def node_findings(nodes: list[dict], warn_days: int) -> list[Finding]:
    out = []
    for n in nodes:
        name = n["host"] or n["dns"] or n["id"]
        base = f"ts:{n['id']}"
        out.append(Finding(
            id=f"{base}:node", source="tailscale", kind="tailnet_device", severity="critical",
            title=f"Device in the tailnet: {name} ({n['os']})",
            message=f"Tailnet node {name} ({', '.join(n['ips'])}, user {n['user'] or '-'}"
                    + (", shared in from another tailnet" if n["shared_in"] else "") + ").",
            action="If you do not know this node: remove it in the Tailscale admin console (Machines) and rotate "
                   "auth keys; otherwise acknowledge it.",
            detail=n, state_key=[n["id"]]))
        exp = parse_iso(n["key_expiry"])
        if n["expired"] or (exp and exp < now()):
            out.append(Finding(id=f"{base}:key", source="tailscale", kind="tailnet_key", severity="high",
                               title=f"Tailscale key of {name} has EXPIRED",
                               message=f"Node {name} can no longer connect until it is re-authenticated.",
                               action="Re-authenticate the node (tailscale up / log in again).", detail=n,
                               state_key=["expired"]))
        elif exp and exp - now() < timedelta(days=warn_days):
            out.append(Finding(id=f"{base}:key", source="tailscale", kind="tailnet_key", severity="medium",
                               title=f"Tailscale key of {name} expires {exp:%Y-%m-%d}",
                               message=f"Node key expires in {(exp - now()).days} days; afterwards remote access via this node stops.",
                               action="Re-authenticate before it expires, or disable key expiry for this server node "
                                      "in the admin console if it is a trusted always-on device.",
                               detail=n, state_key=["expiring"]))
        elif not exp and n["self"]:
            out.append(Finding(id=f"{base}:key", source="tailscale", kind="tailnet_key", severity="low",
                               title=f"Key expiry disabled for {name}",
                               message="This node never has to re-authenticate. Fine for a trusted server; a stolen node key stays valid.",
                               action="Keep only for always-on servers you control.", detail=n, state_key=["disabled"]))
        if n["exit_node_option"]:
            out.append(Finding(id=f"{base}:exit", source="tailscale", kind="tailnet_routing", severity="info",
                               title=f"{name} offers itself as exit node",
                               message="Other tailnet members can route their internet traffic through this node.",
                               action="Fine if intended; otherwise stop advertising (tailscale set --advertise-exit-node=false).",
                               detail=n, state_key=[True]))
        if n["routes"]:
            out.append(Finding(id=f"{base}:routes", source="tailscale", kind="tailnet_routing", severity="low",
                               title=f"{name} routes subnets into the tailnet: {', '.join(n['routes'])}",
                               message="Tailnet members (subject to ACLs) can reach these networks through this node.",
                               action="Restrict access to the routes with ACLs to the users/devices that need them.",
                               detail=n, state_key=sorted(n["routes"])))
        if n["self"] and n["exit_node_in_use"]:
            out.append(Finding(id=f"{base}:using-exit", source="tailscale", kind="tailnet_routing", severity="info",
                               title=f"{name} sends its traffic through an exit node",
                               message="Internet traffic of this node leaves via another tailnet node.",
                               action="Fine if intended.", detail=n, state_key=[True]))
    return out


# ------------------------------------------------------------------------------------- API
class TailscaleAPI:
    def __init__(self, cfg):
        ts = cfg["tailscale"]
        self.base = ts["api_url"].rstrip("/")
        self.tailnet = urllib.parse.quote(ts["tailnet"] or "-")
        self.client_id = cfg.secret("tailscale", "client_id_env")
        self.client_secret = cfg.secret("tailscale", "client_secret_env")
        self.api_key = cfg.secret("tailscale", "api_key_env")
        self._token = None

    @property
    def configured(self) -> bool:
        return bool((self.client_id and self.client_secret) or self.api_key)

    def token(self) -> str:
        if self.api_key:
            return self.api_key
        if self._token:
            return self._token
        data = urllib.parse.urlencode({"client_id": self.client_id, "client_secret": self.client_secret,
                                       "grant_type": "client_credentials"}).encode()
        with urllib.request.urlopen(urllib.request.Request(self.base + "/api/v2/oauth/token", data=data), timeout=20) as r:
            self._token = json.loads(r.read())["access_token"]
        return self._token

    def get(self, path: str):
        req = urllib.request.Request(self.base + path, headers={"Authorization": f"Bearer {self.token()}",
                                                                 "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read())

    def policy(self) -> dict:
        return self.get(f"/api/v2/tailnet/{self.tailnet}/acl")

    def devices(self) -> list[dict]:
        return self.get(f"/api/v2/tailnet/{self.tailnet}/devices?fields=all").get("devices", [])


def _has(values, *wanted) -> bool:
    return any(v in wanted for v in (values or []))


def policy_findings(pol: dict) -> list[Finding]:
    out = []
    allow_all = False
    for rule in pol.get("acls") or []:
        if rule.get("action", "accept") == "accept" and _has(rule.get("src"), "*") and _has(rule.get("dst"), "*:*"):
            allow_all = True
    for g in pol.get("grants") or []:
        if _has(g.get("src"), "*") and _has(g.get("dst"), "*") and _has(g.get("ip"), "*"):
            allow_all = True
    if allow_all:
        out.append(Finding(
            id="ts:acl:allow-all", source="tailscale", kind="tailnet_acl", severity="medium",
            title="Tailnet policy allows every device to reach every port of every other device",
            message="The ACL contains the default allow-all rule (src '*' -> dst '*:*'). A compromised phone or a "
                    "shared-in device can reach every service on the Pi.",
            action="Replace it with explicit rules, e.g. your user -> tag:server:22,8123,8090-8103 and nothing else.",
            state_key=[True]))
    for i, rule in enumerate(pol.get("ssh") or []):
        if rule.get("action") == "accept" and _has(rule.get("users"), "root"):
            out.append(Finding(
                id=f"ts:acl:ssh-root:{i}", source="tailscale", kind="tailnet_acl", severity="low",
                title="Tailscale SSH allows root without re-authentication",
                message=f"SSH rule {i}: action 'accept' for user root (src {rule.get('src')}).",
                action="Use action 'check' (periodic re-authentication) for root access.", state_key=[rule]))
    for i, na in enumerate(pol.get("nodeAttrs") or []):
        if "funnel" in (na.get("attr") or []):
            out.append(Finding(
                id=f"ts:acl:funnel:{i}", source="tailscale", kind="tailnet_acl", severity="medium",
                title="Tailscale Funnel is permitted",
                message=f"nodeAttrs entry {i} grants 'funnel' to {na.get('target')}: those nodes may publish services "
                        "to the public internet through Tailscale - outside the router's control.",
                action="Remove the funnel attribute unless you publish something on purpose.", state_key=[na]))
    aa = pol.get("autoApprovers") or {}
    if aa.get("exitNode") or aa.get("routes"):
        out.append(Finding(
            id="ts:acl:auto-approvers", source="tailscale", kind="tailnet_acl", severity="info",
            title="Auto-approvers for routes/exit nodes configured",
            message=f"autoApprovers: {json.dumps(aa)[:300]}",
            action="Make sure only trusted tags/users are listed.", state_key=[aa]))
    return out


def device_api_findings(devices: list[dict]) -> list[Finding]:
    out = []
    for d in devices:
        name = d.get("hostname") or d.get("name") or d.get("id")
        if d.get("updateAvailable"):
            out.append(Finding(id=f"ts:{d.get('nodeId') or d.get('id')}:update", source="tailscale",
                               kind="tailnet_update", severity="low",
                               title=f"Tailscale update available on {name} ({d.get('clientVersion', '?')})",
                               message="A newer Tailscale client is available for this node.",
                               action="Update the Tailscale client on this device.", detail={"device": name},
                               state_key=[d.get("clientVersion")]))
        if d.get("isExternal"):
            out.append(Finding(id=f"ts:{d.get('nodeId') or d.get('id')}:external", source="tailscale",
                               kind="tailnet_device", severity="low",
                               title=f"{name} is shared in from another tailnet",
                               message="A device of another tailnet is visible in yours.",
                               action="Remove the share if no longer needed.", detail={"device": name},
                               state_key=[True]))
    return out
