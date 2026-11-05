from datetime import timedelta

from exposure_guard import checks, lanweb, tailscale
from exposure_guard.tlscheck import assess
from exposure_guard.util import eui64_iid, mac_from_eui64, now, random_mac


def test_tls_assess():
    exp = (now() - timedelta(days=3)).isoformat()
    sev, issues, days = assess({"not_after": exp, "protocols": ["TLSv1.0", "TLSv1.2"], "self_signed": True}, 30)
    assert sev == "high" and any("EXPIRED" in i for i in issues) and any("outdated" in i for i in issues) and days < 0
    soon = (now() + timedelta(days=10)).isoformat()
    assert assess({"not_after": soon, "protocols": ["TLSv1.3"]}, 30)[0] == "medium"
    assert assess({"key_type": "rsa", "key_bits": 1024}, 30)[0] == "medium"


def test_page_facts_and_products():
    f = lanweb.page_facts(200, {"server": "lighttpd"}, b"<html><title>Tasmota</title><body>Tasmota 14</body></html>")
    assert f["title"] == "Tasmota" and not f["password_field"]
    assert lanweb.match_product(f)["name"] == "Tasmota"
    f = lanweb.page_facts(200, {}, b"<title>Grafana</title><input type='password'>")
    assert f["password_field"] and lanweb.match_product(f)["name"] == "Grafana"
    f = lanweb.page_facts(200, {}, b"<title>Tapo</title>tp-link")
    assert lanweb.match_product(f) is None or lanweb.match_product(f)["name"] != "TP-Link router/access point/extender"


def test_endpoint_findings():
    ep = {"ip": "192.168.10.50", "port": 80, "scheme": "http", "tls": None, "redirects_to_https": False,
          "facts": {"title": "Tasmota", "server": "", "password_field": False, "status": 200},
          "product": lanweb.match_product({"title": "Tasmota", "body": "Tasmota", "server": ""})}
    fs = {f.id: f for f in lanweb.endpoint_findings(ep, {}, 30)}
    assert fs["lan:192.168.10.50:80:http"].severity == "low"
    assert "Unauthenticated" in fs["lan:192.168.10.50:80:product"].title
    ep2 = dict(ep, facts={"title": "Login", "server": "", "password_field": True, "status": 200}, product=None)
    assert lanweb.endpoint_findings(ep2, {}, 30)[0].severity == "medium"


def test_device_findings_and_known():
    devs = {"aa:bb:cc:00:00:01": {"mac": "aa:bb:cc:00:00:01", "ips": ["192.168.10.9"], "ipv6": [], "hostname": "x",
                                  "vendor": "V", "sources": ["fritz"], "random_mac": False, "first_seen": "t"}}
    assert checks.device_findings(devs, {})[0].severity == "critical"
    assert checks.device_findings(devs, {"AA:BB:CC:00:00:01": "known"}) == []


def test_tailscale_status_and_policy():
    st = {"Self": {"ID": "n1", "HostName": "pi", "OS": "linux", "TailscaleIPs": ["100.64.0.1"], "UserID": 1,
                   "KeyExpiry": (now() + timedelta(days=5)).isoformat(), "PrimaryRoutes": ["192.168.10.0/24"],
                   "ExitNodeOption": True},
          "Peer": {"k": {"ID": "n2", "HostName": "phone", "OS": "iOS", "TailscaleIPs": ["100.64.0.2"], "UserID": 1,
                         "Expired": True}},
          "User": {"1": {"LoginName": "user@example.com"}}}
    nodes = tailscale.nodes_from_status(st)
    fs = {f.id: f for f in tailscale.node_findings(nodes, 14)}
    assert fs["ts:n1:key"].severity == "medium" and fs["ts:n2:key"].severity == "high"
    assert "ts:n1:routes" in fs and "ts:n1:exit" in fs and fs["ts:n2:node"].severity == "critical"
    pol = {"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
           "nodeAttrs": [{"target": ["*"], "attr": ["funnel"]}], "ssh": [{"action": "accept", "users": ["root"], "src": ["*"]}]}
    ids = {f.id for f in tailscale.policy_findings(pol)}
    assert {"ts:acl:allow-all", "ts:acl:funnel:0", "ts:acl:ssh-root:0"} <= ids


def test_mac_helpers():
    assert random_mac("02:00:00:00:00:01") and not random_mac("00:1a:2b:00:00:01")
    a = "2001:db8::21a:2bff:fe3c:4d5e"
    assert eui64_iid(a) and mac_from_eui64(a) == "00:1a:2b:3c:4d:5e"
