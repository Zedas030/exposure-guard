import base64
import os
import zlib

from exposure_guard import external, nmapxml
from exposure_guard.config import from_dict
from exposure_guard.tlscheck import assess

XML = open(os.path.join(os.path.dirname(__file__), "fixtures", "nmap_ext.xml")).read()


def result(xml=XML, rc=0, targets=None, ok=True):
    return {"run_id": "20261105T050000Z-daily", "profile": "daily", "ok": ok, "errors": [],
            "started": "2026-11-05T04:00:00+00:00", "finished": "2026-11-05T04:10:00+00:00",
            "targets": targets or [{"addr": "198.51.100.7", "family": "v4", "role": "router", "full": True}],
            "runs": [{"label": "v4-tcp-top", "rc": rc, "cmd": "--privileged -n -Pn -sS -p T:443,32400,47743 198.51.100.7",
                      "xml_z": base64.b64encode(zlib.compress(xml.encode())).decode()}]}


SNAP = {"ipv4": "198.51.100.7", "ipv6": "2001:db8:1::1", "remote_access": {"enabled": True, "port": "47743"},
        "port_mappings": [{"protocol": "TCP", "external_port": 32400, "internal_client": "192.168.10.20",
                           "internal_port": 32400, "origin": "upnp", "enabled": True, "description": "Plex"}]}
DEVICES = {"aa:bb:cc:00:00:02": {"mac": "aa:bb:cc:00:00:02", "ips": ["192.168.10.20"], "ipv6": [], "hostname": "tv",
                                 "vendor": "ACME"}}


def test_parse_and_tls():
    p = nmapxml.parse(XML)
    port = p["hosts"][0]["ports"][0]
    info = nmapxml.tls_info(port)
    assert info["issuer"] == "R11" and info["key_bits"] == 2048 and info["protocols"] == ["TLSv1.2", "TLSv1.3"]
    assert assess(info, 30)[0] == "info"


def test_findings_with_attribution():
    r = result()
    parsed = external.parse_result(r)
    assert parsed["missing"] == [] and len(parsed["hosts"]["198.51.100.7"]) == 2  # filtered 443 ignored
    fs = {f.id: f for f in external.result_findings(r, parsed, SNAP, DEVICES, from_dict({}))}
    plex = fs["ext:v4:tcp/32400"]
    assert plex.severity == "critical"
    assert "UPnP mapping created by 192.168.10.20 (tv, ACME" in plex.message
    assert "remote access" in fs["ext:v4:tcp/47743"].message
    assert fs["tls-ext:v4:47743"].severity == "info"


def test_resolution_only_for_covered_ports():
    r = result()
    ok = external.resolvable_for(r)
    covered = {"id": "ext:v4:tcp/32400", "detail": {"addr": "198.51.100.7", "family": "v4", "proto": "tcp", "port": 32400, "router": True}}
    not_covered = {"id": "ext:v4:tcp/8080", "detail": {"addr": "198.51.100.7", "family": "v4", "proto": "tcp", "port": 8080, "router": True}}
    gone_v6 = {"id": "ext6:2001:db8::9:tcp/22", "detail": {"addr": "2001:db8::9", "family": "v6", "proto": "tcp", "port": 22}}
    assert ok(covered) and not ok(not_covered) and ok(gone_v6)


def test_failed_run_resolves_nothing_and_is_incomplete():
    r = result(rc=1)
    assert not external.resolvable_for(r)({"id": "ext:v4:tcp/32400", "detail": {"addr": "198.51.100.7", "family": "v4",
                                                                                 "proto": "tcp", "port": 32400, "router": True}})
    r = result(xml=XML.replace('addr="198.51.100.7"', 'addr="198.51.100.8"'))
    parsed = external.parse_result(r)
    assert parsed["missing"] == ["198.51.100.7"]
    assert not external.summarize(r, parsed)["ok"]


def test_port_spec():
    assert external._port_in_spec("T:1-1024,47743,U:500", "tcp", 47743)
    assert external._port_in_spec("T:1-1024,47743,U:500", "udp", 500)
    assert not external._port_in_spec("T:1-1024,47743,U:500", "udp", 47743)


def test_ipv6_device_attribution():
    a, facts = external.attribute(SNAP, {"aa:bb:cc:00:00:03": {"mac": "aa:bb:cc:00:00:03", "ips": [],
                                                               "ipv6": ["2001:db8:1:5e00::3"], "hostname": "cam", "vendor": ""}},
                                  "2001:db8:1:5e00::3", "tcp", 80)
    assert facts["via"] == "ipv6-pinhole" and "cam" in a


def test_build_targets(tmp_path):
    from exposure_guard.store import Store
    s = Store(str(tmp_path / "s.db"))
    s.set("fritz:last", SNAP)
    s.observe("v6:2001:db8:1:5e00:2:2ff:fe00:1", "ipv6", {"mac": "00:00:00:00:00:01", "stable": True})
    doc = external.build_targets(from_dict({}), s, None)
    roles = {t["addr"]: (t["role"], t["full"]) for t in doc["targets"]}
    assert roles["198.51.100.7"] == ("router", True) and roles["2001:db8:1:5e00:2:2ff:fe00:1"] == ("device", True)
    assert 47743 in doc["extra_tcp_ports"] and 32400 in doc["extra_tcp_ports"]
