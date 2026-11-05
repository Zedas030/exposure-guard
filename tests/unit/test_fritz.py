import pytest

import fakefritz
from exposure_guard import checks, fritz
from exposure_guard.config import from_dict
from exposure_guard.store import Store


@pytest.fixture()
def fb(monkeypatch):
    srv, state = fakefritz.start()
    monkeypatch.setenv("FRITZ_USER", "u")
    monkeypatch.setenv("FRITZ_PASSWORD", "p")
    cfg = from_dict({"fritzbox": {"host": "127.0.0.1", "port": srv.server_address[1]}})
    yield cfg, state
    srv.shutdown()


def test_collect_reads_everything(fb):
    cfg, state = fb
    state["manual"].append({"ext": 8443, "int": 443, "proto": "TCP", "client": "192.168.10.10", "desc": "nas"})
    state["upnp_maps"].append({"ext": 32400, "int": 32400, "proto": "TCP", "client": "192.168.10.20", "desc": "Plex"})
    snap = fritz.collect(cfg)
    assert snap["device"]["firmware"] == "8.25"
    assert snap["ipv4"] == "198.51.100.7" and snap["ipv6_prefix"] == "2001:db8:1:5e00::/56"
    assert snap["remote_access"]["enabled"] and snap["remote_access"]["port"] == "47743"
    origins = {m["external_port"]: m["origin"] for m in snap["port_mappings"]}
    assert origins == {8443: "manual", 32400: "upnp"}
    assert len(snap["hosts"]) == 2 and snap["hosts"][0]["mac"] == "aa:bb:cc:00:00:01"
    assert snap["igd_ok"]
    assert not state.get("write_attempts")


def test_missing_credentials(monkeypatch):
    monkeypatch.delenv("FRITZ_USER", raising=False)
    with pytest.raises(fritz.FritzError):
        fritz.collect(from_dict({}))


def test_auth_failure(fb):
    cfg, state = fb
    state["fail_auth"] = True
    with pytest.raises(fritz.FritzError, match="login rejected"):
        fritz.collect(cfg)


def test_igd_failure_is_reported(fb):
    cfg, state = fb
    state["fail_igd"] = True
    snap = fritz.collect(cfg)
    assert not snap["igd_ok"] and any("IGD" in e for e in snap["errors"])


def test_refuses_write_actions():
    soap = fritz._Soap.__new__(fritz._Soap)
    soap.services = {"urn:dslforum-org:service:WANIPConnection:1": "/x"}
    with pytest.raises(fritz.FritzError, match="refusing"):
        soap.call("WANIPConnection:1", "AddPortMapping")
    with pytest.raises(fritz.FritzError, match="refusing"):
        soap.call("WANIPConnection:1", "SetEnable")


def test_soap_fault_parsing():
    with pytest.raises(fritz.SoapFault) as e:
        fritz._parse_response(fakefritz.soap_fault(713, "SpecifiedArrayIndexInvalid"))
    assert e.value.code == "713"


def test_router_findings(fb, tmp_path):
    cfg, state = fb
    state["upnp_maps"].append({"ext": 32400, "int": 32400, "proto": "TCP", "client": "192.168.10.20", "desc": "Plex"})
    snap = fritz.collect(cfg)
    devices = {"aa:bb:cc:00:00:02": {"mac": "aa:bb:cc:00:00:02", "ips": ["192.168.10.20"], "ipv6": [],
                                     "hostname": "tv", "vendor": "ACME"}}
    fs = {f.id: f for f in checks.router_findings(snap, devices, Store(str(tmp_path / "s.db")))}
    m = fs["map:tcp/32400"]
    assert m.severity == "critical" and "UPnP" in m.title
    assert "192.168.10.20 (tv, ACME" in m.message and "first seen" in m.message
    assert fs["router:upnp"].severity == "medium"
    assert fs["router:remote-access"].severity == "medium"
    assert fs["router:firmware"].severity == "info"


def test_classify_mappings_dedup():
    a = {"protocol": "TCP", "external_port": 80, "internal_client": "1.2.3.4", "internal_port": 80}
    b = {"protocol": "TCP", "external_port": 81, "internal_client": "1.2.3.4", "internal_port": 81}
    out = fritz.classify_mappings([a, b], [a])
    assert [(m["external_port"], m["origin"]) for m in out] == [(80, "upnp"), (81, "manual")]
