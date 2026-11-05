import base64
import os
import zlib

import pytest

import fakefritz
import fakeha
from exposure_guard import external, metrics, report
from exposure_guard.config import from_dict
from exposure_guard.guard import Guard

XML = open(os.path.join(os.path.dirname(__file__), "fixtures", "nmap_ext.xml")).read()


@pytest.fixture()
def env(tmp_path, monkeypatch):
    fsrv, fstate = fakefritz.start()
    hsrv, records, hcfg = fakeha.start()
    monkeypatch.setenv("FRITZ_USER", "u")
    monkeypatch.setenv("FRITZ_PASSWORD", "p")
    monkeypatch.setenv("HA_TOKEN", "test-token")
    cfg = from_dict({
        "general": {"data_dir": str(tmp_path / "data"), "acks_file": str(tmp_path / "acks.yaml"),
                    "public_url": "http://guard.example.local:8103"},
        "fritzbox": {"host": "127.0.0.1", "port": fsrv.server_address[1]},
        "inventory": {"use_neighbors": False, "ipv6_discovery": False},
        "external": {"probe_host": "probe.example", "probe_verify_key": "x"},
        "lan_web": {"enabled": False}, "tailscale": {"enabled": False},
        "homeassistant": {"url": f"http://127.0.0.1:{hsrv.server_address[1]}", "notify_service": "notify.mobile_app_phone"},
    })
    g = Guard(cfg)
    g.keys.init()
    g.store.set("first_start", "2026-01-01T00:00:00+00:00")
    yield g, fstate, records, hcfg
    fsrv.shutdown()
    hsrv.shutdown()


def titles(records):
    return [n["title"] for n in records["notify"]]


def test_local_baseline_then_upnp_and_new_device(env):
    g, fstate, rec, _ = env
    g.job_local()
    assert titles(rec) == []  # baseline: nothing alerts
    assert len(g.devices()) == 2
    fstate["upnp_maps"].append({"ext": 32400, "int": 32400, "proto": "TCP", "client": "192.168.10.20", "desc": "Plex"})
    fstate["hosts"].append({"mac": "AA:BB:CC:00:00:99", "ip": "192.168.10.99", "name": "intruder", "active": True})
    g.job_local()
    t = titles(rec)
    assert any("UPnP port forwarding 32400/tcp" in x for x in t)
    assert any("Unknown device in the LAN: intruder" in x for x in t)
    g.job_local()
    assert len(rec["notify"]) == len(t)  # no repeats
    fstate["upnp_maps"].clear()
    g.job_local()
    assert any("resolved" in x for x in titles(rec))
    assert not fstate.get("write_attempts")


def test_ack_via_engine_suppresses_new_device(env):
    g, fstate, rec, _ = env
    g.job_local()
    fstate["hosts"].append({"mac": "AA:BB:CC:00:00:77", "ip": "192.168.10.77", "name": "printer", "active": True})
    g.job_local()
    n = len(rec["notify"])
    f = g.store.finding("device:aa:bb:cc:00:00:77")
    g.acks.add(f["id"], f["fingerprint"], "my printer")
    g.job_local()
    assert len(rec["notify"]) == n
    st = g.status()
    assert st["acknowledged"] == 1 and st["critical_open"] == 0


def test_status_unknown_without_external_and_publish(env):
    g, _, rec, _ = env
    g.job_local()
    g.job_external()  # not reachable -> health failure, never "ok"
    g._check_stale()
    st = g.status()
    assert st["state"] == "unknown" and "no complete external scan" in st["external_stale"]
    g.publish()
    assert rec["states"]["sensor.exposure_guard"]["state"] == "unknown"
    assert rec["states"]["sensor.exposure_guard_external"]["state"] == "stale"
    assert "heartbeat" in rec["states"]["sensor.exposure_guard"]["attributes"]
    # after the stale window a warning is pushed once
    assert any("external scan results FAILING" in x for x in titles(rec))
    n = len(rec["notify"])
    g._check_stale()
    assert len(rec["notify"]) == n


def test_probe_unreachable_warns_after_threshold(env):
    g, _, rec, _ = env
    for _ in range(2):
        g.job_external()
    assert not any("connection to the external probe" in x for x in titles(rec))
    g.job_external()
    assert any("connection to the external probe FAILING" in x for x in titles(rec))


def test_external_result_flow(env, monkeypatch):
    g, fstate, rec, _ = env
    fstate["upnp_maps"].append({"ext": 32400, "int": 32400, "proto": "TCP", "client": "192.168.10.20", "desc": "Plex"})
    g.job_local()  # baseline includes the mapping
    res = {"run_id": "r1", "profile": "daily", "ok": True, "errors": [], "started": "2026-11-05T04:00:00+00:00",
           "finished": "2099-01-01T00:00:00+00:00",
           "targets": [{"addr": "198.51.100.7", "family": "v4", "role": "router", "full": True}],
           "runs": [{"label": "v4", "rc": 0, "cmd": "-p T:1-1024,32400,47743 198.51.100.7",
                     "xml_z": base64.b64encode(zlib.compress(XML.replace('portid="32400"', 'portid="9999"').encode())).decode()}]}
    g._process_result("r1", res)  # first external result = baseline
    assert not any("Reachable" in x for x in titles(rec))
    res2 = dict(res, run_id="r2", runs=[dict(res["runs"][0], xml_z=base64.b64encode(zlib.compress(XML.encode())).decode())])
    g._process_result("r2", res2)
    t = [x for x in titles(rec) if "Reachable from the internet: 32400/tcp" in x]
    assert t, titles(rec)
    msg = next(n["message"] for n in rec["notify"] if "32400" in n["title"] and "Reachable" in n["title"])
    assert "UPnP mapping created by 192.168.10.20 (tv" in msg
    assert g.store.get("external:last_good")["run_id"] == "r2"
    # metrics + report render
    text = metrics.render(g)
    assert 'exposure_guard_external_open_ports{family="v4"}' in text
    name = report.write(g, "initial")
    md = open(os.path.join(g.cfg.data_dir, "reports", name + ".md")).read()
    assert "32400/tcp" in md and "UPnP" in md


def test_ip_change_detected(env):
    g, fstate, rec, _ = env
    g.job_local()
    fstate["ipv4"] = "198.51.100.99"
    g.job_local()
    assert any("public IP changed" in x for x in titles(rec))
    assert g.store.get("external:force_push")


def test_fritz_failure_alerts_after_two(env):
    g, fstate, rec, _ = env
    g.job_local()
    fstate["fail_auth"] = True
    g.job_local()
    assert not any("FAILING" in x for x in titles(rec))
    g.job_local()
    assert any("FRITZ!Box query (TR-064/UPnP) FAILING" in x for x in titles(rec))
    assert g.status()["state"] in ("degraded", "unknown")
    fstate["fail_auth"] = False
    g.job_local()
    assert any("working again" in x for x in titles(rec))


def test_outbox_when_ha_down(env):
    g, fstate, rec, hcfg = env
    g.job_local()
    hcfg["down"] = True
    fstate["hosts"].append({"mac": "AA:BB:CC:00:00:55", "ip": "192.168.10.55", "name": "late", "active": True})
    g.job_local()
    assert g.store.get("outbox")
    hcfg["down"] = False
    g._flush_outbox()
    assert any("late" in x for x in titles(rec)) and not g.store.get("outbox")


def test_scheduler_tick(env):
    g, _, rec, _ = env
    g.tick()
    assert g.store.get("sched:local") and g.store.get("published")


def test_probe_sees_different_ip(env):
    g, _, rec, _ = env
    g.job_local()
    g._check_probe_view({"client_ip": "198.51.100.7"})
    assert not any("cross-check" in x for x in titles(rec))
    g._check_probe_view({"client_ip": "203.0.113.1"})
    assert any("public IP cross-check (router vs. probe) FAILING" in x for x in titles(rec))
    assert g.store.get("external:force_push")
