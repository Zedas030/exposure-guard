import base64
import io
import json
import os

import pytest
from nacl.public import PrivateKey
from nacl.signing import SigningKey

import exposure_probe as probe
from exposure_guard.crypto import EnvelopeError, GuardKeys, open_envelope, seal, sign_json


def test_seal_roundtrip_and_tamper(tmp_path):
    sk, box = SigningKey.generate(), PrivateKey.generate()
    env = seal({"a": 1}, base64.b64encode(bytes(box.public_key)).decode(), sk)
    vk = base64.b64encode(bytes(sk.verify_key)).decode()
    assert open_envelope(env, vk, box) == {"a": 1}
    other = base64.b64encode(bytes(SigningKey.generate().verify_key)).decode()
    with pytest.raises(EnvelopeError, match="signature"):
        open_envelope(env, other, box)
    raw = bytearray(base64.b64decode(env))
    raw[-1] ^= 1
    with pytest.raises(EnvelopeError):
        open_envelope(base64.b64encode(bytes(raw)).decode(), vk, box)
    with pytest.raises(EnvelopeError):
        open_envelope(env, vk, PrivateKey.generate())


def test_guard_keys(tmp_path):
    k = GuardKeys(str(tmp_path / "keys"))
    assert k.init() and not k.init()
    assert oct(os.stat(k.sign_path).st_mode & 0o777) == "0o600"
    assert set(k.public()) == {"guard_verify_key", "guard_box_public_key"}


@pytest.fixture()
def probe_env(tmp_path, monkeypatch):
    keys = GuardKeys(str(tmp_path / "gk"))
    keys.init()
    pub = keys.public()
    conf = tmp_path / "probe.json"
    conf.write_text(json.dumps({"guard_verify_key": pub["guard_verify_key"],
                                "guard_box_public_key": pub["guard_box_public_key"], "allow_private_targets": False}))
    monkeypatch.setattr(probe, "CONF", str(conf))
    monkeypatch.setattr(probe, "KEY", str(tmp_path / "probe.key"))
    monkeypatch.setattr(probe, "STATE", str(tmp_path / "state"))
    os.makedirs(tmp_path / "state" / "results")
    probe.init()
    pvk = base64.b64encode(bytes(probe.signing_key().verify_key)).decode()
    return keys, pvk, conf


def gate(monkeypatch, capsys, cmd, stdin=""):
    monkeypatch.setenv("SSH_ORIGINAL_COMMAND", cmd)
    monkeypatch.setenv("SSH_CONNECTION", "203.0.113.5 50000 198.51.100.1 22")
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    rc = probe.gate()
    return rc, capsys.readouterr().out.strip()


def targets_doc(seq, addr="8.8.8.8"):
    return {"seq": seq, "targets": [{"addr": addr, "role": "router", "full": True}], "udp_ports": [500],
            "extra_tcp_ports": [47743], "max_rate": 300}


def test_gate_health_put_targets(probe_env, monkeypatch, capsys):
    keys, pvk, _ = probe_env
    rc, out = gate(monkeypatch, capsys, "health")
    h = open_envelope(out, pvk, keys.box())
    assert rc == 0 and h["client_ip"] == "203.0.113.5" and h["type"] == "health"
    rc, out = gate(monkeypatch, capsys, "put-targets", sign_json(targets_doc(5), keys.signing()))
    assert rc == 0 and open_envelope(out, pvk, keys.box())["ok"]
    rc, out = gate(monkeypatch, capsys, "put-targets", sign_json(targets_doc(4), keys.signing()))
    assert rc == 2 and "stale" in open_envelope(out, pvk, keys.box())["error"]
    # signed by someone else -> rejected
    rc, out = gate(monkeypatch, capsys, "put-targets", sign_json(targets_doc(9), SigningKey.generate()))
    assert rc == 2 and not open_envelope(out, pvk, keys.box())["ok"]
    # private address -> rejected
    rc, out = gate(monkeypatch, capsys, "put-targets", sign_json(targets_doc(10, "192.168.1.1"), keys.signing()))
    assert rc == 2 and "non-global" in open_envelope(out, pvk, keys.box())["error"]


def test_gate_denies_unknown(probe_env, monkeypatch, capsys):
    rc, _ = gate(monkeypatch, capsys, "bash -i")
    assert rc == 3
    rc, _ = gate(monkeypatch, capsys, "")
    assert rc == 3


def test_scan_now_rate_limited(probe_env, monkeypatch, capsys):
    keys, pvk, _ = probe_env
    _, out = gate(monkeypatch, capsys, "scan-now")
    assert open_envelope(out, pvk, keys.box())["accepted"]
    _, out = gate(monkeypatch, capsys, "scan-now")
    assert not open_envelope(out, pvk, keys.box())["accepted"]


def test_run_without_targets_reports_error(probe_env, monkeypatch, capsys):
    keys, pvk, _ = probe_env
    assert probe.run_scan("daily") == 1
    capsys.readouterr()
    rc, out = gate(monkeypatch, capsys, "get-results 0")
    run_id, env = out.split(" ", 1)
    res = open_envelope(env, pvk, keys.box())
    assert not res["ok"] and "no target list" in res["errors"][0] and run_id.endswith("-daily")


def test_run_with_fake_nmap(probe_env, monkeypatch, capsys, tmp_path):
    keys, pvk, _ = probe_env
    gate(monkeypatch, capsys, "put-targets", sign_json(targets_doc(7), keys.signing()))
    calls = []

    def fake_nmap(args, label, timeout):
        calls.append(args)
        return {"label": label, "cmd": "nmap " + " ".join(args), "rc": 0, "stderr": "", "seconds": 1, "xml_z": "eA=="}
    monkeypatch.setattr(probe, "nmap", fake_nmap)
    monkeypatch.setattr(probe, "top_tcp_ports", lambda n: [22, 80, 443])
    assert probe.run_scan("full") == 0
    assert any("T:1-65535" in a for a in calls[0])
    assert any(a.startswith("U:") for a in calls[1])


def test_compress_ranges():
    assert probe.compress_ranges([1, 2, 3, 5, 7, 8]) == "1-3,5,7-8"
