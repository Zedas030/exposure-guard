import yaml

from exposure_guard.findings import Acks, Engine, Finding
from exposure_guard.store import Store


def mk(fid="ext:v4:tcp/32400", sev="critical", state=("plex",)):
    return Finding(id=fid, source="external", kind="open_port", severity=sev, title=f"t {fid}", message="m",
                   action="a", detail={"x": 1}, state_key=list(state))


def setup(tmp_path):
    store = Store(str(tmp_path / "s.db"))
    acks = Acks(str(tmp_path / "acks.yaml"), store)
    return store, acks, Engine(store, acks)


def test_first_run_is_baseline_without_alert(tmp_path):
    store, _, eng = setup(tmp_path)
    assert eng.apply("external", [mk()]) == []
    f = store.finding("ext:v4:tcp/32400")
    assert f["baseline"] and f["state"] == "open"


def test_new_critical_alerts_once(tmp_path):
    store, _, eng = setup(tmp_path)
    eng.apply("external", [])  # baseline: empty
    a = eng.apply("external", [mk()])
    assert [x["type"] for x in a] == ["new"]
    assert eng.apply("external", [mk()]) == []  # no repeat


def test_non_critical_never_alerts(tmp_path):
    _, _, eng = setup(tmp_path)
    eng.apply("external", [])
    assert eng.apply("external", [mk(sev="medium")]) == []


def test_change_realerts_and_resolve(tmp_path):
    store, _, eng = setup(tmp_path)
    eng.apply("external", [])
    eng.apply("external", [mk()])
    a = eng.apply("external", [mk(state=("ssh",))])
    assert [x["type"] for x in a] == ["changed"]
    a = eng.apply("external", [])
    assert [x["type"] for x in a] == ["resolved"]
    assert store.finding("ext:v4:tcp/32400")["state"] == "resolved"
    a = eng.apply("external", [mk()])  # comes back -> new again
    assert [x["type"] for x in a] == ["new"]


def test_resolvable_limits_resolution(tmp_path):
    store, _, eng = setup(tmp_path)
    eng.apply("external", [])
    eng.apply("external", [mk()])
    eng.apply("external", [], resolvable=lambda f: False)
    assert store.finding("ext:v4:tcp/32400")["state"] == "open"


def test_ack_suppresses_until_change(tmp_path):
    store, acks, eng = setup(tmp_path)
    eng.apply("external", [])
    f = mk()
    acks.add(f.id, f.fingerprint, "known")
    assert eng.apply("external", [f]) == []
    a = eng.apply("external", [mk(state=("other-service",))])
    assert [x["type"] for x in a] == ["changed"]
    data = yaml.safe_load(open(tmp_path / "acks.yaml"))
    assert data["acks"][0]["reason"] == "known"


def test_yaml_ack_without_fingerprint_binds_first_state(tmp_path):
    store, acks, eng = setup(tmp_path)
    (tmp_path / "acks.yaml").write_text("acks:\n  - id: 'ext:*'\n    reason: wildcard\n")
    eng.apply("external", [])
    assert eng.apply("external", [mk()]) == []          # bound to this state
    assert eng.apply("external", [mk(state=("x",))])     # changed -> alerts again


def test_ack_expiry(tmp_path):
    store, acks, eng = setup(tmp_path)
    f = mk()
    (tmp_path / "acks.yaml").write_text(f"acks:\n  - id: '{f.id}'\n    reason: old\n    until: 2000-01-01\n")
    eng.apply("external", [])
    assert eng.apply("external", [f])  # expired ack -> alert


def test_baseline_item_that_changes_alerts(tmp_path):
    store, _, eng = setup(tmp_path)
    eng.apply("external", [mk()])
    a = eng.apply("external", [mk(state=("changed",))])
    assert [x["type"] for x in a] == ["changed"]
    assert not store.finding("ext:v4:tcp/32400")["baseline"]


def test_reminders(tmp_path):
    store, _, eng = setup(tmp_path)
    eng.apply("external", [])
    eng.apply("external", [mk()])
    f = store.finding("ext:v4:tcp/32400")
    f["notified_at"] = "2000-01-01T00:00:00+00:00"
    store.upsert_finding(f)
    assert [x["type"] for x in eng.reminders(24)] == ["reminder"]
    assert eng.reminders(0) == []
