"""Configuration: commented YAML (config.yaml) + secrets from the environment (.env)."""
from __future__ import annotations

import copy
import os

import yaml

DEFAULTS: dict = {
    "general": {
        "data_dir": "/data",
        "acks_file": "/acks/acks.yaml",
        "listen_host": "0.0.0.0",
        "listen_port": 8103,
        "public_url": "",
        "timezone": "Europe/Berlin",
        "log_level": "INFO",
    },
    "ui": {"home_url": "", "home_label": "Dashboard"},
    "network": {
        "lan_cidr": "192.168.10.0/24",
        "interface": "eth0",
        "self_ip": "",
    },
    "fritzbox": {
        "enabled": True,
        "host": "192.168.10.1",
        "port": 49000,
        "user_env": "FRITZ_USER",
        "password_env": "FRITZ_PASSWORD",
        "timeout": 10,
    },
    "inventory": {
        "use_fritz_hosts": True,
        "use_neighbors": True,
        "ipv6_discovery": True,
        "ipv6_keep_hours": 24,
        "max_ipv6_targets": 64,
        "known_devices": {},
    },
    "external": {
        "enabled": True,
        "probe_host": "",
        "probe_host_v6": "",
        "probe_verify_key": "",
        "probe_port": 22,
        "probe_user": "probe",
        "fetch_minutes": 30,
        "stale_hours": 26,
        "unreachable_after": 3,
        "connect_timeout": 20,
        "scan_on_ip_change": True,
        "ip_crosscheck": True,
        "extra_tcp_ports": [],
        "udp_ports": [500, 4500, 51820, 1194, 3478, 5060],
        "max_rate": 300,
        "ipv6_devices": True,
    },
    "lan_web": {
        "enabled": True,
        "weekday": "sun",
        "time": "04:30",
        "ports": [80, 81, 443, 591, 3000, 5000, 5001, 7080, 7443, 8000, 8008, 8080, 8081, 8088, 8123, 8181,
                  8443, 8888, 9000, 9090, 9443, 10443],
        "max_rate": 20,
        "request_pause": 0.5,
        "exclude": [],
    },
    "tls": {"warn_days": 30},
    "tailscale": {
        "enabled": True,
        "socket": "/var/run/tailscale/tailscaled.sock",
        "poll_minutes": 60,
        "key_expiry_warn_days": 14,
        "api_enabled": True,
        "client_id_env": "TS_OAUTH_CLIENT_ID",
        "client_secret_env": "TS_OAUTH_CLIENT_SECRET",
        "api_key_env": "TS_API_KEY",
        "tailnet": "-",
        "api_url": "https://api.tailscale.com",
    },
    "schedule": {
        "local_minutes": 10,
        "weekly_report": {"weekday": "sun", "time": "18:00"},
    },
    "homeassistant": {
        "enabled": True,
        "url": "http://127.0.0.1:8123",
        "token_env": "HA_TOKEN",
        "notify_service": "notify.mobile_app_phone",
        "sensor_prefix": "sensor.exposure_guard",
        "verify_tls": True,
        "notify_ip_change": True,
        "remind_critical_hours": 0,
    },
}


def deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = value
    return out


class Config(dict):
    """dict with helpers for secrets. Secrets never live in the YAML, only their variable names."""

    path: str = ""

    def secret(self, section: str, key: str) -> str:
        name = self[section].get(key) or ""
        return os.environ.get(name, "") if name else ""

    @property
    def data_dir(self) -> str:
        return self["general"]["data_dir"]


def load(path: str | None = None) -> Config:
    path = path or os.environ.get("EXPOSURE_GUARD_CONFIG", "/config/config.yaml")
    raw: dict = {}
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
    cfg = Config(deep_merge(DEFAULTS, raw))
    cfg.path = path
    _validate(cfg)
    return cfg


def from_dict(raw: dict) -> Config:
    cfg = Config(deep_merge(DEFAULTS, raw))
    _validate(cfg)
    return cfg


WEEKDAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]


def _validate(cfg: Config) -> None:
    for sect, key in (("lan_web", "weekday"),):
        day = str(cfg[sect][key]).lower()[:3]
        if day not in WEEKDAYS:
            raise ValueError(f"{sect}.{key}: unknown weekday {cfg[sect][key]!r}")
        cfg[sect][key] = day
    wr = cfg["schedule"]["weekly_report"]
    wr["weekday"] = str(wr["weekday"]).lower()[:3]
    if wr["weekday"] not in WEEKDAYS:
        raise ValueError("schedule.weekly_report.weekday invalid")
    svc = cfg["homeassistant"]["notify_service"]
    if cfg["homeassistant"]["enabled"] and "." not in svc:
        raise ValueError("homeassistant.notify_service must look like notify.<name>")
