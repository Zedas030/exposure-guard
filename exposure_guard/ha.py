"""Home Assistant: push notifications through a notify service and status sensors via the REST API."""
from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request

from .util import log


class HomeAssistant:
    def __init__(self, cfg):
        ha = cfg["homeassistant"]
        self.enabled = bool(ha["enabled"])
        self.url = ha["url"].rstrip("/")
        self.token = cfg.secret("homeassistant", "token_env")
        self.service = ha["notify_service"]
        self.prefix = ha["sensor_prefix"]
        self.ctx = None if ha["verify_tls"] else ssl._create_unverified_context()  # noqa: SLF001
        self.last_error = ""

    def _post(self, path: str, payload: dict) -> bool:
        if not self.enabled:
            return True
        if not self.token:
            self.last_error = "HA_TOKEN missing"
            return False
        req = urllib.request.Request(self.url + path, data=json.dumps(payload).encode(), method="POST",
                                     headers={"Authorization": f"Bearer {self.token}",
                                              "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=15, context=self.ctx) as r:
                r.read()
            self.last_error = ""
            return True
        except (urllib.error.URLError, OSError) as exc:
            self.last_error = f"{path}: {exc}"
            log.warning("Home Assistant call failed: %s", self.last_error)
            return False

    def notify(self, title: str, message: str, tag: str = "exposure-guard", url: str = "") -> bool:
        domain, _, name = self.service.partition(".")
        data = {"tag": tag, "group": "exposure-guard"}
        if url:
            data.update(url=url, clickAction=url)
        return self._post(f"/api/services/{domain}/{name}", {"title": title, "message": message, "data": data})

    def state(self, suffix: str, state, attributes: dict) -> bool:
        entity = self.prefix + (f"_{suffix}" if suffix else "")
        return self._post(f"/api/states/{entity}", {"state": state, "attributes": attributes})
