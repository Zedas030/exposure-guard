"""Fake FRITZ!Box for tests: TR-064 + UPnP IGD SOAP with mutable state.

Run standalone (e2e):  python3 fakefritz.py 49000
Control: POST /_control {"op": "add_mapping"|"remove_mapping"|"add_host"|"set", ...}"""
from __future__ import annotations

import json
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TR = "urn:dslforum-org:service:"
UP = "urn:schemas-upnp-org:service:"

TR64_SERVICES = ["DeviceInfo:1", "UserInterface:1", "WANIPConnection:1", "X_AVM-DE_RemoteAccess:1", "X_AVM-DE_MyFritz:1",
                 "ManagementServer:1", "X_AVM-DE_UPnP:1", "Hosts:1"]


def default_state() -> dict:
    return {
        "model": "FRITZ!Box 6660 Cable", "firmware": "8.25", "update": False,
        "ipv4": "198.51.100.7", "ipv6": "2001:db8:1::1", "prefix": "2001:db8:1:5e00::", "prefix_len": 56,
        "remote": {"enabled": True, "port": 47743}, "myfritz": True, "upnp": True,
        "manual": [],   # mappings only visible via TR-064
        "upnp_maps": [],  # mappings created via UPnP (visible via IGD and TR-064)
        "hosts": [
            {"mac": "AA:BB:CC:00:00:01", "ip": "192.168.10.10", "name": "nas", "active": True},
            {"mac": "AA:BB:CC:00:00:02", "ip": "192.168.10.20", "name": "tv", "active": True},
        ],
        "fail_auth": False, "fail_igd": False,
    }


def desc(services, prefix):
    items = "".join(f"<service><serviceType>{prefix}{s}</serviceType><controlURL>/ctl/{s.replace(':', '_')}</controlURL></service>"
                    for s in services)
    return f"<?xml version='1.0'?><root><device><serviceList>{items}</serviceList></device></root>"


def soap_ok(action, svc, fields):
    body = "".join(f"<{k}>{v}</{k}>" for k, v in fields.items())
    return (f"<?xml version='1.0'?><s:Envelope xmlns:s='http://schemas.xmlsoap.org/soap/envelope/'><s:Body>"
            f"<u:{action}Response xmlns:u='{svc}'>{body}</u:{action}Response></s:Body></s:Envelope>")


def soap_fault(code, desc_):
    return (f"<?xml version='1.0'?><s:Envelope xmlns:s='http://schemas.xmlsoap.org/soap/envelope/'><s:Body><s:Fault>"
            f"<detail><UPnPError><errorCode>{code}</errorCode><errorDescription>{desc_}</errorDescription></UPnPError>"
            f"</detail></s:Fault></s:Body></s:Envelope>")


def mapping_fields(m):
    return {"NewRemoteHost": "", "NewExternalPort": m["ext"], "NewProtocol": m["proto"], "NewInternalPort": m["int"],
            "NewInternalClient": m["client"], "NewEnabled": "1", "NewPortMappingDescription": m.get("desc", ""),
            "NewLeaseDuration": "0"}


def make_handler(state, lock):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype="text/xml"):
            data = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path == "/tr64desc.xml":
                return self._send(200, desc(TR64_SERVICES, TR))
            if self.path in ("/igd2desc.xml", "/igddesc.xml"):
                if state["fail_igd"]:
                    return self._send(404, "no")
                return self._send(200, desc(["WANIPConnection:2", "WANIPv6FirewallControl:1"], UP))
            if self.path.startswith("/hostlist"):
                items = "".join(
                    f"<Item><MACAddress>{h['mac']}</MACAddress><IPAddress>{h['ip']}</IPAddress><HostName>{h['name']}</HostName>"
                    f"<Active>{1 if h['active'] else 0}</Active><InterfaceType>Ethernet</InterfaceType>"
                    f"<X_AVM-DE_Guest>0</X_AVM-DE_Guest></Item>" for h in state["hosts"])
                return self._send(200, f"<?xml version='1.0'?><List>{items}</List>")
            if self.path == "/_state":
                return self._send(200, json.dumps(state), "application/json")
            return self._send(404, "")

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n).decode()
            if self.path == "/_control":
                return self._control(json.loads(body))
            sa = self.headers.get("SOAPAction", "").strip('"')
            svc, _, action = sa.partition("#")
            if not action.startswith(("Get", "X_AVM-DE_Get")):
                state.setdefault("write_attempts", []).append(sa)  # the guard must never do this
                return self._send(500, soap_fault(401, "Invalid Action"))
            if svc.startswith(TR) and state["fail_auth"]:
                return self._send(401, "unauthorized")
            args = dict(re.findall(r"<(New\w+)>([^<]*)</\1>", body))
            with lock:
                res = self._dispatch(svc, action, args)
            if isinstance(res, tuple):
                return self._send(500, soap_fault(*res))
            return self._send(200, soap_ok(action, svc, res))

        def _dispatch(self, svc, action, args):
            short = svc.split(":service:")[-1]
            s = state
            if short == "DeviceInfo:1":
                return {"NewModelName": s["model"], "NewSoftwareVersion": s["firmware"], "NewUpTime": "1000"}
            if short == "UserInterface:1":
                return {"NewUpgradeAvailable": "1" if s["update"] else "0", "NewX_AVM-DE_Version": "8.30" if s["update"] else ""}
            if short == "X_AVM-DE_RemoteAccess:1":
                return {"NewEnabled": "1" if s["remote"]["enabled"] else "0", "NewPort": s["remote"]["port"],
                        "NewLetsEncryptEnabled": "1", "NewLetsEncryptState": "valid"}
            if short == "X_AVM-DE_MyFritz:1":
                if action == "GetNumberOfServices":
                    return {"NewNumberOfServices": "0"}
                return {"NewEnabled": "1" if s["myfritz"] else "0", "NewDeviceRegistered": "1"}
            if short == "ManagementServer:1":
                return {"NewURL": "https://acs.example.net", "NewPeriodicInformEnable": "1"}
            if short == "X_AVM-DE_UPnP:1":
                return {"NewEnable": "1" if s["upnp"] else "0", "NewUPnPMediaServer": "0"}
            if short == "Hosts:1":
                return {"NewX_AVM-DE_HostListPath": "/hostlist.lua?sid=1"}
            if short.startswith("WANIPConnection"):
                igd = svc.startswith(UP)
                maps = s["upnp_maps"] if igd else s["manual"] + s["upnp_maps"]
                if action == "GetExternalIPAddress":
                    return {"NewExternalIPAddress": s["ipv4"]}
                if action == "X_AVM-DE_GetExternalIPv6Address":
                    return {"NewExternalIPv6Address": s["ipv6"], "NewPrefixLength": "64"}
                if action == "X_AVM-DE_GetIPv6Prefix":
                    return {"NewIPv6Prefix": s["prefix"], "NewPrefixLength": s["prefix_len"]}
                if action == "GetPortMappingNumberOfEntries":
                    if igd:
                        return (401, "Invalid Action")
                    return {"NewPortMappingNumberOfEntries": len(maps)}
                if action == "GetGenericPortMappingEntry":
                    i = int(args.get("NewPortMappingIndex", 0))
                    if i >= len(maps):
                        return (713, "SpecifiedArrayIndexInvalid")
                    return mapping_fields(maps[i])
            return (401, "Invalid Action")

        def _control(self, cmd):
            with lock:
                op = cmd.get("op")
                if op == "add_mapping":
                    m = {"ext": cmd["ext"], "int": cmd.get("int", cmd["ext"]), "proto": cmd.get("proto", "TCP"),
                         "client": cmd["client"], "desc": cmd.get("desc", "")}
                    (state["upnp_maps"] if cmd.get("upnp", True) else state["manual"]).append(m)
                elif op == "remove_mapping":
                    for k in ("upnp_maps", "manual"):
                        state[k] = [m for m in state[k] if m["ext"] != cmd["ext"]]
                elif op == "add_host":
                    state["hosts"].append({"mac": cmd["mac"], "ip": cmd["ip"], "name": cmd.get("name", ""), "active": True})
                elif op == "set":
                    state.update(cmd["values"])
            return self._send(200, json.dumps({"ok": True}), "application/json")
    return H


def start(port=0, state=None):
    state = state if state is not None else default_state()
    srv = ThreadingHTTPServer(("127.0.0.1" if port == 0 else "0.0.0.0", port), make_handler(state, threading.Lock()))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, state


if __name__ == "__main__":
    srv, _ = start(int(sys.argv[1]) if len(sys.argv) > 1 else 49000)
    print("fake fritz on", srv.server_address, flush=True)
    threading.Event().wait()
