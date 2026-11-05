# Exposure-Wächter (Exposure Guard)

Überwacht laufend, **was das Heimnetz ins Internet freigibt** und **was sich im LAN sicherheitsrelevant ändert** –
mit Schwerpunkt auf Portfreigaben, die Geräte per UPnP still selbst öffnen.

English version: [README.md](README.md)

## Was er prüft

| Bereich | Prüfung | Häufigkeit |
|---|---|---|
| FRITZ!Box (TR-064 + UPnP-IGD, nur lesend) | alle IPv4-Portfreigaben, **getrennt nach manuell und UPnP**, mit Gerät (IP, Hostname, Hersteller, MAC) und Zeitpunkt des ersten Auftretens; MyFRITZ!-Freigaben; UPnP-Status; Fernzugang (HTTPS-Port, Let's Encrypt); MyFRITZ!-Konto; Provider-Fernwartung (TR-069); Firmware-Stand und verfügbare Updates; öffentliche IPv4, WAN-IPv6 und IPv6-Präfix | alle 10 min |
| Externe Sicht (Prüfstation auf einem VPS) | Portscan gegen die eigene öffentliche IPv4 und **jede globale IPv6-Adresse im LAN**: die 1000 häufigsten TCP-Ports + alle weitergeleiteten Ports + Fernzugangsport täglich, **alle 65 535 TCP-Ports samstags** (Router und Geräte mit stabiler IPv6-Adresse), wichtige UDP-Ports (IPsec, WireGuard, OpenVPN, STUN, SIP) am Router; Dienst- und Versionserkennung; TLS (`ssl-cert`, `ssl-enum-ciphers`) | täglich 05:00 |
| IP-Wechsel | Wechsel von IPv4 und IPv6-Präfix; Gegenprüfung: Die Prüfstation meldet, mit welcher Absenderadresse der Pi ankommt | alle 10 / 30 min |
| LAN-Inventar (passiv) | neue, unbekannte Geräte aus der Geräteliste der FRITZ!Box, ARP- und NDP-Tabelle; MAC, Hersteller (IEEE-Liste, offline), Hostname, zufällige MAC | alle 10 min |
| Weboberflächen im LAN (schonend) | Anmeldeseiten über HTTP ohne TLS; Produkte mit bekannten Standard-Logins oder ohne Anmeldung – **nur Erkennung über Startseite und Hersteller, keine Anmeldeversuche**; Zertifikate (Ablauf, Selbstsignierung, alte Protokolle, schwache Schlüssel) | wöchentlich So 04:30 |
| Tailscale | Geräte im Tailnet, abgelaufene/bald ablaufende Keys, abgeschaltetes Key-Ablaufdatum, Exit-Nodes, Subnet-Routen; per API: ACL „alles erlaubt“, Funnel, Tailscale-SSH als root ohne Nachprüfung, Auto-Approver, Client-Updates, geteilte Fremdgeräte | stündlich |

Das Tool **ändert nichts** an FRITZ!Box, Firewall oder Geräten. Es meldet und schlägt Maßnahmen vor. Im Code ist
erzwungen, dass an die FRITZ!Box nur `Get*`-Aktionen gehen.

## Aufbau

```
                    Internet
  +------------------+        scannt nur signierte Ziele
  | VPS: exposure-   | ---------------------------------> öffentliche IPv4 / IPv6 des Heimnetzes
  | probe (nmap)     |
  +------------------+
         ^  SSH, von zu Hause ausgehend; erzwungener Befehl (health | put-targets | get-results | scan-now)
         |  Ergebnisse: für den Wächter verschlüsselt (Sealed Box) und von der Prüfstation signiert (Ed25519)
  +------+-----------------------------------------------+
  | Pi (Docker): exposure-guard                           |
  |  FRITZ!Box, Inventar, LAN-Webcheck, Tailscale          |
  |  -> Befunde, Baseline, Quittierungen                   |
  |  -> HA-Push + Sensoren, /metrics, Web :8103, Berichte |
  +--------------------------------------------------------+
```

- Zu Hause wird **kein Port geöffnet**; die Prüfstation kommt nie ins LAN und nie ins Tailnet.
- Die Prüfstation scannt nur Zielslisten, die der Wächter signiert hat, und lehnt nicht-globale Adressen ab.
- Ergebnisse liegen auf dem VPS nur verschlüsselt; nur der Wächter kann sie öffnen, und er nimmt nur Ergebnisse an,
  die mit dem fest hinterlegten Schlüssel der Prüfstation signiert sind.

## Schweregrade und Meldungen

| Schweregrad | Beispiele | Zustellung |
|---|---|---|
| kritisch | neuer von außen offener Port, neue UPnP- oder manuelle Freigabe, IPv6-Gerät direkt erreichbar, unbekanntes Gerät im LAN oder Tailnet | **sofort** als Push |
| hoch / mittel / niedrig / info | UPnP an, Fernzugang, TLS-Mängel, Login über HTTP, Standard-Login-Produkte, Key-Ablauf, ACL „alles erlaubt“, Firmware | Wochenbericht (So 18:00) mit Bewertung und konkreter Maßnahme |
| Selbstüberwachung | Prüfung schlägt fehl, Prüfstation nicht erreichbar, externe Sicht älter als 26 h, IP passt nicht | **sofort**, plus Entwarnung |

Beispiel einer Sofortmeldung:
`Reachable from the internet: 32400/tcp on router v4 (http)` – „The external probe reached public IPv4 … port 32400/tcp:
Plex Media Server 1.40. Cause: UPnP mapping created by 192.168.10.45 (tv, Hersteller …, MAC …)“.

**Baseline:** Beim ersten Lauf wird alles Vorgefundene als bekannter Stand übernommen (keine Meldung), steht aber im
Erstbericht zur Durchsicht. Danach melden nur Änderungen. Eine Meldung kommt erst wieder, wenn sich der Befund erneut
ändert.

**Ein fehlender Scan sieht nie wie „alles sicher“ aus:** Ohne aktuelle externe Sicht steht der Status auf
`unknown`, der HA-Sensor `sensor.exposure_guard_external` auf `stale`, und es kommt eine Warnung. Die
HA-Automation `exposure_guard_dead_mans_switch` meldet zusätzlich, wenn der Wächter selbst ausfällt.

## Quittieren

```bash
exposure-guard findings                         # IDs anzeigen
exposure-guard ack 'map:tcp/32400' "Plex, gewollt"
exposure-guard ack 'device:aa:bb:cc:dd:ee:ff' "neues Tablet" --until 2027-01-01
exposure-guard unack 'map:tcp/32400'
exposure-guard acks                             # alle Quittierungen
```

Oder per YAML in `/opt/exposure-guard/acks/acks.yaml` (Platzhalter `*` erlaubt, Format siehe
[config/acks.example.yaml](config/acks.example.yaml)). Eine Quittierung gilt für den Zustand, in dem sie gegeben
wurde (Fingerabdruck): Ändert sich der Befund (anderes Gerät, anderer Dienst, andere Herkunft), meldet er sich wieder.

## Installation

### 1. Wächter (Pi mit Docker)

```bash
git clone https://github.com/Zedas030/exposure-guard && cd exposure-guard
sudo ./scripts/install.sh                  # nach /opt/exposure-guard, baut und startet den Container
sudoedit /opt/exposure-guard/config/config.yaml
sudoedit /opt/exposure-guard/.env          # Secrets, siehe unten
cd /opt/exposure-guard && sudo docker compose up -d --force-recreate
```

Das Installationsskript gibt die Werte für die Prüfstation aus (SSH-Public-Key des Wächters und seine zwei
öffentlichen Kryptoschlüssel; erneut anzeigen mit `exposure-guard keys`).

### 2. Externe Prüfstation (VPS)

Jeder kleine VPS mit öffentlicher IPv4 **und IPv6** reicht (1 vCPU, 512 MB). Debian 12/13.

```bash
scp -r probe root@203.0.113.20:/root/
ssh root@203.0.113.20 'cd /root/probe && GUARD_SSH_PUBKEY="ssh-ed25519 AAAA... exposure-guard" \
  GUARD_VERIFY_KEY="..." GUARD_BOX_KEY="..." bash install-probe.sh'
```

Das Skript richtet ein: nmap und python3-nacl, Benutzer `probe` (sein einziger SSH-Schlüssel darf nur das Gate
ausführen: `command=…,restrict`), Scan-Timer (täglich 05:00, samstags alle TCP-Ports), nftables (eingehend nur SSH),
sshd nur mit Schlüssel, automatische Sicherheitsupdates. Es gibt `PROBE_VERIFY_KEY=…` aus – in
`external.probe_verify_key` eintragen und den Host-Key festnageln:

```bash
sudo sh -c 'ssh-keyscan -t ed25519 203.0.113.20 >> /opt/exposure-guard/data/ssh/known_hosts'
exposure-guard run external
```

### 3. Home Assistant

- Langzeit-Token → `HA_TOKEN` in `.env`; notify-Dienst → `homeassistant.notify_service`.
- `ha/automation.yaml` importieren (Dead-Man's-Switch).
- Sensoren (legt der Wächter selbst an): `sensor.exposure_guard` (ok / attention / degraded / unknown / alert),
  `sensor.exposure_guard_external`, `sensor.exposure_guard_open_findings`, `sensor.exposure_guard_last_external_scan`.

### 4. Prometheus und Grafana

```yaml
  - job_name: exposure_guard
    scrape_interval: 60s
    static_configs:
      - targets: ['localhost:8103']
```

Dashboard: `grafana/exposure-guard.json` (uid `exposure-guard`).

## Secrets (Zugangsdaten)

Alle Secrets stehen ausschließlich in **`/opt/exposure-guard/.env`** (Rechte 600, Besitzer root, nur Docker Compose
liest sie). In `config.yaml` stehen nur die *Namen* der Variablen. Vorlage: [.env.example](.env.example).

| Variable | Was | Anlegen / ändern (rotieren) |
|---|---|---|
| `FRITZ_USER`, `FRITZ_PASSWORD` | eigener FRITZ!Box-Benutzer | FRITZ!Box → System → FRITZ!Box-Benutzer → Benutzer hinzufügen. **Nur das Recht „FRITZ!Box Einstellungen“** (ohne dieses Recht verweigert TR-064 die Abfrage von Portfreigaben, Fernzugang und MyFRITZ!; eine Nur-Lese-Rolle bietet AVM nicht). „Zugang auch aus dem Internet erlaubt“ **aus**. Rotieren: Passwort dort ändern, in `.env` eintragen, `docker compose up -d --force-recreate`. |
| `HA_TOKEN` | Home-Assistant-Langzeit-Token | HA-Profil → Sicherheit → Langlebige Zugangstoken. Rotieren: neues Token anlegen, in `.env` eintragen, Container neu erstellen, altes Token löschen. |
| `TS_OAUTH_CLIENT_ID`, `TS_OAUTH_CLIENT_SECRET` | Tailscale-OAuth-Client (optional, für die ACL-Prüfung) | Admin-Konsole → Settings → OAuth clients, Scopes **`policy_file:read` und `devices:core:read`** (nur lesend). Rotieren: neuen Client anlegen, in `.env` eintragen, alten widerrufen. |

Schlüssel, die das Tool selbst erzeugt:

| Datei | Zweck | Rotieren |
|---|---|---|
| `data/ssh/id_ed25519` | SSH-Schlüssel des Wächters für die Prüfstation | löschen, `install.sh` erneut ausführen, neuen Public Key bei `install-probe.sh` angeben |
| `data/keys/guard_sign.key`, `guard_box.key` | signiert Ziellisten / entschlüsselt Ergebnisse | beide löschen, Container neu starten, `install-probe.sh` mit den neuen Werten aus `exposure-guard keys` erneut ausführen |
| Prüfstation: `/etc/exposure-probe/probe_sign.key` | signiert Ergebnisse | löschen, `install-probe.sh` erneut ausführen, `external.probe_verify_key` anpassen |

## Konfiguration

`config/config.yaml` ist vollständig kommentiert ([Beispiel](config/config.example.yaml)): LAN-Bereich,
Router-Adresse, Prüfstation, Scanraten, Wochentag/Uhrzeit und Ausnahmen des LAN-Webchecks, Tailscale, Home Assistant,
Zeitplan. Nach Änderungen: `docker compose restart exposure-guard`.

## Befehle

```
exposure-guard status [--json]          Gesamtzustand und Zustand jeder Prüfung
exposure-guard findings [--all] [-v] [--severity medium]
exposure-guard ack <id> "Begründung" [--until JJJJ-MM-TT] | unack <id> | acks
exposure-guard run local|external|lan-web|tailscale|all
exposure-guard report initial|weekly [--notify]
exposure-guard scan-now                 sofortiger Tagesscan der Prüfstation (höchstens 1x pro Stunde)
exposure-guard keys | test-notify
```

Weboberfläche: `http://<pi>:8103` (nur lesend), JSON unter `/api/status`, `/api/findings`, `/api/devices`,
Metriken unter `/metrics`, Berichte unter `/reports/…`.

## Sicherheit und Rahmen

- Ziele: nur die eigenen öffentlichen Adressen des Routers und globale IPv6-Adressen, die im eigenen LAN gesehen wurden.
- LAN: keine SYN- oder Versionsscans gegen IoT-Geräte; einmal pro Woche ein TCP-Connect-Scan mit `-T2` und
  Paketratenbremse (20/s) über eine kurze Liste von Web-Ports, dann ein GET der Startseite und höchstens drei
  TLS-Handshakes je Port. Es werden keine Zugangsdaten gesendet.
- IPv6-Freigaben lassen sich aus der FRITZ!Box nicht auslesen; sie werden durch den externen Scan aller globalen
  IPv6-Adressen gefunden.
- Container: eigener Benutzer ohne Rechte, alle Capabilities entzogen, Dateisystem nur lesbar, 256 MB / 0,5 CPU,
  Log-Rotation (3 × 10 MB), Neustart `unless-stopped`.

## Tests

```bash
docker build --target test -t exposure-guard:test . && docker run --rm exposure-guard:test   # Unit-Tests
python3 tests/e2e/run_e2e.py                                                                 # End-to-End (Docker)
```

Der End-to-End-Test startet den echten Wächter-Container und die echte Prüfstation (eingerichtet mit
`install-probe.sh`, SSH, verschlüsselte Ergebnisse, nmap) gegen eine nachgebaute FRITZ!Box, einen nachgebauten Home
Assistant und einen Zielrechner und prüft: Baseline, UPnP-Freigabe → Meldung intern und extern, neues Gerät,
LAN-Webcheck, Quittieren und erneute Meldung nach Änderung, Ausfall der Prüfstation → Warnung und Status `unknown`,
Entwarnung, keine Schreibaktion an der FRITZ!Box.

## Deinstallieren

```bash
cd /opt/exposure-guard && sudo docker compose down && sudo rm -rf /opt/exposure-guard /usr/local/bin/exposure-guard
```
Auf dem VPS: `systemctl disable --now exposure-probe-scan.timer exposure-probe-request.path`, `userdel -r probe`,
`rm -rf /opt/exposure-probe /etc/exposure-probe` – oder einfach den VPS löschen.

## Lizenz

MIT
