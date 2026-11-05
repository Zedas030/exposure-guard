#!/usr/bin/env bash
# Exposure Guard - enter or rotate secrets interactively (input is hidden), then restart the container.
#   sudo /opt/exposure-guard/scripts/set-secrets.sh
# Press Enter on a prompt to keep the current value.
set -euo pipefail
DIR="${EXPOSURE_GUARD_DIR:-/opt/exposure-guard}"
ENV="$DIR/.env"
[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }
touch "$ENV" && chmod 600 "$ENV"

current() { grep -E "^$1=" "$ENV" | tail -1 | cut -d= -f2- || true; }
ask() {
  local name="$1" text="$2" hidden="$3" value cur
  cur="$(current "$name")"
  if [ "$hidden" = 1 ]; then
    read -r -s -p "$text [${cur:+set, Enter = keep}]: " value; echo
  else
    read -r -p "$text [${cur:-empty}]: " value
  fi
  [ -n "$value" ] || value="$cur"
  local tmp; tmp="$(mktemp)"
  grep -vE "^$name=" "$ENV" > "$tmp" || true
  printf '%s=%s\n' "$name" "$value" >> "$tmp"
  install -m 600 -o root -g root "$tmp" "$ENV"; rm -f "$tmp"
}

echo "Exposure Guard secrets -> $ENV"
ask FRITZ_USER "FRITZ!Box user (only right 'FRITZ!Box settings')" 0
ask FRITZ_PASSWORD "FRITZ!Box password" 1
ask HA_TOKEN "Home Assistant long-lived token" 1
ask TS_OAUTH_CLIENT_ID "Tailscale OAuth client ID (optional)" 0
ask TS_OAUTH_CLIENT_SECRET "Tailscale OAuth client secret (optional)" 1

cd "$DIR" && docker compose up -d --force-recreate >/dev/null
echo "Restarted. Checking in 20 s ..."
sleep 20
docker exec exposure-guard exposure-guard run local >/dev/null 2>&1 || true
docker exec exposure-guard exposure-guard run tailscale >/dev/null 2>&1 || true
docker exec exposure-guard exposure-guard status || true
docker exec exposure-guard exposure-guard test-notify || true
