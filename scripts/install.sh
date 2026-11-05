#!/usr/bin/env bash
# Exposure Guard - install/update on the host (run as root from the source checkout):
#   sudo ./scripts/install.sh [/opt/exposure-guard]
# Keeps existing config/config.yaml, acks/acks.yaml, .env and data/.
set -euo pipefail
SRC="$(cd "$(dirname "$0")/.." && pwd)"
DST="${1:-/opt/exposure-guard}"
UID_GUARD=10001

[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
command -v docker >/dev/null || { echo "docker missing"; exit 1; }

install -d -m 755 "$DST" "$DST/config"
install -d -m 775 -o "$UID_GUARD" -g "$UID_GUARD" "$DST/acks"
install -d -m 750 -o "$UID_GUARD" -g "$UID_GUARD" "$DST/data" "$DST/data/ssh" "$DST/data/keys" "$DST/data/reports"
chmod 700 "$DST/data/ssh" "$DST/data/keys"

# application files (code is baked into the image; the copy here is the build context)
rm -rf "$DST/exposure_guard" "$DST/probe"
cp -r "$SRC/exposure_guard" "$SRC/probe" "$DST/"
find "$DST/exposure_guard" -name __pycache__ -prune -exec rm -rf {} +
install -m 644 "$SRC/Dockerfile" "$SRC/docker-compose.yml" "$SRC/pyproject.toml" "$SRC/README.md" "$SRC/LICENSE" "$DST/"
install -m 644 "$SRC/config/config.example.yaml" "$SRC/config/acks.example.yaml" "$DST/config/"
mkdir -p "$DST/tests" && cp -r "$SRC/tests/unit" "$SRC/tests/fakes" "$DST/tests/"

[ -f "$DST/config/config.yaml" ] || install -m 644 "$SRC/config/config.example.yaml" "$DST/config/config.yaml"
[ -f "$DST/acks/acks.yaml" ] || install -m 664 -o "$UID_GUARD" -g "$UID_GUARD" /dev/stdin "$DST/acks/acks.yaml" <<'EOF'
# Exposure Guard - acknowledged findings (see config/acks.example.yaml for the format)
acks: []
EOF
if [ ! -f "$DST/.env" ]; then
  install -m 600 "$SRC/.env.example" "$DST/.env"
  echo ">> $DST/.env created from the example - enter the secrets there (chmod 600 stays)."
fi
chmod 600 "$DST/.env"

# SSH key the guard uses to pull results from the probe (forced command on the probe side)
if [ ! -f "$DST/data/ssh/id_ed25519" ]; then
  ssh-keygen -q -t ed25519 -N "" -C "exposure-guard" -f "$DST/data/ssh/id_ed25519"
fi
touch "$DST/data/ssh/known_hosts"
chown -R "$UID_GUARD:$UID_GUARD" "$DST/data/ssh" "$DST/data/keys"
chmod 600 "$DST/data/ssh/id_ed25519"

# CLI wrapper on the host
cat > /usr/local/bin/exposure-guard <<'EOF'
#!/bin/sh
# Exposure Guard CLI (runs inside the container). Example: exposure-guard status
if [ -t 0 ] && [ -t 1 ]; then exec docker exec -it -e EG_USER="${SUDO_USER:-$USER}" exposure-guard exposure-guard "$@"; fi
exec docker exec -i -e EG_USER="${SUDO_USER:-$USER}" exposure-guard exposure-guard "$@"
EOF
chmod 755 /usr/local/bin/exposure-guard

cd "$DST"
docker compose build --pull
docker compose up -d
sleep 5
docker exec exposure-guard exposure-guard keys >/dev/null
echo
echo "== Exposure Guard installed in $DST, UI on :8103 =="
echo "Probe setup values (public, safe to copy):"
echo "  GUARD_SSH_PUBKEY: $(cat "$DST/data/ssh/id_ed25519.pub")"
docker exec exposure-guard exposure-guard keys | sed 's/^/  /'
