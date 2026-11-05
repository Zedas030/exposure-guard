#!/usr/bin/env bash
# Exposure Guard - install the external probe on a fresh Debian 12/13 VPS (run as root):
#   GUARD_SSH_PUBKEY="ssh-ed25519 AAAA... exposure-guard" \
#   GUARD_VERIFY_KEY="<base64>" GUARD_BOX_KEY="<base64>" ./install-probe.sh
# Values come from `sudo exposure-guard keys` and data/ssh/id_ed25519.pub on the guard host.
# Re-running updates the code and keys and keeps state.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
: "${GUARD_SSH_PUBKEY:?missing}" "${GUARD_VERIFY_KEY:?missing}" "${GUARD_BOX_KEY:?missing}"
ALLOW_PRIVATE="${ALLOW_PRIVATE_TARGETS:-false}"   # only for the end-to-end test
TZ_NAME="${PROBE_TZ:-Europe/Berlin}"
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }

export DEBIAN_FRONTEND=noninteractive
if [ "${SKIP_APT:-0}" != 1 ]; then
  apt-get update -q
  apt-get install -y -q --no-install-recommends python3 python3-nacl nmap iproute2 openssh-server nftables \
      unattended-upgrades ca-certificates tzdata
fi
timedatectl set-timezone "$TZ_NAME" 2>/dev/null || ln -sf "/usr/share/zoneinfo/$TZ_NAME" /etc/localtime

id probe >/dev/null 2>&1 || useradd --system --create-home --home-dir /var/lib/exposure-probe --shell /bin/sh probe
usermod -p '*' probe   # no password login, but not 'locked' (sshd would refuse the key)
install -d -m 750 -o probe -g probe /var/lib/exposure-probe /var/lib/exposure-probe/results /var/lib/exposure-probe/work
install -d -m 750 -o root -g probe /etc/exposure-probe /opt/exposure-probe
install -m 755 "$HERE/exposure_probe.py" /opt/exposure-probe/exposure_probe.py
cat > /usr/local/bin/exposure-probe <<'EOF'
#!/bin/sh
exec /usr/bin/python3 -I /opt/exposure-probe/exposure_probe.py "$@"
EOF
chmod 755 /usr/local/bin/exposure-probe

cat > /etc/exposure-probe/probe.json <<EOF
{"guard_verify_key": "$GUARD_VERIFY_KEY", "guard_box_public_key": "$GUARD_BOX_KEY", "allow_private_targets": $ALLOW_PRIVATE}
EOF
chown root:probe /etc/exposure-probe/probe.json && chmod 640 /etc/exposure-probe/probe.json
if [ ! -f /etc/exposure-probe/probe_sign.key ]; then
  EXPOSURE_PROBE_KEY=/etc/exposure-probe/probe_sign.key /usr/local/bin/exposure-probe init >/dev/null
fi
chown probe:probe /etc/exposure-probe/probe_sign.key && chmod 600 /etc/exposure-probe/probe_sign.key

# guard's key may ONLY run the gate - no shell, no forwarding
install -d -m 700 -o probe -g probe /var/lib/exposure-probe/.ssh
echo "command=\"/usr/local/bin/exposure-probe gate\",restrict $GUARD_SSH_PUBKEY" > /var/lib/exposure-probe/.ssh/authorized_keys
chown probe:probe /var/lib/exposure-probe/.ssh/authorized_keys && chmod 600 /var/lib/exposure-probe/.ssh/authorized_keys

# sshd: keys only
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/10-exposure-probe.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
X11Forwarding no
MaxAuthTries 3
EOF

if [ -d /run/systemd/system ]; then
  install -m 644 "$HERE/systemd/"*.service "$HERE/systemd/"*.timer "$HERE/systemd/"*.path /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable --now exposure-probe-scan.timer exposure-probe-request.path
  systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
  # nothing besides sshd needs to listen (Oracle/Ubuntu images ship rpcbind)
  systemctl disable --now rpcbind.socket rpcbind.service 2>/dev/null || true
  if [ "${SKIP_FIREWALL:-0}" != 1 ]; then
    if systemctl is-enabled netfilter-persistent >/dev/null 2>&1 && [ -s /etc/iptables/rules.v4 ]; then
      # Provider image with its own iptables rules (e.g. Oracle Cloud: they also protect the metadata service).
      # Keep IPv4 as shipped, add the same policy for IPv6: only SSH and ICMPv6 inbound.
      cp -n /etc/iptables/rules.v6 /etc/iptables/rules.v6.bak-exposure-probe 2>/dev/null || true
      cat > /etc/iptables/rules.v6 <<'EOF'
# Exposure Guard probe: IPv6 inbound only SSH (+ ICMPv6 for neighbour discovery / PMTU)
*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -p ipv6-icmp -j ACCEPT
-A INPUT -p tcp -m conntrack --ctstate NEW -m tcp --dport 22 -j ACCEPT
-A INPUT -j REJECT --reject-with icmp6-adm-prohibited
COMMIT
EOF
      ip6tables-restore < /etc/iptables/rules.v6
    else
      install -m 644 "$HERE/nftables.conf" /etc/nftables.conf
      systemctl enable nftables && nft -c -f /etc/nftables.conf && systemctl restart nftables
    fi
  fi
  systemctl enable --now unattended-upgrades 2>/dev/null || true
fi
echo "PROBE_VERIFY_KEY=$(EXPOSURE_PROBE_KEY=/etc/exposure-probe/probe_sign.key /usr/local/bin/exposure-probe init)"
echo "Put this value into external.probe_verify_key of the guard's config.yaml."
