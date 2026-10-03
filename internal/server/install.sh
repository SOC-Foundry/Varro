#!/bin/sh
# Varro agent installer.
#
#   curl -sSL __VARRO_SERVER__/install.sh | sudo VARRO_TOKEN=<org-enrollment-token> sh
#
# Downloads the varro binary from the latest GitHub release, installs it to
# /usr/local/bin, and starts a systemd service enrolled against this collector.
set -eu

REPO="SOC-Foundry/Varro"
SERVER="${VARRO_SERVER:-__VARRO_SERVER__}"
BIN=/usr/local/bin/varro
UNIT=/etc/systemd/system/varro-agent.service

fail() { echo "varro-install: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || fail "must run as root (pipe to 'sudo sh')"
[ -n "${VARRO_TOKEN:-}" ] || fail "set VARRO_TOKEN to your org's enrollment token"
command -v systemctl >/dev/null 2>&1 || fail "systemd is required (for macOS/Windows see the README)"
command -v curl >/dev/null 2>&1 || fail "curl is required"

case "$(uname -s)" in
  Linux) OS=linux ;;
  *) fail "this installer supports Linux; for macOS/Windows see https://github.com/$REPO" ;;
esac
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) fail "unsupported architecture: $(uname -m)" ;;
esac

ASSET="varro-$OS-$ARCH"
BASE="https://github.com/$REPO/releases/latest/download"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "downloading $ASSET from latest release..."
curl -fsSL "$BASE/$ASSET" -o "$TMP/varro" || fail "download failed — does the release exist?"
curl -fsSL "$BASE/checksums.txt" -o "$TMP/checksums.txt" || fail "checksum download failed"
(cd "$TMP" && grep " $ASSET\$" checksums.txt | sed "s|$ASSET|varro|" | sha256sum -c -) \
  || fail "checksum verification failed"

install -m 755 "$TMP/varro" "$BIN"
echo "installed $("$BIN" --version)"

cat > "$UNIT" <<EOF
[Unit]
Description=Varro telemetry agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$BIN agent --server $SERVER --state-dir /var/lib/varro-agent
Environment=VARRO_TOKEN=$VARRO_TOKEN
StateDirectory=varro-agent
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
chmod 600 "$UNIT"

systemctl daemon-reload
systemctl enable --now varro-agent
sleep 2
systemctl is-active --quiet varro-agent || fail "service failed to start; see: journalctl -u varro-agent"

echo
echo "varro agent is running and enrolling with $SERVER"
echo "  status:  systemctl status varro-agent"
echo "  logs:    journalctl -u varro-agent -f"
