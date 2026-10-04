#!/bin/sh
# Varro agent installer (Linux + macOS).
#
#   curl -sSL __VARRO_SERVER__/install.sh | sudo VARRO_TOKEN=<org-enrollment-token> sh
#
# Downloads the varro binary from the latest GitHub release, verifies it, and
# installs a service (systemd on Linux, launchd on macOS) enrolled against
# this collector.
set -eu

REPO="SOC-Foundry/Varro"
SERVER="${VARRO_SERVER:-__VARRO_SERVER__}"
BIN=/usr/local/bin/varro

fail() { echo "varro-install: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || fail "must run as root (pipe to 'sudo sh')"
[ -n "${VARRO_TOKEN:-}" ] || fail "set VARRO_TOKEN to your org's enrollment token"
command -v curl >/dev/null 2>&1 || fail "curl is required"

case "$(uname -s)" in
  Linux)  OS=linux
          command -v systemctl >/dev/null 2>&1 || fail "systemd is required on Linux" ;;
  Darwin) OS=darwin ;;
  *) fail "unsupported OS: $(uname -s) (for Windows use install.ps1)" ;;
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

# sha256sum on Linux, shasum on macOS.
if command -v sha256sum >/dev/null 2>&1; then SHA="sha256sum"; else SHA="shasum -a 256"; fi
(cd "$TMP" && grep " $ASSET\$" checksums.txt | sed "s|$ASSET|varro|" | $SHA -c -) \
  || fail "checksum verification failed"

mkdir -p "$(dirname $BIN)"
install -m 755 "$TMP/varro" "$BIN"
echo "installed $("$BIN" --version)"

if [ "$OS" = "linux" ]; then
  UNIT=/etc/systemd/system/varro-agent.service
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
  systemctl enable varro-agent
  systemctl restart varro-agent   # restart (not just enable --now) so reinstall picks up a new binary
  sleep 2
  systemctl is-active --quiet varro-agent || fail "service failed to start; see: journalctl -u varro-agent"
  echo
  echo "varro agent is running and enrolling with $SERVER"
  echo "  status:  systemctl status varro-agent"
  echo "  logs:    journalctl -u varro-agent -f"
else
  STATE="/Library/Application Support/Varro"
  PLIST=/Library/LaunchDaemons/com.socfoundry.varro-agent.plist
  mkdir -p "$STATE"
  launchctl bootout system/com.socfoundry.varro-agent 2>/dev/null || true
  cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.socfoundry.varro-agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>$BIN</string>
    <string>agent</string>
    <string>--server</string><string>$SERVER</string>
    <string>--state-dir</string><string>$STATE</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict><key>VARRO_TOKEN</key><string>$VARRO_TOKEN</string></dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/var/log/varro-agent.log</string>
  <key>StandardErrorPath</key><string>/var/log/varro-agent.log</string>
</dict>
</plist>
EOF
  chmod 600 "$PLIST"
  launchctl bootstrap system "$PLIST" || fail "launchctl bootstrap failed"
  sleep 2
  launchctl print system/com.socfoundry.varro-agent >/dev/null 2>&1 \
    || fail "daemon failed to start; see /var/log/varro-agent.log"
  echo
  echo "varro agent is running and enrolling with $SERVER"
  echo "  status:  sudo launchctl print system/com.socfoundry.varro-agent"
  echo "  logs:    tail -f /var/log/varro-agent.log"
fi
