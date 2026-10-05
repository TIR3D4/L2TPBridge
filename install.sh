#!/usr/bin/env bash
# Install the independent L2TPBridge manager on Debian/Ubuntu + systemd.
set -Eeuo pipefail
[[ "$EUID" -eq 0 ]] || { echo 'Run: sudo bash install.sh'; exit 1; }
[[ -d /run/systemd/system ]] || { echo 'A running systemd Linux host is required.'; exit 1; }
command -v apt-get >/dev/null || { echo 'Supported OS: Debian/Ubuntu (apt).'; exit 1; }
source_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "$source_dir/l2tp_bridge.py" ]] || { echo 'Keep install.sh and l2tp_bridge.py in the same folder.'; exit 1; }
if [[ -f /etc/l2tpbridge/state.json ]]; then
  echo 'Already configured. Open: sudo l2tpbridge'
  exit 0
fi
for unit in l2tpbridge-tunnel.service l2tpbridge-xray.service; do
  if [[ -f "/etc/systemd/system/$unit" ]]; then
    echo "Reserved unit already exists: $unit. Inspect it before installation."
    exit 1
  fi
done
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y python3 iproute2 iputils-ping kmod ca-certificates
install -d -m 755 /opt/l2tpbridge
install -d -m 700 /etc/l2tpbridge
install -m 755 "$source_dir/l2tp_bridge.py" /opt/l2tpbridge/l2tp_bridge.py
cat > /usr/local/bin/l2tpbridge <<'WRAPPER'
#!/usr/bin/env bash
exec /usr/bin/python3 /opt/l2tpbridge/l2tp_bridge.py "$@"
WRAPPER
chmod 755 /usr/local/bin/l2tpbridge
echo 'Installed. Opening interactive menu...'
exec /usr/local/bin/l2tpbridge
