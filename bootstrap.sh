#!/usr/bin/env bash
# Download the manager into a private temporary directory and launch its installer.
set -Eeuo pipefail
[[ "$EUID" -eq 0 ]] || { echo 'Run this bootstrap with sudo/root.'; exit 1; }
command -v curl >/dev/null || { echo 'Install curl first: sudo apt-get install -y curl'; exit 1; }
setup_dir="$(mktemp -d -t l2tpbridge.XXXXXXXX)"
trap 'rm -rf -- "$setup_dir"' EXIT
repo_base='https://raw.githubusercontent.com/TIR3D4/L2TPBridge/main'
for name in install.sh l2tp_bridge.py; do
  curl --fail --silent --show-error --location --retry 3 \
    --connect-timeout 15 --max-time 120 "$repo_base/$name" -o "$setup_dir/$name"
done
bash "$setup_dir/install.sh"
