#!/usr/bin/env bash
# deploy_ca.sh — One-Command Deployment Script for AETHER-PQ Certificate Authority (CA)
set -euo pipefail

echo "=========================================================="
echo " AETHER-PQ Certificate Authority (CA) Deployment"
echo "=========================================================="

CONFIG_DIR="/etc/aether"
CERTS_DIR="/etc/aether/certs/ca"
BIN_DEST="/usr/local/bin/uav_pqc_ca_node"
SYSTEMD_DEST="/etc/systemd/system/aether-ca.service"

# 1. Create aether user & directories
sudo useradd -r -s /bin/false aether 2>/dev/null || true
sudo mkdir -p "$CONFIG_DIR" "$CERTS_DIR" /var/log/aether

# 2. Install Configuration Template if missing
if [ ! -f "$CONFIG_DIR/ca.yaml" ]; then
    echo "Installing default ca.yaml to $CONFIG_DIR/ca.yaml..."
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    sudo cp "$SCRIPT_DIR/../config/templates/ca.yaml" "$CONFIG_DIR/ca.yaml"
fi

# 3. Verify binary existence or build
if [ -f "./build/tools/process_sim/uav_pqc_ca_node" ]; then
    sudo cp ./build/tools/process_sim/uav_pqc_ca_node "$BIN_DEST"
elif [ -f "./uav_pqc_ca_node" ]; then
    sudo cp ./uav_pqc_ca_node "$BIN_DEST"
elif [ -f "$BIN_DEST" ]; then
    echo "Using existing binary at $BIN_DEST"
else
    echo "❌ ERROR: CA binary not found! Please build or provide uav_pqc_ca_node."
    exit 1
fi
sudo chmod +x "$BIN_DEST"

# 4. Set secure permissions
sudo chown -R aether:aether "$CONFIG_DIR" "$CERTS_DIR" /var/log/aether
sudo chmod 700 "$CERTS_DIR"

# 5. Install & Enable Systemd Service if systemd is active
if command -v systemctl &>/dev/null && systemctl is-system-running &>/dev/null; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    sudo cp "$SCRIPT_DIR/systemd/aether-ca.service" "$SYSTEMD_DEST"
    sudo systemctl daemon-reload
    sudo systemctl enable aether-ca
    sudo systemctl restart aether-ca
    echo "✓ systemd service aether-ca enabled and started."
else
    echo "ℹ️ Systemd not active. Starting CA manually in background..."
    sudo -u aether nohup "$BIN_DEST" --config "$CONFIG_DIR/ca.yaml" > /var/log/aether/ca.log 2>&1 &
fi

echo "=========================================================="
echo "✓ CA Deployment Complete!"
echo "  Status check: systemctl status aether-ca OR aether status"
echo "=========================================================="
