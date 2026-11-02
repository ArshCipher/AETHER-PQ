#!/usr/bin/env bash
# deploy_uav.sh — Production Hardware UAV Node Deployment & Auto-Start Script
# Hardware Target Compatibility: Raspberry Pi 4/5, NVIDIA Jetson, Ubuntu UAVs
set -euo pipefail

UAV_ID="${1:-1}"
UAV_IP="${2:-192.168.171.1}"
UAV_PORT="${3:-28003}"
GCS_IP="${4:-192.168.1.100}"
CA_IP="${5:-$GCS_IP}"

echo "=========================================================="
echo " Deploying AETHER-PQ UAV Node ID: $UAV_ID"
echo " Mesh IP: $UAV_IP:$UAV_PORT"
echo " GCS/CA Host IP: $GCS_IP"
echo " Architecture: $(uname -m)"
echo "=========================================================="

CONFIG_DIR="/etc/aether"
CERTS_DIR="/etc/aether/certs/uav"
BIN_DEST="/usr/local/bin/uav_pqc_uav_node"

# 1. Create aether user & sandbox
sudo useradd -r -s /bin/false aether 2>/dev/null || true
export AETHER_UAV_QUERY_ROOT="$HOME/uav_media"
mkdir -p "$AETHER_UAV_QUERY_ROOT" "$CONFIG_DIR" "$CERTS_DIR" /var/log/aether

# 2. Check or install BATMAN-adv module & interface setup
if command -v batctl &>/dev/null; then
    echo "Configuring BATMAN-adv mesh interface bat0..."
    sudo modprobe batman-adv || true
    # Use default physical interface eth0 or wlan0 if present
    PHY_IF=$(ip route show default | awk '/default/ {print $5}' | head -n 1)
    PHY_IF=${PHY_IF:-eth0}
    sudo ip link set dev "$PHY_IF" up || true
    sudo batctl if add "$PHY_IF" 2>/dev/null || true
    sudo ip link set dev bat0 up 2>/dev/null || true
    sudo ip addr add "$UAV_IP/24" dev bat0 2>/dev/null || true
    echo "✓ BATMAN-adv mesh interface bat0 active ($UAV_IP)."
fi

# 3. Create or update uav.yaml configuration
sudo bash -c "cat <<EOF > $CONFIG_DIR/uav.yaml
node_type: 'uav'
node_id: $UAV_ID
mesh_interface: 'bat0'
mesh_ip: '$UAV_IP'
node_port: $UAV_PORT
ca_endpoint: '$CA_IP:28000'
gcs_endpoint: '$GCS_IP:28001'
certs_dir: '$CERTS_DIR'
telemetry:
  enabled: true
  interval_ms: 1000
log_level: 'INFO'
EOF"

# 4. Verify binary existence
if [ -f "./build/tools/process_sim/uav_pqc_uav_node" ]; then
    sudo cp ./build/tools/process_sim/uav_pqc_uav_node "$BIN_DEST"
elif [ -f "./uav_pqc_uav_node" ]; then
    sudo cp ./uav_pqc_uav_node "$BIN_DEST"
elif [ -f "$BIN_DEST" ]; then
    echo "Using existing binary at $BIN_DEST"
else
    echo "❌ ERROR: 'uav_pqc_uav_node' binary not found!"
    exit 1
fi
sudo chmod +x "$BIN_DEST"

# 5. Set secure permissions
sudo chown -R aether:aether "$CONFIG_DIR" "$CERTS_DIR" /var/log/aether
sudo chmod 700 "$CERTS_DIR"

# 6. Install & Enable Systemd Service if active
if command -v systemctl &>/dev/null && systemctl is-system-running &>/dev/null; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [ -f "$SCRIPT_DIR/systemd/aether-uav.service" ]; then
        sudo cp "$SCRIPT_DIR/systemd/aether-uav.service" /etc/systemd/system/aether-uav.service
        sudo systemctl daemon-reload
        sudo systemctl enable aether-uav
        sudo systemctl restart aether-uav
        echo "✓ systemd service aether-uav enabled and started."
    fi
else
    echo "🚀 Starting UAV node process manually..."
    sudo -u aether nohup "$BIN_DEST" \
        --id "$UAV_ID" \
        --ip "0.0.0.0" \
        --port "$UAV_PORT" \
        --ca-ip "$CA_IP" \
        --ca-port 28000 \
        --gcs-ip "$GCS_IP" \
        --gcs-port 28001 > /var/log/aether/uav.log 2>&1 &
fi

echo "=========================================================="
echo "✓ UAV $UAV_ID Deployment Complete!"
echo "  Status check: systemctl status aether-uav OR aether status"
echo "=========================================================="
