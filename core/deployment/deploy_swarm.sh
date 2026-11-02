#!/usr/bin/env bash
# deploy_swarm.sh — One-Command Fleet & Swarm Deployer
# Automatically deploys CA, GCS, and a fleet of UAV nodes locally or to a list of IP hosts over SSH.
set -euo pipefail

SWARM_SIZE="${1:-4}"
GCS_HOST_IP="${2:-127.0.0.1}"

echo "=========================================================="
echo " AETHER-PQ Swarm Fleet Deployment"
echo " Swarm Size: $SWARM_SIZE UAVs"
echo " Target GCS Host: $GCS_HOST_IP"
echo "=========================================================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 1. Deploy CA
echo "Step 1/3: Deploying CA..."
bash "$SCRIPT_DIR/deploy_ca.sh"

# 2. Deploy GCS
echo "Step 2/3: Deploying GCS..."
bash "$SCRIPT_DIR/deploy_gcs.sh"

# 3. Deploy UAV Fleet
echo "Step 3/3: Deploying UAV Swarm Fleet..."
for i in $(seq 1 "$SWARM_SIZE"); do
    UAV_IP="192.168.171.$i"
    UAV_PORT=$((28002 + i))
    echo "  -> Deploying UAV-$i ($UAV_IP:$UAV_PORT)..."
    bash "$SCRIPT_DIR/deploy_uav.sh" "$i" "$UAV_IP" "$UAV_PORT" "$GCS_HOST_IP"
done

echo "=========================================================="
echo "✓ Swarm Fleet Deployment Complete!"
echo "  Verify status with: aether status"
echo "=========================================================="
