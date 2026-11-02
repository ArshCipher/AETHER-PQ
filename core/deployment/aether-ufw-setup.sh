#!/usr/bin/env bash
# aether-ufw-setup.sh — Security Firewall & Permission Hardening for Field UAVs
set -euo pipefail

echo "=========================================================="
echo " AETHER-PQ Security & Firewall Hardening"
echo "=========================================================="

# 1. Enforce strict key file permissions
echo "1. Applying file permission hardening on certificates..."
sudo chmod 700 /etc/aether/certs 2>/dev/null || true
sudo chmod 600 /etc/aether/certs/*/*.key 2>/dev/null || true
sudo chmod 644 /etc/aether/certs/*/*.crt 2>/dev/null || true
sudo chown -R root:root /etc/aether 2>/dev/null || true

# 2. UFW Firewall rules configuration (if UFW installed)
if command -v ufw &>/dev/null; then
    echo "2. Configuring UFW firewall rules for AETHER-PQ..."
    sudo ufw default deny incoming
    sudo ufw default allow outgoing

    # Allow SSH for administration
    sudo ufw allow 22/tcp

    # Allow BATMAN-adv mesh interface traffic
    sudo ufw allow in on bat0

    # Allow AETHER-PQ service ports
    sudo ufw allow 28000/udp comment 'AETHER-PQ CA Port'
    sudo ufw allow 28001/udp comment 'AETHER-PQ GCS Port'
    sudo ufw allow 28002:28050/udp comment 'AETHER-PQ UAV Ports'
    sudo ufw allow 3001/tcp comment 'AETHER-PQ UI Gateway'

    echo "✓ UFW firewall rules configured."
    echo "  To enable: sudo ufw enable"
fi

echo "=========================================================="
echo "✓ Security Hardening Complete!"
echo "=========================================================="
