#!/bin/bash
# setup_remote_pc.sh - Runs on Mac/local host to push code and run setup on a remote Ubuntu PC
set -e

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <REMOTE_IP> [SSH_PASSWORD]"
    echo "Example: $0 192.168.171.17"
    echo "Example: $0 192.168.171.17 'Passphrase@123'"
    exit 1
fi

REMOTE_IP=$1
PASSWORD=$2
USER="${REMOTE_USER:-uav}" # Default user name on the remote Ubuntu PC

echo "=========================================================="
echo "Preparing deployment for Ubuntu PC at $REMOTE_IP"
echo "=========================================================="

# 1. Generate local clean tarball
echo "1. Creating source package from local workspace..."
cd /Users/arsh/Documents/D2D
tar --exclude='build' --exclude='.git' --exclude='*.pcap' --exclude='*.log' -czf uav_pqc_source.tar.gz uav_pqc

# 2. Transfer package to target remote Ubuntu PC
if [ -n "$PASSWORD" ]; then
    if ! command -v sshpass &> /dev/null; then
        echo "sshpass not found. Installing via Homebrew..."
        brew install hudochenkov/sshpass/sshpass
    fi
    
    echo "2. Transferring source package to $REMOTE_IP..."
    sshpass -p "$PASSWORD" scp -o StrictHostKeyChecking=no uav_pqc_source.tar.gz "$USER@$REMOTE_IP:~/"
    
    echo "3. Triggering dependency installation and native compile on target..."
    sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no -t "$USER@$REMOTE_IP" \
        "mkdir -p ~/UAV && rm -rf ~/UAV/uav_pqc && tar -xzf ~/uav_pqc_source.tar.gz -C ~/UAV/ && chmod +x ~/UAV/uav_pqc/deployment/setup_dependencies.sh && ~/UAV/uav_pqc/deployment/setup_dependencies.sh"
else
    echo "2. Transferring source package to $REMOTE_IP (using SSH keys)..."
    scp -o StrictHostKeyChecking=no uav_pqc_source.tar.gz "$USER@$REMOTE_IP:~/"
    
    echo "3. Triggering dependency installation and native compile on target (using SSH keys)..."
    ssh -o StrictHostKeyChecking=no -t "$USER@$REMOTE_IP" \
        "mkdir -p ~/UAV && rm -rf ~/UAV/uav_pqc && tar -xzf ~/uav_pqc_source.tar.gz -C ~/UAV/ && chmod +x ~/UAV/uav_pqc/deployment/setup_dependencies.sh && ~/UAV/uav_pqc/deployment/setup_dependencies.sh"
fi

echo "=========================================================="
echo "✓ Success! setup_remote_pc execution completed for $REMOTE_IP."
echo "=========================================================="
