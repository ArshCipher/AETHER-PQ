#!/bin/bash
# remote_deploy.sh - Runs on your Mac to copy and start the UAV node on a remote Ubuntu PC

if [ "$#" -lt 4 ]; then
    echo "Usage: $0 <UAV_ID> <UAV_IP> <UAV_PORT> <MAC_CA_GCS_IP> [SSH_PASSWORD]"
    echo "Example (passwordless SSH): $0 1 192.168.1.150 28002 192.168.1.100"
    echo "Example (with password):     $0 1 192.168.1.150 28002 192.168.1.100 'my_password'"
    exit 1
fi

UAV_ID=$1
UAV_IP=$2
UAV_PORT=$3
MAC_IP=$4
PASSWORD=$5
USER="root" # Change this to the username of the Ubuntu PC

BINARY_PATH="/Users/arsh/Documents/D2D/uav_pqc/build/tools/process_sim/uav_pqc_uav_node"
DEPLOY_SCRIPT_PATH="/Users/arsh/Documents/D2D/uav_pqc/deployment/deploy_uav.sh"

echo "=========================================================="
echo "Preparing to copy and launch UAV $UAV_ID on $UAV_IP"
echo "=========================================================="

if [ -n "$PASSWORD" ]; then
    # Using sshpass with password
    if ! command -v sshpass &> /dev/null; then
        echo "sshpass not found. Installing via Homebrew..."
        brew install hudochenkov/sshpass/sshpass
    fi
    
    echo "1. Copying binary and helper script to remote machine..."
    sshpass -p "$PASSWORD" scp -o StrictHostKeyChecking=no "$BINARY_PATH" "$DEPLOY_SCRIPT_PATH" "$USER@$UAV_IP:~/"
    
    echo "2. Launching UAV node daemon in the background..."
    sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "$USER@$UAV_IP" "nohup bash ~/deploy_uav.sh $UAV_ID $UAV_IP $UAV_PORT $MAC_IP > ~/uav_node.log 2>&1 &"
else
    # Passwordless SSH keys
    echo "1. Copying binary and helper script to remote machine..."
    scp -o StrictHostKeyChecking=no "$BINARY_PATH" "$DEPLOY_SCRIPT_PATH" "$USER@$UAV_IP:~/"
    
    echo "2. Launching UAV node daemon in the background..."
    ssh -o StrictHostKeyChecking=no "$USER@$UAV_IP" "nohup bash ~/deploy_uav.sh $UAV_ID $UAV_IP $UAV_PORT $MAC_IP > ~/uav_node.log 2>&1 &"
fi

echo "=========================================================="
echo "✓ Success! UAV $UAV_ID started."
echo "Remote Log File: ~/uav_node.log on $UAV_IP"
echo "=========================================================="
