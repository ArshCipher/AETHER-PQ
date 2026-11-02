#!/usr/bin/env bash
# Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

# Multi-process Simulation Launcher Script

set -e

# Configurable defaults
NUM_UAVS=3
BIN_DIR="./build/tools/process_sim"
LOG_DIR="./process_logs"

# Print usage
usage() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -n, --uavs <num>   Number of UAV processes to launch (default: 3, max: 1000)"
    echo "  -h, --help         Show this help message"
    exit 1
}

# Parse options
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -n|--uavs) NUM_UAVS="$2"; shift ;;
        -h|--help) usage ;;
        *) echo "Unknown parameter: $1"; usage ;;
    esac
    shift
done

echo "===================================================="
echo "Starting Multi-Process UAV Network Simulation"
echo "  Swarm Size   : ${NUM_UAVS} UAV(s)"
echo "  CA Port      : 28000"
echo "  GCS Port     : 28001"
echo "  UAV Ports    : 28003 to $((28002 + NUM_UAVS))"
echo "  Log Directory: ${LOG_DIR}"
echo "===================================================="

# Ensure executables exist
if [[ ! -f "${BIN_DIR}/uav_pqc_ca_node" ]] || \
   [[ ! -f "${BIN_DIR}/uav_pqc_gcs_node" ]] || \
   [[ ! -f "${BIN_DIR}/uav_pqc_uav_node" ]]; then
    echo "Error: Simulation binaries not found! Make sure to compile the project first."
    exit 1
fi

# Setup log directory
mkdir -p "${LOG_DIR}"
rm -f "${LOG_DIR}"/*.log

# Array to track background process IDs
PIDS=()

# Cleanup hook on script termination
cleanup() {
    echo ""
    echo "===================================================="
    echo "Cleaning up simulated processes..."
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            echo "Killing process $pid"
            kill -9 "$pid" 2>/dev/null
        fi
    done
    echo "All processes terminated cleanly."
    echo "===================================================="
    exit 0
}

# Register traps
trap cleanup SIGINT SIGTERM EXIT

# 1. Spawn CA node
echo "[Launcher] Spawning CA node process..."
"${BIN_DIR}/uav_pqc_ca_node" > "${LOG_DIR}/ca.log" 2>&1 &
CA_PID=$!
PIDS+=($CA_PID)
sleep 1

# 2. Spawn GCS node
echo "[Launcher] Spawning GCS node process..."
"${BIN_DIR}/uav_pqc_gcs_node" > "${LOG_DIR}/gcs.log" 2>&1 &
GCS_PID=$!
PIDS+=($GCS_PID)
sleep 1

# 3. Spawn UAV nodes
for ((i=1; i<=NUM_UAVS; i++)); do
    echo "[Launcher] Spawning UAV-${i} process (port $((28002 + i)))..."
    "${BIN_DIR}/uav_pqc_uav_node" --id "$i" > "${LOG_DIR}/uav_${i}.log" 2>&1 &
    UAV_PID=$!
    PIDS+=($UAV_PID)
    sleep 3
done

echo ""
echo "[Launcher] Simulation started successfully."
echo "[Launcher] Press Ctrl+C to terminate the simulation."
echo "----------------------------------------------------"
echo "Displaying GCS node log output in real-time:"
echo "----------------------------------------------------"

# Tail the GCS log in foreground to show interaction
tail -f "${LOG_DIR}/gcs.log" &
TAIL_PID=$!

# Wait for tail or Ctrl+C
wait $TAIL_PID
