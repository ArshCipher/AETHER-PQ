#!/usr/bin/env bash
# Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

# Hardware Board Validation Control Script
# Run this on the physical ARM boards to simulate link degradation and manage services.

INTERFACE="eth0"

usage() {
    echo "Usage: $0 <command> [options]"
    echo "Commands:"
    echo "  start-uav            Start the UAV node process manually"
    echo "  stop-uav             Stop the UAV node process"
    echo "  net-delay <ms>       Add a latency delay (in ms) to the Ethernet interface"
    echo "  net-loss <%>         Add a packet loss percentage to the Ethernet interface"
    echo "  net-jitter <ms>      Add a latency jitter (in ms) to the Ethernet interface"
    echo "  net-clear            Clear all traffic control delay/loss rules"
    echo "  net-status           Show current traffic control network rules"
    exit 1
}

if [[ $# -lt 1 ]]; then
    usage
fi

CMD=$1
shift

case $CMD in
    start-uav)
        echo "[Hardware] Launching UAV Node in background..."
        ./uav_pqc_uav_node "$@" > uav_node_run.log 2>&1 &
        echo "[Hardware] UAV Node launched. PID: $!. Logs saved to uav_node_run.log"
        ;;
    stop-uav)
        echo "[Hardware] Stopping UAV Node process..."
        pkill -f uav_pqc_uav_node || echo "[Hardware] No active UAV node process found."
        ;;
    net-delay)
        DELAY=$1
        if [[ -z "$DELAY" ]]; then echo "Error: Specify delay in ms"; exit 1; fi
        echo "[Hardware] Setting Ethernet latency delay to ${DELAY}ms on interface ${INTERFACE}..."
        sudo tc qdisc add dev "${INTERFACE}" root netem delay "${DELAY}ms" 2>/dev/null || \
        sudo tc qdisc change dev "${INTERFACE}" root netem delay "${DELAY}ms"
        ;;
    net-loss)
        LOSS=$1
        if [[ -z "$LOSS" ]]; then echo "Error: Specify loss in %"; exit 1; fi
        echo "[Hardware] Setting Ethernet packet loss to ${LOSS}% on interface ${INTERFACE}..."
        sudo tc qdisc add dev "${INTERFACE}" root netem loss "${LOSS}%" 2>/dev/null || \
        sudo tc qdisc change dev "${INTERFACE}" root netem loss "${LOSS}%"
        ;;
    net-jitter)
        DELAY=$1
        JITTER=$2
        if [[ -z "$DELAY" ]] || [[ -z "$JITTER" ]]; then echo "Error: Specify delay and jitter in ms"; exit 1; fi
        echo "[Hardware] Setting latency delay to ${DELAY}ms and jitter to ${JITTER}ms..."
        sudo tc qdisc add dev "${INTERFACE}" root netem delay "${DELAY}ms" "${JITTER}ms" 2>/dev/null || \
        sudo tc qdisc change dev "${INTERFACE}" root netem delay "${DELAY}ms" "${JITTER}ms"
        ;;
    net-clear)
        echo "[Hardware] Clearing all network delay/loss rules on interface ${INTERFACE}..."
        sudo tc qdisc del dev "${INTERFACE}" root 2>/dev/null || true
        ;;
    net-status)
        echo "[Hardware] Current Netem rules for ${INTERFACE}:"
        tc qdisc show dev "${INTERFACE}"
        ;;
    *)
        usage
        ;;
esac
