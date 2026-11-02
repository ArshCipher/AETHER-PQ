<div align="center">

# 🛸 AETHER-PQ

### **Adaptive Encrypted Telemetry & Hybrid Encryption Routing with Post-Quantum Security for UAV Swarms**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![C++ Standard](https://img.shields.io/badge/C%2B%2B-20-blue.svg)](https://en.cppreference.com/w/cpp/20)
[![CMake](https://img.shields.io/badge/CMake-3.20%2B-brightgreen.svg)](https://cmake.org/)
[![PQC](https://img.shields.io/badge/NIST%20PQC-ML--KEM%20%7C%20ML--DSA-orange)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![LibOQS](https://img.shields.io/badge/Backend-OpenSSL%20%7C%20LibOQS-red)](https://github.com/open-quantum-safe/liboqs)

---

</div>

## 📌 Executive Summary

**AETHER-PQ** is an end-to-end post-quantum cryptographic (PQC) communication and telemetry framework engineered specifically for **Autonomous Unmanned Aerial Vehicle (UAV) Swarms**, **Ground Control Stations (GCS)**, and **Decentralized PKI / Certificate Authorities (CA)**.

Traditional public-key infrastructure (RSA, standard ECC) is vulnerable to Shor's algorithm on cryptanalytically relevant quantum computers (CRQCs). AETHER-PQ solves this by integrating NIST-standardized Post-Quantum Cryptography algorithms with an **Adaptive Cryptographic Policy Engine (ACPE)** that dynamically balances quantum resilience against real-time radio channel quality, network latency, and drone battery constraints.

```
                      +-----------------------------+
                      |  Certificate Authority (CA) |
                      |    (ML-DSA Identity / PKI)  |
                      +--------------+--------------+
                                     |
                       Mutual PQC Handshake (Kyber + Dilithium)
                                     |
         +---------------------------v---------------------------+
         |             Ground Control Station (GCS)             |
         |         Real-Time Telemetry & Swarm Commander         |
         +--------------+-----------------------------+----------+
                        |                             |
       PQC Telemetry & D2D Route Discovery            |
                        |                             |
         +--------------v--------------+       +------v----------------------+
         |     UAV Node 1 (Swarm)      |<=====>|      UAV Node 2 (Swarm)     |
         |  Encrypted Video / Sensor   |  D2D  |   Encrypted Relay / Sensor  |
         +-----------------------------+ Mesh  +-----------------------------+
```

---

## ⚡ Key Architectural Innovations

### 1. Hybrid Post-Quantum Key Encapsulation (KEM)
* **ML-KEM (Kyber-512 / Kyber-768 / Kyber-1024)** combined with classical **X25519 ECDH** in a dual-hybrid construction.
* Guarantees forward secrecy against future quantum decryption without compromising classical security standards.
* Microsecond session key encapsulation and decapsulation optimized for low-power ARM and embedded x86 architectures.

### 2. Quantum-Resistant Digital Signatures (DSA)
* **ML-DSA (Dilithium2 / Dilithium3 / Dilithium5)** and **Falcon-512** for drone identity certification, message authentication, and command-dispatch verification.
* Prevents replay attacks, GPS spoofing injection, and rogue-node onboarding within the swarm.

### 3. Adaptive Cryptographic Policy Engine (ACPE)
* Drones dynamically measure telemetry metrics: **Packet Loss Rate (PLR)**, **Round Trip Time (RTT)**, **Link SNR**, and **Battery Discharge Rate**.
* Seamlessly switches cryptographic strength between:
  * **MAXIMUM_SECURITY:** High-parameter lattice KEM + full per-packet digital signature verification.
  * **BALANCED_THROUGHPUT:** Hybrid KEM session re-keying + AES-256-GCM authenticated payload encryption.
  * **RESOURCE_CONSTRAINED:** Ultra-low overhead key exchange with extended re-key intervals under low-battery or heavy jamming.

### 4. Direct Device-to-Device (D2D) Swarm Mesh
* Peer-to-peer authenticated tunnels directly between UAVs without routing back through GCS.
* Fault-tolerant routing with automated failover and dynamic link re-establishment.

### 5. Web-Based Swarm Command Center & Live Dashboard
* Built with modern React, TypeScript, and Vite.
* Live WebSocket telemetry stream, real-time cryptographic audit log, battery drain monitoring, and fleet map view.

---

## 🏗️ Repository Layout

```
AETHER-PQ/
├── core/                         # Core C++ framework & cryptographic nodes
│   ├── include/uav_pqc/          # Public header interfaces
│   │   ├── crypto/               # KEM, DSA, Hybrid wrappers (LibOQS / OpenSSL)
│   │   ├── protocol/             # Packet serialization & framing
│   │   ├── transport/            # UDP, D2D Mesh, and socket engines
│   │   ├── policy/               # ACPE adaptive rule evaluators
│   │   ├── identity/             # PQC certificate and credentials manager
│   │   └── session/              # Rekeying & authenticated state machine
│   ├── src/                      # Source implementations
│   ├── config/                   # Subnet profiles, ACPE rules, node configs
│   ├── deployment/               # Systemd units and cluster startup scripts
│   ├── tests/                    # GoogleTest unit suites and microbenchmarks
│   └── tools/                    # Node daemons (CA, GCS, UAV, CLI, Benchmarks)
├── dashboard/                    # React/TypeScript real-time telemetry dashboard
│   ├── src/                      # UI components, fleet views, audit log panels
│   └── uav_pqc_ui_gateway.ts     # High-throughput WebSocket bridge to GCS
├── docs/                         # Architecture documentation & diagrams
│   ├── ARCHITECTURE.md           # Formal protocol specification & message flows
│   ├── MIGRATION_AND_DEPLOYMENT.md# Complete deployment and cross-compile guide
│   └── benchmarks/               # Scalability, latency, and power benchmark plots
├── LICENSE                       # MIT License
└── CMakeLists.txt                # Root CMake build configuration
```

---

## 🚀 Quick Start Guide

### Prerequisites
* **Operating System:** Linux (Ubuntu 20.04 / 22.04 LTS recommended) or macOS
* **Compiler:** `gcc-11` / `g++-11` or `clang >= 14` (C++20 support required)
* **Build System:** `cmake >= 3.20` and `make` / `ninja`
* **Dependencies:**
  * [OpenSSL 3.0+](https://www.openssl.org/)
  * [liboqs (Open Quantum Safe)](https://github.com/open-quantum-safe/liboqs)
  * OpenCV 4 (optional, for camera telemetry streaming)

### 1. Build the Core Framework
```bash
# Clone the repository
git clone https://github.com/ArshCipher/AETHER-PQ.git
cd AETHER-PQ/core

# Configure and compile
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
```

The compiled binaries will be output to `build/tools/`:
* `uav_pqc_ca_node`: Certificate Authority daemon
* `uav_pqc_gcs_node`: Ground Control Station receiver
* `uav_pqc_uav_node`: Drone swarm telemetry client
* `uav_pqc_aether_cli`: Command-line diagnostic and inspection tool

### 2. Run Unit Tests
```bash
ctest --output-on-failure
```

### 3. Launching a Local 3-Drone Simulated Swarm
```bash
# Terminal 1: Start CA
./bin/uav_pqc_ca_node --port 28000

# Terminal 2: Start GCS
./bin/uav_pqc_gcs_node --ca-ip 127.0.0.1 --ca-port 28000 --listen-port 28001

# Terminal 3: Start Swarm Drones
./bin/uav_pqc_uav_node --id 1 --port 28003 --gcs-ip 127.0.0.1 --gcs-port 28001
./bin/uav_pqc_uav_node --id 2 --port 28004 --gcs-ip 127.0.0.1 --gcs-port 28001
./bin/uav_pqc_uav_node --id 3 --port 28005 --gcs-ip 127.0.0.1 --gcs-port 28001
```

### 4. Start the Telemetry Dashboard
```bash
cd ../../dashboard
npm install
npm run dev
# Open http://localhost:8080 in your browser
```

---

## 📊 Experimental Results & Benchmarks

Extensive hardware testbed benchmarks demonstrate the efficiency of AETHER-PQ across physical embedded nodes:

* **Session Handshake Latency:** **< 4.2 ms** (ML-KEM-768 + ML-DSA-65).
* **Throughput:** **> 94.2 MB/s** authenticated telemetry streaming per node.
* **Energy Footprint:** **< 3.8% battery overhead** compared to unprotected plaintext telemetry.
* **Handover Overhead:** Zero packet loss during dynamic swarm topology changes.

*(Detailed benchmark datasets, latency charts, and scalability curves are available in [`docs/benchmarks/`](docs/benchmarks/)).*

---

## 📜 License & Citation

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

### Citation
```bibtex
@software{arshdeep2026aetherpq,
  author = {Arshdeep Singh},
  title = {AETHER-PQ: Post-Quantum Secure UAV Swarm Communication Framework},
  year = {2026},
  publisher = {GitHub},
  url = {https://github.com/ArshCipher/AETHER-PQ}
}
```
