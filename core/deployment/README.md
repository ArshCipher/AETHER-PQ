# UAV-PQC Target Hardware Deployment Guide

This guide details the steps required to compile, configure, install, and execute the UAV-PQC suite across multiple physical ARMv7 Cortex-A9 boards.

## 1. System Requirements & Dependencies

The target platform uses:
- **Architecture**: ARMv7l (Cortex-A9 @ 1.3–1.8 GHz)
- **RAM**: 256 MB
- **OS**: Linux 4.4+ (e.g., lightweight Debian/Ubuntu rootfs)
- **Compiler**: GCC/G++ version 10 or newer (supporting C++20 standard)
- **Ethernet**: Standard POSIX UDP socket interface

### Required Third-Party Libraries
1. **OpenSSL 3.0+**: Provides cryptographic primitives (EVP AEAD, X25519, HKDF, SHA-256).
   ```bash
   sudo apt-get install -y libssl-dev
   ```
2. **liboqs**: Open Quantum Safe library providing ML-KEM and ML-DSA implementations.
   ```bash
   git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
   cmake -S liboqs -B liboqs/build -DOQS_USE_OPENSSL=ON -DBUILD_SHARED_LIBS=OFF -DCMAKE_BUILD_TYPE=Release
   cmake --build liboqs/build --parallel
   sudo cmake --install liboqs/build
   ```

---

## 2. Cross-Compilation (from Host to Target)

If compiling directly on the ARMv7 board is too slow or constrained by the 256 MB RAM limit, cross-compile from a Linux desktop:

1. Install the arm-linux-gnueabihf toolchain:
   ```bash
   sudo apt-get install -y gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf
   ```
2. Build the project using the cross-toolchain file:
   ```bash
   cmake -DCMAKE_TOOLCHAIN_FILE=cmake/armv7-toolchain.cmake \
         -DCMAKE_BUILD_TYPE=Release \
         -DUAV_PQC_EMBEDDED=ON \
         -B build-arm
   cmake --build build-arm --parallel
   ```
3. Copy the compiled binaries to the ARM boards via `scp`:
   ```bash
   scp build-arm/bin/uav_pqc_ca_node user@board1:/usr/local/bin/
   scp build-arm/bin/uav_pqc_gcs_node user@board2:/usr/local/bin/
   scp build-arm/bin/uav_pqc_uav_node user@board3:/usr/local/bin/
   ```

---

## 3. Configuration & Startup Templates

Each node is configured dynamically using command-line parameters or JSON configuration files.

### Configuration A (3 Boards)
- **Board 1 (CA)**: `uav_pqc_ca_node --ip 192.168.1.101 --port 28000`
- **Board 2 (GCS)**: `uav_pqc_gcs_node --ip 192.168.1.102 --port 28001 --ca-ip 192.168.1.101`
- **Board 3 (UAV)**: `uav_pqc_uav_node --id 1 --ip 192.168.1.103 --gcs-ip 192.168.1.102 --ca-ip 192.168.1.101`

### Running as Systemd Services
To run processes automatically on system bootup, copy the service templates from the `/deployment/` directory to target boards:
```bash
sudo cp uav_pqc_*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable uav_pqc_uav
sudo systemctl start uav_pqc_uav
```

---

## 4. Hardware Benchmarks

Run the benchmarking tool once deployed to measure ARM-specific performance metrics:
```bash
uav_pqc_hardware_benchmark --output /home/user/bench_report --target-ip 192.168.1.102 --target-port 28001
```
This output generates:
- `/home/user/bench_report.csv`
- `/home/user/bench_report.json`
containing wall time, CPU time, allocations, and throughputs.

---

## 5. Link Simulation & Service Management

Use the helper script `hardware_control.sh` on the physical boards to simulate network delays and manage the local UAV process:

- **Launch UAV Node**:
  ```bash
  ./hardware_control.sh start-uav --id 1 --ip 192.168.1.103 --gcs-ip 192.168.1.102 --ca-ip 192.168.1.101
  ```
- **Simulate Network Delay (50ms)**:
  ```bash
  ./hardware_control.sh net-delay 50
  ```
- **Simulate Packet Loss (3%)**:
  ```bash
  ./hardware_control.sh net-loss 3
  ```
- **Show Traffic Control Status**:
  ```bash
  ./hardware_control.sh net-status
  ```
- **Clear Rules**:
  ```bash
  ./hardware_control.sh net-clear
  ```
- **Stop UAV Node**:
  ```bash
  ./hardware_control.sh stop-uav
  ```
