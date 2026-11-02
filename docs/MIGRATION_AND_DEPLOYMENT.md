# AETHER-PQ Swarm Framework Migration & Complete Setup Manual

This manual provides step-by-step instructions to compile, install, and execute the **AETHER-PQ (Post-Quantum Secure UAV Swarm Communication Framework)** on a completely clean network of physical or virtual machines. 

It covers all prerequisites, exact library versions, source download links, build flags, network configuration, and troubleshooting directions to migrate the infrastructure (GCS Host, Certificate Authority, and UAV Swarms) to new PCs.

---

## 1. System Architecture & Port Bindings

The framework is structured as follows:

| Node / Process | Type | Default Port | Protocol | Purpose |
|---|---|---|---|---|
| **CA Node (`uav_pqc_ca_node`)** | Host | `28000` | TCP | Onboards nodes and signs certificates using ML-DSA. |
| **GCS Node (`uav_pqc_gcs_node`)** | Host | `28001` | UDP | Receives telemetry, coordinates direct D2D links, issues rekey blocks. |
| **UI Gateway WebSocket Server** | Host | `3001` | WS | Bridges GCS process output events directly to the frontend. |
| **Vite Dashboard Frontend** | Host | `8080` | HTTP | Live React/TanStack monitoring SPA. |
| **UAV Swarm Client 1 (`uav_pqc_uav_node`)** | Remote PC-1 | `28003` | UDP | Swarm drone node (captures `/dev/video0`). |
| **UAV Swarm Client 2 (`uav_pqc_uav_node`)** | Remote PC-2 | `28004` | UDP | Swarm drone node. |
| **UAV Swarm Client 3 (`uav_pqc_uav_node`)** | Remote PC-3 | `28005` | UDP | Swarm drone node. |

---

## 2. Hard Prerequisites & System Tools

On a fresh Ubuntu/Debian installation, run the following commands to install the core compiler and packaging tools:

```bash
# 1. Update Package Registries
sudo apt-get update

# 2. Install Build Essentials, CMake, Git, Wget, and Toolchain helper
sudo apt-get install -y build-essential cmake git wget libssl-dev gcc-11 g++-11 sshpass pkg-config
```

### For GCS Host (Node.js & npm setup)
The GCS host requires **Node.js (v18.x or v20.x)**. Install it cleanly on a fresh Linux host:
```bash
# Install NodeSource Node.js v20 LTS
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# Verify versions
node -v  # Expected: v20.x.x
npm -v   # Expected: v10.x.x
```

### For UAV Nodes (OpenCV Setup)
UAV Node 1 sniffs the camera feed using OpenCV. Install the development packages:
```bash
sudo apt-get install -y libopencv-dev
```

---

## 3. Library Installation & Compilation Guide

The C++ backend links against OpenSSL 3.0+ and `liboqs`. If your OS provides older packages (e.g. Ubuntu 18.04/20.04 only ship OpenSSL 1.1.1), compile them from source:

### A. OpenSSL (Version 3.0.12)
* **Required Version**: `3.0.x` (Do not use 1.1.1 or 3.2+ to prevent API mismatches).
* **Download URL**: `https://www.openssl.org/source/openssl-3.0.12.tar.gz`
* **Compilation Commands**:
  ```bash
  # 1. Create dependency sandbox
  mkdir -p ~/UAV && cd ~/UAV
  
  # 2. Download source tarball
  wget -q https://www.openssl.org/source/openssl-3.0.12.tar.gz
  tar -xzf openssl-3.0.12.tar.gz
  
  # 3. Configure and compile
  cd openssl-3.0.12
  ./config --prefix="$HOME/UAV/openssl3" --openssldir="$HOME/UAV/openssl3" shared
  make -j$(nproc)
  make install_sw
  ```

### B. liboqs (Version 0.10.0 / Main Branch)
* **Required Version**: Open Quantum Safe `liboqs` (v0.10.0 or compatible main branch).
* **Download URL**: `https://github.com/open-quantum-safe/liboqs.git`
* **Compilation Commands**:
  ```bash
  cd ~/UAV
  
  # 1. Clone target branch
  git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
  
  # 2. Configure with OpenSSL 3 override and static link settings
  cmake -S liboqs -B liboqs/build \
      -DOQS_USE_OPENSSL=ON \
      -DOPENSSL_ROOT_DIR="$HOME/UAV/openssl3" \
      -DBUILD_SHARED_LIBS=OFF \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX="$HOME/UAV/oqs"
      
  # 3. Build & Install locally
  cmake --build liboqs/build --parallel $(nproc)
  cmake --install liboqs/build
  ```

### C. Automatically Resolved Libraries (No Manual Steps Required)
The C++ project uses CMake's `FetchContent` to download, build, and link these libraries automatically during the build step:
* **spdlog (v1.14.1)**: Structured logging framework.
* **nlohmann_json (v3.11.3)**: JSON serialization/deserialization.
* **googletest / googlemock**: Test suites and mocks.

---

## 4. GCS Host Setup & Launch (CA, GCS, Gateway, Frontend)

### Step 1: Compile CA & GCS Host Binaries
1. Enter the backend directory and run CMake:
   ```bash
   cd uav_pqc
   mkdir -p build && cd build
   ```
2. Configure and build target binaries:
   ```bash
   cmake -DCMAKE_BUILD_TYPE=Release ..
   cmake --build . -j$(nproc || sysctl -n hw.ncpu)
   ```
This generates `uav_pqc_ca_node` and `uav_pqc_gcs_node` under `build/tools/process_sim/`.

### Step 2: Start UI Gateway Server
1. Navigate to the Vite frontend project directory:
   ```bash
   cd build/frontend
   ```
2. Install npm dependencies:
   ```bash
   npm install
   ```
3. Spawn the gateway process. Set GCS host IP and drone IP mappings:
   ```bash
   AETHER_CA_BIN=/absolute/path/to/build/tools/process_sim/uav_pqc_ca_node \
   AETHER_GCS_BIN=/absolute/path/to/build/tools/process_sim/uav_pqc_gcs_node \
   SPAWN_LOCAL_UAVS=false \
   CA_IP=192.168.171.21 \
   CA_BIND_IP=192.168.171.21 \
   GCS_IP=192.168.171.21 \
   CA_PORT=28000 \
   GCS_PORT=28001 \
   UAV_ROUTES="1:192.168.171.206:28003,2:192.168.171.17:28004,3:192.168.171.179:28005" \
   npx tsx uav_pqc_ui_gateway.ts
   ```
   *(Note: Replace `192.168.171.21` with your new GCS host IP, and the UAV routes with the respective IP addresses of your drone nodes).*

### Step 3: Run the Dashboard Frontend
Open a new terminal on the host machine:
```bash
cd build/frontend
npm run dev
```
Open **`http://localhost:8080`** in your browser.

---

## 5. UAV Swarm Nodes Setup & Launch (Drones)

For each remote UAV PC, compile the codebase natively (to target its specific processor architecture like `i686` or `x86_64`) and start the client.

### Step 1: Natively Build the Code
1. Extract the distribution tarball to a workspace directory (e.g. `~/UAV` or `~/D2D`).
2. Enter the C++ directory:
   ```bash
   cd uav_pqc
   mkdir -p build && cd build
   ```
3. Run CMake. **You must force the `gcc-11` and `g++-11` toolchain** to support C++20 standard compiler features:
   * **Case A: If you compiled custom OpenSSL/liboqs in Section 3**:
     ```bash
     CC=gcc-11 CXX=g++-11 cmake \
         -DOPENSSL_ROOT_DIR=/home/uav/UAV/openssl3 \
         -DOQS_ROOT_DIR=/home/uav/UAV/oqs \
         -DCMAKE_BUILD_TYPE=Release ..
     ```
   * **Case B: If dependencies are installed globally in `/usr/lib/` & `/usr/local/`**:
     ```bash
     CC=gcc-11 CXX=g++-11 cmake -DCMAKE_BUILD_TYPE=Release ..
     ```
4. Build the client node binary:
   ```bash
   make -j$(nproc)
   ```
This generates `uav_pqc_uav_node` under `build/tools/process_sim/`.

### Step 2: Spawn Node Daemons on Remote PCs
Ensure any old process is terminated, then launch the client daemon.

* **PC-1 (UAV Node 1, with camera `dev/video0`)**:
  ```bash
  ssh uav@192.168.171.206 "killall uav_pqc_uav_node 2>/dev/null; true"
  ssh -o PubkeyAuthentication=no -o PreferredAuthentications=password uav@192.168.171.206 \
    "setsid nohup /home/uav/D2D/uav_pqc/build/tools/process_sim/uav_pqc_uav_node \
        --id 1 \
        --ip 192.168.171.206 \
        --port 28003 \
        --ca-ip 192.168.171.21 --ca-port 28000 \
        --gcs-ip 192.168.171.21 --gcs-port 28001 \
        --uav-routes '1:192.168.171.206:28003,2:192.168.171.17:28004,3:192.168.171.179:28005' \
        --camera-device /dev/video0 \
        </dev/null >~/uav_node.log 2>&1 &"
  ```
* **PC-2 (UAV Node 2)**:
  ```bash
  ssh uav@192.168.171.17 "killall uav_pqc_uav_node 2>/dev/null; true"
  ssh -o PubkeyAuthentication=no -o PreferredAuthentications=password uav@192.168.171.17 \
    "setsid nohup /home/uav/UAV/uav_pqc/build/tools/process_sim/uav_pqc_uav_node \
        --id 2 \
        --ip 192.168.171.17 \
        --port 28004 \
        --ca-ip 192.168.171.21 --ca-port 28000 \
        --gcs-ip 192.168.171.21 --gcs-port 28001 \
        --uav-routes '1:192.168.171.206:28003,2:192.168.171.17:28004,3:192.168.171.179:28005' \
        </dev/null >~/uav_node.log 2>&1 &"
  ```
* **PC-3 (UAV Node 3)**:
  ```bash
  ssh uav@192.168.171.179 "killall uav_pqc_uav_node 2>/dev/null; true"
  ssh -o PubkeyAuthentication=no -o PreferredAuthentications=password uav@192.168.171.179 \
    "setsid nohup /home/uav/UAV/uav_pqc/build/tools/process_sim/uav_pqc_uav_node \
        --id 3 \
        --ip 192.168.171.179 \
        --port 28005 \
        --ca-ip 192.168.171.21 --ca-port 28000 \
        --gcs-ip 192.168.171.21 --gcs-port 28001 \
        --uav-routes '1:192.168.171.206:28003,2:192.168.171.17:28004,3:192.168.171.179:28005' \
        </dev/null >~/uav_node.log 2>&1 &"
  ```

---

## 6. Swarm Verification & Monitoring

### A. Check local socket bindings (GCS Host)
```bash
netstat -an | grep 2800
# Expected bindings:
# tcp4       0      0  GCS_IP.28000   *.*                    LISTEN
# udp4       0      0  GCS_IP.28001   *.*
```

### B. Verify remote UAV telemetry output
Run this on any UAV client PC to confirm active handshake, TreeKEM swarm synchronization, and telemetric heartbeats:
```bash
cat ~/uav_node.log
```
**Healthy UAV output:**
```
[UAV-1] Registered with CA.
[UAV-1] Starting ACPE and Post-Quantum hybrid handshake with GCS...
[protocol.handshake] Handshake COMPLETE — mode=Hybrid suite=Hybrid+ML-KEM-768+AES-256-GCM
[UAV-1] Handshake COMPLETE. Requesting TreeKEM enrollment...
[UAV-0:1] Successfully synchronized TreeKEM membership/public state. Swarm size: 3
[UAV-0:1] Successfully processed TreeKEM update. Installed group key for epoch 3
[UAV-1] MAVLink Heartbeat telemetry sent (AES-GCM encrypted).
```

---

## 7. Troubleshooting

* **Issue: CMake error: `Target requires the language dialect "CXX20" but CMake does not know the compile flags...`**
  * *Cause*: CMake is using an old compiler version (like GCC 7.5.0) that has incomplete C++20 support.
  * *Solution*: Force gcc-11 compiler flags when calling CMake: `CC=gcc-11 CXX=g++-11 cmake ..`
* **Issue: `CA Registration Error: Connection refused`**
  * *Cause*: Host CA process is not listening, bound to local loopback instead of Ethernet, or blocked by the host firewall.
  * *Solution*: Confirm CA is listening on `GCS_IP` via netstat. Allow port 28000 TCP through the firewall.
* **Issue: SSH session timeout or `Connection timed out during banner exchange` during compilation**
  * *Cause*: Compiling with too many threads (`make -j$(nproc)`) is overloading the target CPU cores, rendering the SSH daemon temporarily unresponsive.
  * *Solution*: Wait for compilation to complete, or lower the build parallelism: `make -j2`.
* **Issue: SSH command rejects password or key**
  * *Cause*: SSH attempts public key validation which is rejected, leading to connection limits blocking passwords.
  * *Solution*: Explicitly bypass public key authentication:
    `ssh -o PubkeyAuthentication=no -o PreferredAuthentications=password ...`
