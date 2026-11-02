#!/bin/bash
# setup_dependencies.sh - Setup dependencies and build UAV-PQC on a clean Ubuntu PC
set -e

echo "=========================================================="
echo "Starting UAV-PQC Dependency Setup on Ubuntu PC..."
echo "=========================================================="

# 1. Update package manager and install build system essentials
echo "1. Installing basic system build tools..."
sudo apt-get update
sudo apt-get install -y build-essential cmake git wget libssl-dev

# Ensure UAV sandbox and dependency root exists
mkdir -p "$HOME/UAV"
cd "$HOME/UAV"

# 2. Build OpenSSL 3.0.12 from source if not already built
if [ ! -d "$HOME/UAV/openssl3" ]; then
    echo "2. Downloading and compiling OpenSSL 3.0.12..."
    if [ ! -f openssl-3.0.12.tar.gz ]; then
        wget -q https://www.openssl.org/source/openssl-3.0.12.tar.gz || wget -q https://github.com/openssl/openssl/releases/download/openssl-3.0.12/openssl-3.0.12.tar.gz
    fi
    tar -xzf openssl-3.0.12.tar.gz
    cd openssl-3.0.12
    ./config --prefix="$HOME/UAV/openssl3" --openssldir="$HOME/UAV/openssl3" shared
    make -j$(nproc)
    make install_sw
    cd "$HOME/UAV"
    echo "✓ OpenSSL 3.0.12 build completed successfully."
else
    echo "✓ OpenSSL 3.0.12 already installed at $HOME/UAV/openssl3."
fi

# 3. Build liboqs from source if not already built
if [ ! -d "$HOME/UAV/oqs" ]; then
    echo "3. Cloning and compiling liboqs..."
    rm -rf liboqs
    git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
    cmake -S liboqs -B liboqs/build \
        -DOQS_USE_OPENSSL=ON \
        -DOPENSSL_ROOT_DIR="$HOME/UAV/openssl3" \
        -DBUILD_SHARED_LIBS=OFF \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX="$HOME/UAV/oqs"
    cmake --build liboqs/build --parallel $(nproc)
    cmake --install liboqs/build
    echo "✓ liboqs build completed successfully."
else
    echo "✓ liboqs already installed at $HOME/UAV/oqs."
fi

# 4. Compile UAV-PQC code natively
UAV_PQC_DIR="$HOME/UAV/uav_pqc"
if [ -d "$UAV_PQC_DIR" ]; then
    echo "4. Building UAV-PQC project natively..."
    cd "$UAV_PQC_DIR"
    rm -rf build
    mkdir -p build
    cd build
    cmake -DOPENSSL_ROOT_DIR="$HOME/UAV/openssl3" -DOQS_ROOT_DIR="$HOME/UAV/oqs" ..
    make -j$(nproc)
    echo "✓ UAV-PQC built successfully!"
else
    echo "⚠️  Note: UAV-PQC source folder not found at $UAV_PQC_DIR."
    echo "   Please upload/copy the 'uav_pqc' directory to $UAV_PQC_DIR and run compile."
fi

echo "=========================================================="
echo "✓ Setup process completed!"
echo "=========================================================="
