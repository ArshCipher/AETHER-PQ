#!/bin/bash
set -e

# Download OpenSSL source
if [ ! -f openssl-3.0.12.tar.gz ]; then
    echo "Downloading OpenSSL 3.0.12..."
    wget -q https://www.openssl.org/source/openssl-3.0.12.tar.gz || wget -q https://github.com/openssl/openssl/releases/download/openssl-3.0.12/openssl-3.0.12.tar.gz
fi

# Extract
if [ ! -d openssl-3.0.12 ]; then
    echo "Extracting OpenSSL..."
    tar -xzf openssl-3.0.12.tar.gz
fi

# Build and Install
cd openssl-3.0.12
echo "Configuring OpenSSL..."
export PATH=/opt/gcc-linaro-7.5.0-2019.12-x86_64_arm-linux-gnueabi/bin/:$PATH

./Configure linux-armv4 shared \
    --cross-compile-prefix=arm-linux-gnueabi- \
    --prefix=/opt/pqc/UAV/openssl-arm-install \
    --openssldir=/opt/pqc/UAV/openssl-arm-install/ssl

echo "Compiling OpenSSL (this may take a minute)..."
make -j$(nproc)
echo "Installing OpenSSL..."
make install_sw
echo "OpenSSL build completed successfully."
