#!/usr/bin/env bash
# build_hardware_package.sh — Creates self-contained deployment tarball for Raspberry Pi / Jetson / Ubuntu hardware
set -euo pipefail

PACKAGE_NAME="aether_pq_hardware_package_$(date +%Y%m%d)"
BUILD_DIR="/tmp/$PACKAGE_NAME"

echo "=========================================================="
echo " Building AETHER-PQ Hardware Deployment Package"
echo " Target Package: ${PACKAGE_NAME}.tar.gz"
echo " Architecture  : $(uname -m)"
echo "=========================================================="

rm -rf "$BUILD_DIR" "${PACKAGE_NAME}.tar.gz"
mkdir -p "$BUILD_DIR/bin" "$BUILD_DIR/config" "$BUILD_DIR/deployment" "$BUILD_DIR/systemd" "$BUILD_DIR/tools"

# 1. Copy Compiled Binaries
echo "1. Collecting binaries..."
if [ -f "./build/tools/process_sim/uav_pqc_uav_node" ]; then
    cp ./build/tools/process_sim/uav_pqc_uav_node "$BUILD_DIR/bin/"
    cp ./build/tools/process_sim/uav_pqc_gcs_node "$BUILD_DIR/bin/"
    cp ./build/tools/process_sim/uav_pqc_ca_node "$BUILD_DIR/bin/"
elif [ -f "./uav_pqc_uav_node" ]; then
    cp ./uav_pqc_uav_node "$BUILD_DIR/bin/"
fi

# 2. Copy Config Templates
echo "2. Packaging configuration templates..."
cp -r ./config/templates/* "$BUILD_DIR/config/" 2>/dev/null || true

# 3. Copy Deployment Scripts & Systemd Files
echo "3. Packaging deployment automation scripts..."
cp -r ./deployment/*.sh "$BUILD_DIR/deployment/" 2>/dev/null || true
cp -r ./deployment/systemd/* "$BUILD_DIR/systemd/" 2>/dev/null || true
cp -r ./tools/aether_cli/aether "$BUILD_DIR/tools/" 2>/dev/null || true

# 4. Include Quick-Start Installer Script
cat <<'EOF' > "$BUILD_DIR/install.sh"
#!/usr/bin/env bash
set -e
echo "=========================================================="
echo " Installing AETHER-PQ Node on Physical Hardware"
echo "=========================================================="

sudo mkdir -p /usr/local/bin /etc/aether /var/log/aether /etc/aether/certs
sudo cp bin/* /usr/local/bin/ 2>/dev/null || true
sudo cp tools/aether /usr/local/bin/ 2>/dev/null || true
sudo chmod +x /usr/local/bin/uav_pqc_* /usr/local/bin/aether 2>/dev/null || true

sudo cp config/* /etc/aether/ 2>/dev/null || true
sudo cp systemd/* /etc/systemd/system/ 2>/dev/null || true

if command -v systemctl &>/dev/null; then
    sudo systemctl daemon-reload
fi

echo "=========================================================="
echo "✓ AETHER-PQ Hardware Package Installed Successfully!"
echo "  To start UAV Node: sudo deploy_uav.sh <ID> <IP> <PORT> <GCS_IP>"
echo "  To check status  : aether status"
echo "=========================================================="
EOF
chmod +x "$BUILD_DIR/install.sh"

# 5. Compress into tar.gz bundle
echo "4. Creating compressed distribution archive..."
tar -czf "${PACKAGE_NAME}.tar.gz" -C /tmp "$PACKAGE_NAME"

echo "=========================================================="
echo "✓ Package build complete!"
echo "  Archive: ${PACKAGE_NAME}.tar.gz ($(du -h "${PACKAGE_NAME}.tar.gz" | awk '{print $1}'))"
echo "=========================================================="
