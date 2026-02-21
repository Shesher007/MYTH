#!/bin/bash
# MYTH Desktop — Debian/Ubuntu APT Repository Setup
# This script creates the repository structure for hosting MYTH via apt.
#
# Usage for end users:
#   curl -fsSL https://repo.myth-tools.github.io/gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/myth.gpg
#   echo "deb [signed-by=/usr/share/keyrings/myth.gpg] https://repo.myth-tools.github.io/apt stable main" | sudo tee /etc/apt/sources.list.d/myth.list
#   sudo apt update && sudo apt install myth && MYTH

set -euo pipefail

VERSION="${MYTH_VERSION:-1.1.6}"
ARCH="amd64"
REPO_DIR="./repo"
POOL_DIR="${REPO_DIR}/pool/main/m/myth"
DIST_DIR="${REPO_DIR}/dists/stable/main/binary-${ARCH}"

echo "📦 Setting up MYTH APT repository..."

# Create directory structure
mkdir -p "${POOL_DIR}" "${DIST_DIR}"

# Copy .deb package
if [ -f "MYTH_{${VERSION}}_${ARCH}.deb" ]; then
    cp "MYTH_{${VERSION}}_${ARCH}.deb" "${POOL_DIR}/"
else
    echo "⚠️  .deb package not found. Build it first with: cd ui && npx tauri build"
    exit 1
fi

# Generate Packages index
cd "${REPO_DIR}"
dpkg-scanpackages pool/ /dev/null | gzip -9c > "${DIST_DIR}/Packages.gz"
dpkg-scanpackages pool/ /dev/null > "${DIST_DIR}/Packages"

# Generate Release file
cat > "dists/stable/Release" << EOF
Origin: MYTH Tools
Label: MYTH
Suite: stable
Codename: stable
Architectures: amd64 arm64
Components: main
Description: MYTH Desktop Application Repository
EOF

# Sign with GPG (requires key)
# gpg --default-key "support@myth-tools.github.io" -abs -o dists/stable/Release.gpg dists/stable/Release
# gpg --default-key "support@myth-tools.github.io" --clearsign -o dists/stable/InRelease dists/stable/Release

echo "✅ APT repository created in ${REPO_DIR}/"
echo "   Upload to: https://repo.myth-tools.github.io/apt/"
