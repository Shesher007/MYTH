#!/bin/bash
# MYTH Desktop — macOS PKG Builder
# Wraps the .app bundle into a signed .pkg installer
# Usage: ./scripts/build_macos_pkg.sh

APP_PATH="ui/src-tauri/target/release/bundle/macos/MYTH.app"
PKG_OUTPUT="dist/MYTH-1.1.5.pkg"
SIGNING_ID="${SIGNING_ID:-Developer ID Installer: MYTH}"

if [ ! -d "$APP_PATH" ]; then
    echo "Error: .app bundle not found. Run 'npm run tauri:build' first."
    exit 1
fi

mkdir -p dist

echo "📦 Building component package..."
PKG_ARGS=(--root "$APP_PATH" --identifier "com.shesher011.myth" --version "1.1.5" --install-location "/Applications/MYTH.app")

if [ -d "packaging/macos/scripts" ]; then
    PKG_ARGS+=(--scripts "packaging/macos/scripts")
fi

pkgbuild "${PKG_ARGS[@]}" dist/component.pkg

echo "📦 Building product archive..."
PROD_ARGS=(--distribution "packaging/macos/distribution.xml" --package-path "dist" "$PKG_OUTPUT")

if [ -d "packaging/macos/resources" ]; then
    PROD_ARGS+=(--resources "packaging/macos/resources")
fi

productbuild "${PROD_ARGS[@]}"

# Optional signing
if [ -n "$SIGNING_ID" ]; then
    echo "🔏 Signing package with ID: $SIGNING_ID"
    productsign --sign "$SIGNING_ID" "$PKG_OUTPUT" "dist/MYTH-1.1.5-signed.pkg"
    mv "dist/MYTH-1.1.5-signed.pkg" "$PKG_OUTPUT"
fi

rm dist/component.pkg
echo "✅ macOS Installer Package created: $PKG_OUTPUT"
