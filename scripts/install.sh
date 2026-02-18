#!/bin/bash
# Universal Installer for MYTH Desktop
# Supports most Linux distributions (Alpine, Void, Solus, Slackware, etc.)

set -e

APP_NAME="myth"
INSTALL_DIR="/opt/$APP_NAME"
BIN_LINK="/usr/local/bin/$APP_NAME"

# Check for root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo ./install.sh)"
  exit 1
fi

echo "🚀 Installing $APP_NAME..."

# Create opt directory
mkdir -p "$INSTALL_DIR"

# Copy files from the package directory to /opt
cp -r bin share "$INSTALL_DIR/"

# Create symlink
ln -sf "$INSTALL_DIR/bin/$APP_NAME" "$BIN_LINK"

# Register Desktop File
DESKTOP_FILE="$INSTALL_DIR/share/applications/$APP_NAME.desktop"
if [ -f "$DESKTOP_FILE" ]; then
    cp "$DESKTOP_FILE" "/usr/share/applications/"
    echo "✅ Desktop entry registered."
fi

# Register Icons
cp -r "$INSTALL_DIR/share/icons/hicolor" "/usr/share/icons/"
gtk-update-icon-cache /usr/share/icons/hicolor || true

echo "--------------------------------------------------"
echo "✅ Installation Complete!"
echo "You can now launch '$APP_NAME' from your terminal or application menu."
echo "--------------------------------------------------"
