#!/bin/bash
# ==============================================================================
# MYTH Auto-Builder for Ubuntu VM
# This script automates everything exactly like your GitHub Action does.
# ==============================================================================

set -e # Exit on error

echo "🚀 Starting MYTH Automated Build Environment Setup..."

# 1. Mirror GitHub Action "Setup Linux Dependencies"
echo "📦 Installing system headers (webkit2gtk, gtk3, rpm, etc.)..."
sudo apt update
sudo apt install -y build-essential curl git libwebkit2gtk-4.1-dev \
    libappindicator3-dev librsvg2-dev patchelf libssl-dev libgtk-3-dev rpm \
    python3 python3-pip python3-venv

# 2. Mirror GitHub Action "Setup Rust"
echo "🦀 Installing Rust (Stable)..."
if ! command -v rustc &> /dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
else
    echo "✅ Rust already installed."
fi
rustup target add x86_64-unknown-linux-gnu

# 3. Mirror GitHub Action "Setup Node.js"
echo "🟢 Installing Node.js 24..."
if ! command -v node &> /dev/null; then
    curl -fsSL https://deb.nodesource.com/setup_24.x | sudo -E bash -
    sudo apt install -y nodejs
else
    echo "✅ Node.js already installed."
fi

# 4. Mirror GitHub Action "Install uv"
echo "⚡ Installing uv (Python manager)..."
if ! command -v uv &> /dev/null; then
    curl -LsSf https://astral.sh/uv/install.sh | sh
    source "$HOME/.cargo/env"
else
    echo "✅ uv already installed."
fi

echo "✅ Environment Readiness Check Complete!"

# 5. The Build Command (Exactly like CI)
echo "🏗️ Starting Build Pipeline..."

# YOU MUST SET THIS VARIABLE BEFORE RUNNING
if [ -z "$MYTH_SECRETS_BUNDLE" ]; then
    echo "⚠️  WARNING: MYTH_SECRETS_BUNDLE is not set. The built app will use template defaults."
    echo "   To set it, run: export MYTH_SECRETS_BUNDLE='your_string' before running this script."
fi

export TAURI_TARGET_TRIPLE="x86_64-unknown-linux-gnu"
export UV_LINK_MODE="copy"
export PDTM_HOME="$(pwd)/ui/src-tauri/binaries"

# Cleanup local locks
rm -rf ui/node_modules

# Full Orchestration
uv sync --all-extras
uv run python3 scripts/ci_orchestrator.py build-all

echo "✨ DONE! Your artifacts are in the root directory and ui/src-tauri/target/."