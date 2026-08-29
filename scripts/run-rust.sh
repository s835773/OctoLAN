#!/usr/bin/env bash
# ==============================================================================
# OctoLAN Rust Daemon (octolan-rs) Build & Launch Script
# ==============================================================================
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR"

echo "🦀 =================================================="
echo "   OctoLAN Rust Daemon Build & Runner (Axum + Tokio)"
echo "   =================================================="

# Check if Rust/Cargo is installed
if ! command -v cargo &> /dev/null; then
    echo "[!] Cargo not found! Installing Rust toolchain via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

echo "[+] Building optimized Rust binary (octolan-rs)..."
if [ -d "octolan-rs" ]; then
    cd octolan-rs
    cargo build --release
    TARGET_BIN="./target/release/octolan-rs"
else
    cargo build --release
    TARGET_BIN="./target/release/octolan-rs"
fi

echo "[+] Binary built successfully: $TARGET_BIN"

# Give binary raw socket capabilities without requiring full root
if command -v setcap &> /dev/null; then
    echo "[+] Granting CAP_NET_RAW & CAP_NET_ADMIN capabilities to binary..."
    sudo setcap cap_net_raw,cap_net_admin=eip "$TARGET_BIN" 2>/dev/null || true
fi

INTERFACE=${1:-eth0}
PORT=${2:-3000}

echo "[+] Starting octolan-rs daemon on interface $INTERFACE (Port: $PORT)..."
echo "    Web UI: http://localhost:$PORT"
echo "    WS Stream: ws://localhost:$PORT/ws/telemetry"
echo ""

exec "$TARGET_BIN" --interface "$INTERFACE" --port "$PORT"
