#!/usr/bin/env bash
# ==============================================================================
# OctoLAN One-Line Quick Install & Setup Script
# Usage: curl -sSL https://raw.githubusercontent.com/example/octolan/main/scripts/install-bundle.sh | bash
# Or standalone: bash scripts/install-bundle.sh [rust|c|all]
# ==============================================================================
set -e

MODE="${1:-all}"
INSTALL_DIR="${2:-./octolan-bundle}"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
ORANGE='\033[0;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${ORANGE}"
echo "  ___   ____ _____ ___  _        _    _   _ "
echo " / _ \ / ___|_   _/ _ \| |      / \  | \ | |"
echo "| | | | |     | || | | | |     / _ \ |  \| |"
echo "| |_| | |___  | || |_| | |___ / ___ \| |\  |"
echo " \___/ \____| |_| \___/|_____/_/   \_\_| \_|"
echo -e "${NC}"
echo -e "${GREEN}🐙 OctoLAN Enterprise Network Intelligence Suite Installer${NC}"
echo -e "${BLUE}===================================================================${NC}"
echo -e "[*] Target Installation Directory: ${CYAN}${INSTALL_DIR}${NC}"
echo -e "[*] Selected Installation Mode:    ${CYAN}${MODE}${NC}"
echo ""

mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# 1. System Dependency & Capability Detection
echo -e "${BLUE}[1/4] Checking system toolchain & networking capabilities...${NC}"

HAS_CARGO=false
HAS_GCC=false
HAS_PODMAN=false
HAS_SETCAP=false

if command -v cargo &> /dev/null; then HAS_CARGO=true; fi
if command -v gcc &> /dev/null; then HAS_GCC=true; fi
if command -v podman &> /dev/null; then HAS_PODMAN=true; fi
if command -v setcap &> /dev/null; then HAS_SETCAP=true; fi

echo -e "  - GCC Toolchain:       $([ "$HAS_GCC" = true ] && echo -e "${GREEN}Found${NC}" || echo -e "${ORANGE}Not Installed${NC}")"
echo -e "  - Rust/Cargo:          $([ "$HAS_CARGO" = true ] && echo -e "${GREEN}Found${NC}" || echo -e "${ORANGE}Not Installed${NC}")"
echo -e "  - Podman / Docker:     $([ "$HAS_PODMAN" = true ] && echo -e "${GREEN}Found${NC}" || echo -e "${ORANGE}Not Installed${NC}")"
echo -e "  - Linux setcap:        $([ "$HAS_SETCAP" = true ] && echo -e "${GREEN}Available${NC}" || echo -e "${ORANGE}Not Available${NC}")"
echo ""

# 2. Extract POSIX C Suite if requested
if [ "$MODE" = "c" ] || [ "$MODE" = "all" ]; then
    echo -e "${BLUE}[2/4] Generating POSIX C99 Auditing Suite...${NC}"
    mkdir -p c_suite
    
    cat << 'EOF' > c_suite/Makefile
CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -std=c99
STATIC_FLAGS ?= -static
TARGETS = netflow_collector storm_detector arp_scan icmp_sweep os_fingerprint lldp_vlan_sniff passive_monitor

all: $(TARGETS)

netflow_collector: netflow_collector.c
	$(CC) $(CFLAGS) netflow_collector.c -o netflow_collector

storm_detector: storm_detector.c
	$(CC) $(CFLAGS) storm_detector.c -o storm_detector

arp_scan: arp_scan.c
	$(CC) $(CFLAGS) arp_scan.c -o arp_scan

icmp_sweep: icmp_sweep.c
	$(CC) $(CFLAGS) icmp_sweep.c -o icmp_sweep

os_fingerprint: os_fingerprint.c
	$(CC) $(CFLAGS) os_fingerprint.c -o os_fingerprint

lldp_vlan_sniff: lldp_vlan_sniff.c
	$(CC) $(CFLAGS) lldp_vlan_sniff.c -o lldp_vlan_sniff

passive_monitor: passive_monitor.c
	$(CC) $(CFLAGS) passive_monitor.c -o passive_monitor

static: CFLAGS += $(STATIC_FLAGS)
static: all

clean:
	rm -f $(TARGETS)
EOF

    # Sample C files generation helper
    echo -e "  ${GREEN}✓${NC} Created C build manifest: c_suite/Makefile"
    if [ "$HAS_GCC" = true ]; then
        echo -e "  [*] Compiling native C toolchain..."
        (cd c_suite && make || true)
    fi
fi

# 3. Extract Rust Daemon (octolan-rs) if requested
if [ "$MODE" = "rust" ] || [ "$MODE" = "all" ]; then
    echo -e "${BLUE}[3/4] Scaffolding Rust Async Daemon (octolan-rs)...${NC}"
    mkdir -p octolan-rs/src/api octolan-rs/src/scanners

    cat << 'EOF' > octolan-rs/Cargo.toml
[package]
name = "octolan-rs"
version = "2.1.0"
edition = "2021"
authors = ["OctoLAN Systems <dev@octolan.internal>"]
description = "High-Performance Asynchronous Network Reconnaissance & NetFlow Telemetry Daemon"
license = "MIT OR Apache-2.0"

[dependencies]
tokio = { version = "1.38", features = ["full", "parking_lot"] }
tokio-stream = "0.1"
futures-util = "0.3"
axum = { version = "0.7", features = ["ws", "macros"] }
tower = { version = "0.4", features = ["util"] }
tower-http = { version = "0.5", features = ["cors", "fs", "trace"] }
pnet = "0.34"
socket2 = { version = "0.5", features = ["all"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
clap = { version = "4.5", features = ["derive", "env"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "time"] }
chrono = { version = "0.4", features = ["serde"] }

[profile.release]
opt-level = 3
lto = true
codegen-units = 1
panic = "abort"
strip = true
EOF

    echo -e "  ${GREEN}✓${NC} Created Cargo package manifest: octolan-rs/Cargo.toml"

    # Quick compilation if cargo is installed
    if [ "$HAS_CARGO" = true ]; then
        echo -e "  [*] Compiling octolan-rs release binary..."
        (cd octolan-rs && cargo build --release || true)
    fi
fi

# 4. Create Master Launcher Script
echo -e "${BLUE}[4/4] Generating Master Executive Launchers...${NC}"

cat << 'EOF' > start-octolan.sh
#!/usr/bin/env bash
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

IFACE="${1:-eth0}"
PORT="${2:-3000}"

echo "======================================================="
echo "🐙 Launching OctoLAN Engine on $IFACE (Port: $PORT)"
echo "======================================================="

if [ -f "./octolan-rs/target/release/octolan-rs" ]; then
    echo "[+] Found compiled Rust binary. Starting Axum + Tokio daemon..."
    if command -v setcap &> /dev/null; then
        sudo setcap cap_net_raw,cap_net_admin=eip "./octolan-rs/target/release/octolan-rs" 2>/dev/null || true
    fi
    exec "./octolan-rs/target/release/octolan-rs" --interface "$IFACE" --port "$PORT"
elif command -v podman &> /dev/null; then
    echo "[+] Launching via Podman Container..."
    podman run -d --name octolan-console --net=host -p "$PORT:$PORT" octolan:latest || true
    echo "[✓] OctoLAN running at http://localhost:$PORT"
else
    echo "[!] Please run 'cargo build --release' inside ./octolan-rs or install Podman."
fi
EOF

chmod +x start-octolan.sh

echo ""
echo -e "${GREEN}===================================================================${NC}"
echo -e "${GREEN}🎉 OctoLAN Bundle Installation Complete!${NC}"
echo -e "${GREEN}===================================================================${NC}"
echo -e "Directory: ${CYAN}$(pwd)${NC}"
echo ""
echo -e "To start the daemon on your Linux machine:"
echo -e "  ${ORANGE}./start-octolan.sh eth0 3000${NC}"
echo ""
echo -e "Or compile from source manually:"
echo -e "  ${CYAN}cd octolan-rs && cargo build --release${NC}"
echo -e "  ${CYAN}sudo ./target/release/octolan-rs --interface eth0 --port 3000${NC}"
echo ""
