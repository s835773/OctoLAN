#!/usr/bin/env bash
# ==============================================================================
# OctoLAN - Podman Container Launcher Helper Script
# ==============================================================================
set -euo pipefail

IMAGE_NAME="octolan:latest"
CONTAINER_NAME="octolan-console"
PORT="3000"

echo "=========================================================="
echo " 🐙 OctoLAN: Launching Podman Container"
echo "=========================================================="

# Check if podman is installed
if ! command -v podman &> /dev/null; then
    echo "[!] Error: Podman is not installed on this system."
    echo "    Install Podman via: sudo apt install podman (Debian/Ubuntu) or sudo dnf install podman (Fedora/RHEL)"
    exit 1
fi

# Parse flags
REBUILD=false
HOST_NET=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --build|-b)
      REBUILD=true
      shift
      ;;
    --host-net|-h)
      HOST_NET=true
      shift
      ;;
    --port|-p)
      PORT="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1"
      echo "Usage: $0 [--build] [--host-net] [--port <port>]"
      exit 1
      ;;
  esac
done

# Build container image if needed or requested
if [[ "$REBUILD" == true ]] || ! podman image exists "$IMAGE_NAME"; then
    echo "[+] Building Podman container image ($IMAGE_NAME) from Containerfile..."
    podman build -t "$IMAGE_NAME" -f Containerfile .
fi

# Stop and remove existing container if running
if podman container exists "$CONTAINER_NAME"; then
    echo "[*] Stopping and removing previous container instance..."
    podman rm -f "$CONTAINER_NAME" > /dev/null 2>&1 || true
fi

# Run container
if [[ "$HOST_NET" == true ]]; then
    echo "[+] Running container in HOST networking mode (native subnet visibility)..."
    podman run -d \
      --name "$CONTAINER_NAME" \
      --network host \
      --restart unless-stopped \
      "$IMAGE_NAME"
    echo "[✓] OctoLAN is running on host network! Access via http://localhost:3000"
else
    echo "[+] Running rootless container with port forwarding 0.0.0.0:${PORT} -> 3000..."
    podman run -d \
      --name "$CONTAINER_NAME" \
      -p "${PORT}:3000" \
      --restart unless-stopped \
      "$IMAGE_NAME"
    echo "[✓] OctoLAN is running! Access the console at: http://localhost:${PORT}"
fi

echo "=========================================================="
echo " Container Management Commands:"
echo "   - View logs:   podman logs -f ${CONTAINER_NAME}"
echo "   - Stop:        podman stop ${CONTAINER_NAME}"
echo "   - Status:      podman ps -f name=${CONTAINER_NAME}"
echo "=========================================================="
