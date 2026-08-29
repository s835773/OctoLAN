# OctoLAN Rust Daemon (`octolan-rs`)
**High-Performance Asynchronous Network Reconnaissance & NetFlow Telemetry Engine**

Built with **Rust (Edition 2021)**, **Tokio (Multi-Threaded Async Runtime)**, **Axum v0.7 (REST & WebSockets)**, and **pnet (Raw AF_PACKET Network Capture)**.

---

## Architecture Overview

```
                        ┌──────────────────────────────────────────────────────────┐
                        │             octolan-rs Native Engine (Rust)              │
                        │                                                          │
   Physical Interface   │  ┌────────────────┐    ┌───────────────────────────────┐ │
   (e.g., eth0, enp3s0) ┼─►│ pnet Raw Socket│───►│ Tokio Async Multi-Core Workers│ │
   [CAP_NET_RAW]        │  └────────────────┘    └───────────────┬───────────────┘ │
                        │                                        │                 │
   NetFlow UDP :2055    │  ┌────────────────┐                    ▼                 │
   Ingestion Stream     ┼─►│ Tokio UdpSocket│───►┌───────────────────────────────┐ │
                        │  └────────────────┘    │ broadcast::channel (Telemetry)│ │
                        │                        └───────────────┬───────────────┘ │
                        │                                        │                 │
                        │                                        ▼                 │
                        │                    ┌───────────────────────────────────┐ │
                        │                    │   Axum v0.7 Web & WebSocket Server│ │
                        │                    └───────────────────┬───────────────┘ │
                        └────────────────────────────────────────┼─────────────────┘
                                                                 │
                                                       HTTP:3000 │ WebSocket /ws/telemetry
                                                                 ▼
                                                  ┌───────────────────────────────┐
                                                  │ React LAN Auditor Dashboard   │
                                                  └───────────────────────────────┘
```

---

## Features

- **Blazing Fast ARP Sweep**: Probes an entire `/24` subnet in sub-seconds using zero-copy packet structures.
- **Async NetFlow v5/v9 Collector**: Consumes high-throughput flow datagrams over UDP `2055` without blocking.
- **Broadcast Storm Watchdog**: Real-time sliding window packet frequency counter alerting on PPS threshold breaches.
- **OS & Banner Fingerprinting**: Probes TCP stack characteristics, initial TTL, and service ports.
- **Embedded Web & WebSocket Daemon**: Axum backend pushing live metrics to React frontend over `/ws/telemetry`.
- **Zero-Privilege Capability Support**: Operates under unprivileged users with Linux `CAP_NET_RAW` / `CAP_NET_ADMIN`.

---

## Quickstart

### 1. Build and Run via Cargo
```bash
# Clone and enter directory
cd octolan-rs

# Compile release binary
cargo build --release

# Run with raw socket capability
sudo ./target/release/octolan-rs --interface eth0 --port 3000
```

### 2. Standalone CLI Subcommands
```bash
# Run one-off ARP sweep
cargo run --release -- scan --subnet 192.168.1.0/24

# Launch Broadcast Storm Watchdog CLI
cargo run --release -- storm-watch --threshold-pps 2500
```

### 3. Containerized Run (Podman / Docker)
```bash
# Build lightweight multi-stage container
podman build -t octolan-rs:latest -f Dockerfile.rust .

# Run with host networking & packet raw capabilities
podman run -d \
  --name octolan-rs \
  --net=host \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  -p 3000:3000 \
  -p 2055:2055/udp \
  octolan-rs:latest
```
