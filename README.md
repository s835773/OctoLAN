# OcuLAN: On-Premise Network Intelligence, NetFlow Telemetry & Storm Guard

<div align="center">

![OcuLAN Banner](https://images.unsplash.com/photo-1558494949-ef010cbdcc31?auto=format&fit=crop&w=1200&q=80)

**An educational, enterprise-grade on-premise network reconnaissance, flow telemetry, and broadcast watchdog suite.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](#license)
[![POSIX C](https://img.shields.io/badge/Language-C99%20%2F%20POSIX-00599C.svg?logo=c&logoColor=white)](#c-source-suite)
[![Architecture: Educational Standards](https://img.shields.io/badge/Architecture-Standards--Based%20Network%20Auditing-238636.svg)](#architectural-overview)
[![NetFlow](https://img.shields.io/badge/Protocol-NetFlow%20v5%20%2F%20IPFIX-58a6ff.svg)](#1-netflow-v5--ipfix-telemetry-collector)
[![Storm Guard](https://img.shields.io/badge/Security-L2%20Storm%20Guard-da3633.svg)](#2-layer-2-broadcast-storm--stp-loop-watchdog)

</div>

---

## 🌟 Overview & Educational Objectives

**OcuLAN** is an on-premise network intelligence platform designed to demonstrate modern network auditing, telemetry collection, and Layer 2 broadcast protection paradigms. 

Built specifically for educational study, network administration training, and security research, OcuLAN pairs an interactive visual console with a standalone, zero-dependency native **POSIX C99 toolkit** capable of running on edge routers, embedded hardware, and Linux servers without third-party runtime dependencies.

All modules are designed around open, vendor-neutral networking RFCs and IEEE standards (IEEE 802.1Q, 802.1D, 802.1AB, RFC 3954, RFC 7011).

---

## 📸 Key Features & Architecture

### 1. Interactive Layer 2/3 Topology & Active Discovery
![Network Topology & Discovery](https://images.unsplash.com/photo-1544197150-b99a580bb7a8?auto=format&fit=crop&w=1200&q=80)

- **Dynamic Node Graph**: Visualizes Core Gateways, Managed Switches, 802.1Q VLAN clusters, and connected endpoints with real-time operational status.
- **Deep Device Inspector**: Audits MAC vendor OUI allocations, TCP/UDP open ports, OS fingerprinting heuristics (IP TTL + TCP Window size), and CVE vulnerability profiles.
- **Multi-Subnet Layer 2 Probing**: Promiscuous ARP and ICMP discovery capable of identifying stealth devices that filter standard ping requests.

---

### 2. NetFlow v5 & IPFIX Telemetry Collector
![NetFlow Telemetry & Analytics](https://images.unsplash.com/photo-1551288049-bebda4e38f71?auto=format&fit=crop&w=1200&q=80)

- **5-Tuple Flow Aggregation**: Decouples packet payload inspection by collecting unidirectional flow tuples:
  $$\text{Flow} = (\text{Src IP}, \text{Src Port}, \text{Dst IP}, \text{Dst Port}, \text{Proto}, \text{Octets}, \text{Packets}, \text{TCP Flags})$$
- **Top Talkers & Bandwidth Analyzer**: Identifies heavy bandwidth consumers and packet volume anomalies to spot unauthorized file transfers, streaming hogs, and egress spikes.
- **Inter-VLAN Boundary Leak Detection**: Flags unexpected traffic crossing isolated broadcast domains (e.g., IoT VLAN 50 sending packets directly to Management VLAN 1).
- **Native C UDP Daemon (`netflow_collector.c`)**: Listens on UDP port 2055 with zero dynamic memory allocations per packet for ultra-low latency processing.

---

### 3. Layer 2 Broadcast Storm & STP Loop Watchdog
![Broadcast Storm Watchdog & Flow Rings](https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?auto=format&fit=crop&w=1200&q=80)

- **Dynamic Flow & Chatter Rings**: Circular topology diagram featuring real-time expanding halo rings around nodes exhibiting elevated broadcast (`FF:FF:FF:FF:FF:FF`) or multicast (`01:00:5E` / `33:33`) frame output.
- **Real-Time PPS Threshold Meter**: Live gauge tracking Layer 2 chatter against user-configurable Packets-Per-Second (PPS) alarm triggers.
- **Spanning Tree Protocol (STP) Diagnostics**: Isolates unmanaged hub bridging loops and ARP flooding storms before switch control-plane CPU exhaustion occurs.
- **Promiscuous C Sniffer (`storm_detector.c`)**: Directly taps `AF_PACKET` with `ETH_P_ALL` to calculate per-second L2 broadcast metrics.

---

### 4. Continuous Presence & Anomaly Alerting Engine
![Continuous Alerting Engine](https://images.unsplash.com/photo-1563986768609-322da13575f3?auto=format&fit=crop&w=1200&q=80)

- **Automated Anomaly Detection**: Generates notifications when newly connected MAC addresses, rogue APs, or abnormal port states appear.
- **Multi-Channel Dispatch**:
  - **SMTP Email Notifications**: Automated incident summaries with source IP, MAC vendor, and recommended mitigation actions.
  - **Webhook Integration**: Direct JSON payload delivery to webhook endpoints and log management systems.
- **Interactive Simulator**: Test webhook and email endpoints on demand directly from the UI.

---

### 5. 802.1Q VLAN Segmentation & Trunk Audit
![VLAN Segmentation Matrix](https://images.unsplash.com/photo-1544716278-ca5e3f4abd8c?auto=format&fit=crop&w=1200&q=80)

- **VLAN Matrix**: Visualizes Management (VLAN 1), Corporate Workstations (VLAN 10), Voice VoIP (VLAN 20), Surveillance (VLAN 30), and Guest/IoT (VLAN 50).
- **Trunk Tagging Verifier**: Parses IEEE 802.1Q 4-byte tags (`TPID 0x8100` + `TCI: PCP/VID`) to verify untagged access vs. tagged trunk configurations.
- **Broadcast Isolation Score**: Evaluates subnet segregation health to minimize cross-boundary attack surfaces.

---

### 6. AI Network Hygiene Advisor
- **Automated Security Auditing**: Analyzes all discovered devices, open ports, and flow anomalies to generate an actionable hardening checklist.
- **Vendor-Neutral & CLI Remediation**: Generates ready-to-paste CLI commands for standard network operating systems (Cisco IOS, Linux iptables/nftables, MikroTik, Ubiquiti).

---

## 🛠️ C Source Code Suite

All scanning and telemetry tools are written in clean, dependency-free POSIX C99.

| Filename | Description | Protocol / Socket | Privileges |
| :--- | :--- | :--- | :--- |
| `netflow_collector.c` | UDP NetFlow v5 collector on port 2055 with 5-tuple flow parser | `SOCK_DGRAM` (UDP) | Standard User |
| `storm_detector.c` | Promiscuous broadcast PPS meter & STP loop watchdog | `AF_PACKET` (`ETH_P_ALL`) | `CAP_NET_RAW` / Root |
| `arp_scan.c` | High-speed Layer 2 MAC/vendor discovery sweep | `AF_PACKET` (`ETH_P_ARP`) | `CAP_NET_RAW` / Root |
| `icmp_sweep.c` | Multi-threaded raw socket ICMP echo probe | `AF_INET` (`IPPROTO_ICMP`) | `CAP_NET_RAW` / Root |
| `os_fingerprint.c` | TCP SYN / TTL / Window Size OS identification | `SOCK_RAW` / `IPPROTO_TCP` | `CAP_NET_RAW` / Root |
| `lldp_vlan_sniff.c` | IEEE 802.1AB LLDP & 802.1Q VLAN tag decoder | `AF_PACKET` (`ETH_P_ALL`) | `CAP_NET_RAW` / Root |
| `passive_monitor.c` | Zero-footprint passive DHCP, mDNS & ARP listener | `AF_PACKET` (`ETH_P_ALL`) | `CAP_NET_RAW` / Root |
| `lan_recon.sh` | Zero-dependency Bash orchestrator using native `/proc` & `/sys` | Bash + standard POSIX utils | Standard User |

---

## 🚀 Quick Start & Compilation

### Build All C Tools
```bash
# 1. Clone repository
git clone https://github.com/example/oculan.git
cd oculan

# 2. Build with native GCC
make

# 3. Build fully static portable binaries (works on Alpine, OpenWrt, minimal containers)
make static

# 4. Cross-compile for ARM / Raspberry Pi
make arm
```

### Running the NetFlow Collector
```bash
# Start NetFlow v5 listener on UDP port 2055
./netflow_collector 2055
```

### Running the Broadcast Storm Watchdog
```bash
# Monitor eth0 with a threshold of 250 broadcast PPS
sudo ./storm_detector eth0 250
```

### Running the Full LAN Reconnaissance Sweep
```bash
# Execute native ARP discovery on eth0
sudo ./arp_scan eth0 192.168.1.0/24
```

---

## 🔬 Architectural Overview

| Auditing Layer | Core Mechanism | Purpose | Primary Protocols |
| :--- | :--- | :--- | :--- |
| **Layer 2 Topology** | Raw Frame Snooping & Link Layer Discovery | Map physical adjacency and switchports | ARP, IEEE 802.1AB (LLDP), CDP |
| **Flow Telemetry** | Unidirectional 5-Tuple Aggregation | Bandwidth accounting & conversation tracking | NetFlow v5/v9, IPFIX (RFC 7011) |
| **Storm Guard** | Promiscuous PPS Rate Accounting | Prevent network outage from loops and floods | Ethernet Broadcast, STP BPDU (IEEE 802.1D) |
| **Segment Isolation** | 802.1Q Tag Inspection & ACL Auditing | Enforce broadcast domain isolation | IEEE 802.1Q, IP Subnetting |
| **Presence Alerting** | Continuous MAC & Lease Monitoring | Detect rogue and unauthorized network joins | DHCP Snooping, ARP Resolution |

---

## 🛡️ License

This project is distributed under the **MIT License**. Created strictly for educational, research, and network engineering training purposes.
