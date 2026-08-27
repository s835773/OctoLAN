# OctoLAN: On-Premise Network Intelligence, NetFlow Telemetry & Storm Guard

<div align="center">

<img src="./public/octolan-mascot.svg" alt="OctoLAN Mascot" width="200" />

### *“8 Tentacles Probing Every Packet Across Your Broadcast Domain”*

**An educational, enterprise-grade on-premise network reconnaissance, flow telemetry, and broadcast watchdog suite.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](#license)
[![Mascot: Inky the Octo](https://img.shields.io/badge/Mascot-Inky%20the%20Octopus-238636.svg?logo=octopus-deploy&logoColor=white)](#-meet-the-mascot-inky-the-octolan-guardian)
[![POSIX C](https://img.shields.io/badge/Language-C99%20%2F%20POSIX-00599C.svg?logo=c&logoColor=white)](#-c-source-code-suite)
[![Architecture: Educational Standards](https://img.shields.io/badge/Architecture-Standards--Based%20Network%20Auditing-238636.svg)](#-architectural-overview)
[![NetFlow](https://img.shields.io/badge/Protocol-NetFlow%20v5%20%2F%20IPFIX-58a6ff.svg)](#2-netflow-v5--ipfix-telemetry-collector)
[![Storm Guard](https://img.shields.io/badge/Security-L2%20Storm%20Guard-da3633.svg)](#3-layer-2-broadcast-storm--stp-loop-watchdog)

</div>

---

## 🐙 Meet the Mascot: Inky the OctoLAN Guardian

**OctoLAN** is represented by **Inky**, a monochrome black cartoon octopus on a vibrant green badge. Inky's 8 cyber tentacles represent the 8 foundational network auditing and telemetry capabilities built directly into the platform:

```text
Tentacle 1: Layer 2 ARP           -> Raw Ethernet frame crafting (AF_PACKET / ETH_P_ARP)
Tentacle 2: Layer 3 ICMP          -> Raw socket ICMP echo sweeps with round-trip latency precision
Tentacle 3: Layer 4 OS Fingerprint-> Heuristic TCP SYN/ACK analysis of IP TTL, TCP Window, and DF bit
Tentacle 4: IEEE 802.1AB & VLAN   -> LLDP switch chassis discovery and 802.1Q VLAN trunk tag auditing
Tentacle 5: Passive Sniffer       -> Stealth capture of DHCP Option 12 hostnames, mDNS, and SSDP
Tentacle 6: NetFlow v5 & IPFIX    -> High-speed UDP listener on port 2055 extracting 5-tuple flows
Tentacle 7: Broadcast Storm Guard -> Promiscuous PPS accounting and Spanning Tree (STP) loop protection
Tentacle 8: POSIX C99 Engine      -> Standalone, zero-dependency C binaries for edge routers & Linux servers
```

### The 8 Capabilities:
* **Tentacle 1 (Layer 2 ARP)**: Raw Ethernet frame crafting (`AF_PACKET` / `ETH_P_ARP`) bypassing IP firewalls to uncover all active MAC addresses.
* **Tentacle 2 (Layer 3 ICMP)**: Raw socket ICMP echo sweeps with microsecond round-trip latency measurements.
* **Tentacle 3 (Layer 4 OS Fingerprinting)**: Heuristic inspection of initial IP TTL, TCP Window Size, and DF (Don't Fragment) flag.
* **Tentacle 4 (IEEE 802.1AB & VLAN)**: LLDP switch chassis discovery and IEEE 802.1Q tagged/untagged trunk verification.
* **Tentacle 5 (Zero-Footprint Passive Sniffer)**: Stealth listening on `eth0` for DHCP Option 12 client hostnames, mDNS announcements, and SSDP broadcasts without transmitting any packets.
* **Tentacle 6 (NetFlow v5 & IPFIX)**: High-throughput UDP listener on port 2055 aggregating conversation flows, byte counters, and protocol splits.
* **Tentacle 7 (Broadcast Storm Guard)**: Promiscuous Packets-Per-Second (PPS) meter and Spanning Tree (STP) bridging loop protector.
* **Tentacle 8 (POSIX C99 Static Engine)**: Standalone, zero-dependency C tools that compile statically for embedded routers, OpenWrt, and Linux environments.

---

## 📸 Key Modules & Functional Overview

### 1. Interactive Layer 2/3 Topology & Active Discovery Console

```text
GATEWAY: 192.168.1.1 (Cisco ISR 4451)
  │
  └── CORE-SW01: 192.168.1.2 (Cisco Catalyst 2960-X)
        ├── VLAN 10 (Corp Workstations): 192.168.10.0/24
        │     ├── 192.168.10.100 (Dell OptiPlex 7090 - Win11) [TTL: 128 | Win: 64512]
        │     ├── 192.168.10.101 (Apple MacBook Pro - macOS)  [TTL: 64  | Win: 65535]
        │     └── 192.168.10.102 (Ubuntu Linux Server - Linux) [TTL: 64  | Win: 29200]
        ├── VLAN 20 (Voice VoIP): 192.168.20.0/24
        │     └── 192.168.20.10  (Cisco IP Phone 8845 - SIP 5060)
        ├── VLAN 30 (Surveillance): 192.168.30.0/24
        │     └── 192.168.30.101 (Axis 4K Dome Camera - RTSP 554)
        └── VLAN 50 (IoT / Guest): 192.168.50.0/24
              └── 192.168.50.42  (Smart Thermostat - MQTT 1883)
```

* **Interactive Multi-View Layouts**: Switch seamlessly between Card Grid view, Hierarchical Tree view, and 2D Interactive Canvas Graph.
* **VLAN Cluster Grouping**: Organizes endpoints by 802.1Q broadcast domains with collapsible cluster hubs.
* **Deep Device Inspector**: Audits MAC vendor OUI allocations, TCP/UDP open ports, OS fingerprinting heuristics, and vulnerability risk scores.
* **Multi-Subnet Layer 2 Probing**: Promiscuous ARP and ICMP discovery capable of identifying stealth devices filtering ping requests.

---

### 2. NetFlow v5 & IPFIX Telemetry Collector

```text
NetFlow Collector: UDP Port 2055 | Active Flows: 8 | Cumulative Rate: 14.8 MB/s

TIME      SOURCE ENDPOINT          DESTINATION ENDPOINT     PROTO  PACKETS    OCTETS (BYTES)  FLAGS
17:18:02  192.168.10.101:54122     192.168.10.15:445 (SMB)  TCP    34,120     48,920,150 B    [ACK, PSH]
17:18:00  192.168.30.101:554(RTSP) 192.168.10.15:58920     TCP    14,200     18,450,000 B    [ACK, PSH]
17:17:58  192.168.10.102:49812     192.168.10.20:5432 (SQL) TCP     9,800     12,400,500 B    [ACK, PSH]
17:17:55  192.168.20.51:16402      192.168.20.10:10240      UDP     4,200        840,000 B    [-]
17:17:50  192.168.50.42:38910(IoT) 192.168.1.1:80 (MGMT!)  TCP       450         28,900 B    ⚠️ LEAK!
```

* **5-Tuple Flow Aggregation**: Decouples packet payload inspection by collecting unidirectional flow tuples:
  $$\text{Flow} = (\text{Src IP}, \text{Src Port}, \text{Dst IP}, \text{Dst Port}, \text{Proto}, \text{Octets}, \text{Packets}, \text{TCP Flags})$$
* **Top Talkers & Bandwidth Analyzer**: Identifies heavy bandwidth consumers and packet volume anomalies to spot unauthorized file transfers, streaming hogs, and egress spikes.
* **Inter-VLAN Boundary Leak Detection**: Flags unexpected traffic crossing isolated broadcast domains (e.g., IoT VLAN 50 sending packets directly to Management VLAN 1).
* **Native C UDP Daemon (`netflow_collector.c`)**: Listens on UDP port 2055 with zero dynamic memory allocations per packet for ultra-low latency processing.

---

### 3. Layer 2 Broadcast Storm & STP Loop Watchdog

```text
Interface: eth0 | Current Rate: 42 PPS | Alarm Threshold: 250 PPS | Status: NORMAL

Node Chatter Breakdown:
- 192.168.1.1 (Gateway):       18 PPS [Normal - ARP/Default Route]
- 192.168.10.100 (Workstation): 8 PPS [Normal - NetBIOS/mDNS]
- 192.168.10.101 (Workstation): 6 PPS [Normal - SSDP]
- 192.168.50.254 (Rogue Hub): 380 PPS [CRITICAL - Storm / Bridging Loop]

STP Diagnostic: BPDU Guard Enabled | PortFast Filtering Active | Status: 0 Loops Detected
```

* **Dynamic Chatter & Pulse Rings**: Visualizes expanding halo rings around nodes exhibiting elevated broadcast (`FF:FF:FF:FF:FF:FF`) or multicast (`01:00:5E` / `33:33`) output.
* **Real-Time PPS Threshold Meter**: Live gauge tracking Layer 2 chatter against user-configurable Packets-Per-Second (PPS) alarm triggers.
* **Spanning Tree Protocol (STP) Diagnostics**: Isolates unmanaged hub bridging loops and ARP flooding storms before switch control-plane CPU exhaustion occurs.
* **Promiscuous C Sniffer (`storm_detector.c`)**: Directly taps `AF_PACKET` with `ETH_P_ALL` to calculate per-second L2 broadcast metrics.

---

### 4. Continuous Presence & Anomaly Alerting Engine

```text
Alert Engine: Active Rules: 4/4 | Dispatch Channels: SMTP + Webhook JSON

Recent Dispatches:
- [CRITICAL] 17:15:10 - Rogue Access Point Broadcast (SSID: "CORP-GUEST-FREE", BSSID: 00:14:22:98:76:54)
- [HIGH]     17:10:04 - Inter-VLAN Boundary Leak (VLAN 50 IoT host 192.168.50.42 -> VLAN 1 Switch HTTP)
- [INFO]     17:02:11 - New Authorized Device Joined (MAC: 3c:22:fb:11:22:33, Hostname: "MacBook-Air")
- [STATUS]   Webhook Dispatcher: Payload delivered to https://api.corp.internal/hooks/lan-alerts (HTTP 200 OK)
```

* **Automated Anomaly Detection**: Generates instant notifications when newly connected MAC addresses, rogue APs, or abnormal port states appear.
* **Multi-Channel Dispatch**:
  * **SMTP Email Notifications**: Automated incident summaries with source IP, MAC vendor, and recommended mitigation actions.
  * **Webhook Integration**: Direct JSON payload delivery to webhook endpoints and log management systems.
* **Interactive Simulator**: Test webhook and email endpoints on demand directly from the UI.

---

### 5. 802.1Q VLAN Segmentation & Trunk Audit

* **VLAN Matrix**: Visualizes Management (VLAN 1), Corporate Workstations (VLAN 10), Voice VoIP (VLAN 20), Surveillance (VLAN 30), and Guest/IoT (VLAN 50).
* **Trunk Tagging Verifier**: Parses IEEE 802.1Q 4-byte tags (`TPID 0x8100` + `TCI: PCP/VID`) to verify untagged access vs. tagged trunk configurations.
* **Broadcast Isolation Score**: Evaluates subnet segregation health to minimize cross-boundary attack surfaces.

---

### 6. AI Network Hygiene Advisor

* **Automated Security Auditing**: Analyzes all discovered devices, open ports, and flow anomalies to generate an actionable hardening checklist.
* **Vendor-Neutral CLI Remediation**: Generates ready-to-paste CLI commands for standard network operating systems (Cisco IOS, Linux iptables/nftables, MikroTik, Ubiquiti).

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
git clone https://github.com/example/octolan.git
cd octolan

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
