# OctoLAN

**Portable network discovery, mapping and posture assessment for MSP field techs.**

Plug a laptop into a customer's network, run one file, and get a live map of the network, a full device inventory, traffic and layer-2 health monitoring, and a scored security-posture report you can hand to the customer. No installer, no runtime, no agents, no cloud.

```
octolan            # opens the live dashboard in your browser
octolan scan       # or run the whole assessment from the terminal
```

One self-contained binary per platform: Windows, macOS and Linux (x86-64 and ARM), plus OpenWrt/embedded Linux (MIPS, ARM). Nothing else to install.

---

## What it does

| | Capability | How |
|---|---|---|
| 1 | **Layer-2 ARP discovery** | Crafts raw ARP who-has frames (AF_PACKET / BPF / Npcap) to find every live MAC on the segment, even hosts that firewall ICMP and TCP. Falls back to the Windows `SendARP` API or the OS ARP cache when raw access isn't available. |
| 2 | **ICMP sweep** | Rate-limited echo sweep with microsecond round-trip timing and TTL capture (raw sockets, unprivileged datagram ICMP, or the Windows ICMP API, whichever the host allows). |
| 3 | **OS fingerprinting** | Initial TTL, TCP window, DF bit and MSS from the SYN-ACKs of the service scan; Windows build/version from the anonymous SMB/NTLM handshake; SNMP sysDescr; service banners; Bonjour model IDs; DHCP vendor class. Flags end-of-life systems. |
| 4 | **LLDP/CDP and VLANs** | Hears LLDP/CDP from the switch port it's plugged into (switch name, port, native VLAN); polls LLDP-MIB and CDP tables over SNMP and **crawls neighbor management addresses**; learns VLANs from Q-BRIDGE / Cisco VTP, LLDP 802.1 TLVs and 802.1Q tags on the wire. |
| 5 | **Zero-footprint passive listener** | DHCP hostnames, vendor classes and **rogue DHCP servers**; mDNS/Bonjour; SSDP/UPnP; any host that talks on the segment. *Zero-footprint mode* never transmits a single packet. |
| 6 | **NetFlow v5 / v9 / IPFIX collector** | UDP 2055 listener with template handling; top talkers, applications, protocol mix, conversations and throughput over time. |
| 7 | **Storm Guard** | Promiscuous per-second broadcast / multicast / unicast / ARP metering, repeated-frame (loop) detection, top broadcasters, spanning-tree root bridge, root changes and topology-change floods. |
| 8 | **Runs on routers and edge devices** | The same Go code cross-compiles to static Linux binaries for MIPS/ARM routers (OpenWrt) and servers. No C toolchain or separate C engine needed. |

Plus the inventory and mapping you'd expect from a network management platform:

- **SNMP v1/v2c/v3 inventory**: system info, interfaces (speed, status, errors, traffic), model/serial/firmware (ENTITY-MIB), switch MAC tables, router ARP tables (finds hosts on *other* VLANs), VLAN names.
- **Topology map** built from LLDP/CDP adjacencies, then switch forwarding tables (which edge port each device is on), then subnet clouds for everything else. Drag, zoom, search, infrastructure-only view.
- **Device classification**: router, firewall, switch, AP, server, workstation, hypervisor, NAS, printer, VoIP phone, camera, mobile, media, IoT, UPS. Uses SNMP, ports, banners, OUI vendor (embedded IEEE registry), mDNS and DHCP evidence. Techs can correct the type, name and notes in the UI.
- **Name resolution**: reverse DNS, NetBIOS node status, unicast mDNS, SMB/NTLM computer and domain names.
- **Security posture checks**, scored 0–100 with a letter grade:
  Telnet/FTP, Cisco Smart Install, unauthenticated Docker/Redis/Elasticsearch/MongoDB, VNC, RDP on workstations, TR-069, PPTP, plain-HTTP management UIs, default SNMP communities, SNMPv1/v2c, SMBv1, SMB signing not required, end-of-life OS, old OpenSSH, expired/expiring/self-signed certificates, legacy TLS, UPnP on the gateway, rogue DHCP, duplicate IPs, broadcast storms, STP instability/root changes/default priority, flat networks, IoT not segmented, interface errors, high latency, long uptime (unpatched).
- **Reports**: a single self-contained HTML report (interactive map, executive summary, priority actions, findings with remediation, full inventory, methodology). Print to PDF straight from the browser. Also CSV (devices, findings) and JSON session files.

## Quick start

1. Download the binary for your laptop from [Releases](../../releases) (or build it, below).
2. Plug into the customer network (ideally a normal access port in the main VLAN).
3. Run it:

| OS | Full capability | Without admin rights |
|---|---|---|
| **macOS** | `sudo ./octolan-darwin-universal` | `./octolan-darwin-universal` |
| **Linux** | `sudo ./octolan-linux-amd64` | `./octolan-linux-amd64` |
| **Windows** | Install free [Npcap](https://npcap.com), then run `octolan-windows-amd64.exe` | Just run it |

The dashboard opens at `http://127.0.0.1:8484`. Enter the customer name, click **New assessment**, and watch the map fill in. When it's done, **Export → Open report** and print to PDF.

> **First run on macOS:** downloaded binaries are quarantined by Gatekeeper. Run `xattr -d com.apple.quarantine ./octolan-darwin-universal` once (or right-click → Open).
> **Windows SmartScreen** may warn about an unsigned executable: *More info → Run anyway*.

### What raw capture adds

Without admin/root (or Npcap on Windows) OctoLAN still discovers devices via ping, the OS ARP cache, TCP, SNMP, SMB, DNS, NetBIOS and mDNS. Raw packet access adds:
ARP sweeps (finds firewalled hosts), passive DHCP/LLDP/CDP/STP/VLAN listening, Storm Guard, and SYN-ACK stack fingerprinting. The sidebar shows which mode you're in and why.

On Linux you can grant raw access once instead of using sudo:
`sudo setcap cap_net_raw,cap_net_admin+ep ./octolan-linux-amd64`

## Command line

```
octolan [serve]          Live dashboard (default)
  -site "Acme Dental"     customer / site name
  -iface en0              interface (default: the one with the default route)
  -listen 0.0.0.0:8484    share the dashboard with teammates (prints a tokenized URL)
  -netflow :2055          start the NetFlow collector too
  -load session.json      reopen a saved assessment
  -scan                   start an assessment immediately

octolan scan             Full assessment in the terminal; writes report + session
  -t 10.0.0.0/24 -t 10.0.5.1-50   targets (default: local subnet)
  -c public -c s3cr3t             SNMP communities (default: public, private)
  -v3 user:SHA:authpass:AES:privpass
  -ports default|top|none|22,80,8000-8100
  -passive 180                    seconds of passive listening (DHCP/LLDP/STP)
  -zero-footprint                 listen only; never transmit
  -rate 400                       sweep packets/second
  -out ./reports

octolan report session.json      Rebuild the HTML report from a saved session
octolan storm [-warn 1000 -crit 5000]   Live broadcast-storm / STP meter
octolan netflow [-listen :2055]  NetFlow/IPFIX collector with live top talkers
octolan passive [-seconds 300]   Listen-only discovery
octolan interfaces               Interfaces and what this host can do
```

Sessions and reports are saved under `~/OctoLAN/<site>/`. SNMP communities and v3 passwords are held in memory only and are never written to session files or reports.

## Using it on site: tips

- **Get the most from SNMP**: ask the customer for the read-only community (or v3 user). Switch MAC tables and LLDP/CDP neighbors are what turn a device list into an accurate map.
- **NetFlow**: point the firewall's flow export at the laptop's IP, UDP 2055, and leave the dashboard open for a while.
- **Mirror/SPAN port**: plugging into a mirror port gives Storm Guard and the passive listener visibility of the whole switch.
- **Routed subnets**: add other VLANs' CIDRs as targets. Routers' ARP tables (via SNMP) also reveal hosts there.
- **Sensitive environments** (medical, OT/ICS): use *Zero-footprint mode* first, then decide on active scanning.
- **Share with a teammate**: `octolan -listen 0.0.0.0:8484` prints a URL with an access token. Without `-listen`, the dashboard is only reachable from the laptop itself.

Only scan networks you are authorized to assess.

## Building

Requires Go 1.27+. No cgo, no C libraries.

```
go build ./cmd/octolan        # this machine
./scripts/build.sh           # all platforms → ./dist (with SHA256SUMS)
go test -race ./...
```

To refresh the embedded MAC-vendor table:

```
curl -fsSLo manuf https://www.wireshark.org/download/automated/data/manuf
go run ./tools/genoui manuf internal/oui/oui.txt.gz
```

### Layout

```
cmd/octolan          CLI entry point
internal/capture    raw Ethernet I/O: AF_PACKET (Linux), BPF (macOS/BSD), Npcap loaded at runtime (Windows)
internal/discovery  ARP, ICMP, TCP + banners, SYN-ACK fingerprinting, TLS, SMB/NTLM, names, SNMP, classifier
internal/passive    listen-only discovery (DHCP, LLDP, CDP, mDNS, SSDP, 802.1Q)
internal/storm      Storm Guard (PPS meter, loop detection, STP)
internal/netflow    NetFlow v5/v9/IPFIX collector
internal/topology   map builder
internal/assess     posture checks and scoring
internal/engine     scan pipeline and monitors
internal/report     HTML/CSV reports
internal/web        dashboard API (JSON + server-sent events)
internal/ui/static  dashboard front end (vanilla JS, embedded)
```
