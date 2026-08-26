import { NetworkDevice, VlanInfo, ProtocolStat, ScanProfile } from '../types';

export const INITIAL_VLANS: VlanInfo[] = [
  {
    id: 1,
    name: 'Default / Management',
    subnet: '192.168.1.0/24',
    gateway: '192.168.1.1',
    deviceCount: 4,
    color: '#238636', // GitHub Green (MGMT)
    description: 'Network management layer, switches, firewalls, and hypervisors',
    securityZone: 'Management',
    isolated: false,
  },
  {
    id: 10,
    name: 'Corporate Servers & LAN',
    subnet: '192.168.10.0/24',
    gateway: '192.168.10.1',
    deviceCount: 6,
    color: '#1f6feb', // Blue (DATA)
    description: 'Active Directory domain controllers, file servers, databases, and workstations',
    securityZone: 'Trusted',
    isolated: false,
  },
  {
    id: 20,
    name: 'VoIP & Unified Comms',
    subnet: '192.168.20.0/24',
    gateway: '192.168.20.1',
    deviceCount: 3,
    color: '#58a6ff', // Light Blue
    description: 'SIP phones, PBX server, and video conferencing endpoints',
    securityZone: 'Restricted',
    isolated: false,
  },
  {
    id: 30,
    name: 'IoT & Physical Security',
    subnet: '192.168.30.0/24',
    gateway: '192.168.30.1',
    deviceCount: 5,
    color: '#d29922', // Amber
    description: 'IP security cameras, badge access controllers, smart thermostats, and printers',
    securityZone: 'IoT',
    isolated: true,
  },
  {
    id: 50,
    name: 'Guest Wi-Fi',
    subnet: '192.168.50.0/24',
    gateway: '192.168.50.1',
    deviceCount: 4,
    color: '#da3633', // Red (UNTRUSTED / GUEST)
    description: 'Isolated guest subnet with client isolation enabled',
    securityZone: 'Guest',
    isolated: true,
  }
];

export const INITIAL_DEVICES: NetworkDevice[] = [
  {
    id: 'dev-gw-01',
    ip: '192.168.1.1',
    mac: '00:0c:29:4f:8a:12',
    vendor: 'pfSense / FreeBSD',
    hostname: 'edge-firewall.corp.local',
    deviceType: 'firewall',
    vlanId: 1,
    vlanName: 'Default / Management',
    subnet: '192.168.1.0/24',
    osFingerprint: {
      name: 'FreeBSD 14.0-RELEASE (pfSense)',
      family: 'BSD',
      accuracy: 98,
      initialTtl: 64,
      tcpWindowSize: 65535,
      details: 'SYN packet DF bit set, TCP Options: MSS(1460), SACK_PERM, TS, WS(7)'
    },
    ports: [
      { port: 22, protocol: 'tcp', service: 'ssh', state: 'open', version: 'OpenSSH 9.6p1 FreeBSD-20240101' },
      { port: 443, protocol: 'tcp', service: 'https', state: 'open', version: 'nginx/1.24.0 (pfSense WebGUI)' },
      { port: 53, protocol: 'udp', service: 'domain', state: 'open', version: 'Unbound 1.19.1 DNS Resolver' },
      { port: 123, protocol: 'udp', service: 'ntp', state: 'open', version: 'ntpd 4.2.8p17' }
    ],
    activeProtocols: ['SSH', 'HTTPS', 'DNS', 'NTP', 'CARP', '802.1Q'],
    firstSeen: '2026-08-26 09:10:00',
    lastSeen: '2026-08-26 09:44:12',
    status: 'online',
    latencyMs: 0.8,
    riskScore: 'Low',
    riskFactors: ['Web management accessible on management VLAN interface']
  },
  {
    id: 'dev-sw-core',
    ip: '192.168.1.2',
    mac: '70:69:79:ab:cd:10',
    vendor: 'Cisco Systems',
    hostname: 'core-sw01.corp.local',
    deviceType: 'switch',
    vlanId: 1,
    vlanName: 'Default / Management',
    subnet: '192.168.1.0/24',
    osFingerprint: {
      name: 'Cisco IOS-XE 17.9.3 (Catalyst 9300)',
      family: 'Cisco IOS',
      accuracy: 96,
      initialTtl: 255,
      tcpWindowSize: 4128,
      details: 'TTL 255 with characteristic Cisco SYN ACK window size and TCP timestamps'
    },
    ports: [
      { port: 22, protocol: 'tcp', service: 'ssh', state: 'open', version: 'Cisco SSH 2.0' },
      { port: 161, protocol: 'udp', service: 'snmp', state: 'open', version: 'SNMPv2c/v3', isRisky: true, riskReason: 'Default community string "public" active' },
      { port: 443, protocol: 'tcp', service: 'https', state: 'open', version: 'Cisco Web UI' }
    ],
    activeProtocols: ['SSH', 'SNMP', 'LLDP', 'CDP', 'STP', '802.1Q', 'VTP'],
    firstSeen: '2026-08-26 09:10:05',
    lastSeen: '2026-08-26 09:44:10',
    status: 'online',
    latencyMs: 1.2,
    riskScore: 'Medium',
    riskFactors: ['SNMPv2c community string accessible', 'CDP broadcasts leaking internal switchport and VTP domain details'],
    lldpNeighbor: {
      chassisId: '70:69:79:ab:cd:00',
      systemName: 'core-sw01',
      portId: 'TenGigabitEthernet1/1/1',
      vlanTagged: true
    }
  },
  {
    id: 'dev-sw-edge1',
    ip: '192.168.1.10',
    mac: 'e4:aa:5d:22:33:44',
    vendor: 'Ubiquiti UniFi',
    hostname: 'unifi-sw-floor2.corp.local',
    deviceType: 'switch',
    vlanId: 1,
    vlanName: 'Default / Management',
    subnet: '192.168.1.0/24',
    osFingerprint: {
      name: 'Linux 5.4 (UniFi USW-Pro-24-PoE)',
      family: 'Linux',
      accuracy: 94,
      initialTtl: 64,
      tcpWindowSize: 29200,
      details: 'Embedded Linux kernel on ARM Cortex-A53'
    },
    ports: [
      { port: 22, protocol: 'tcp', service: 'ssh', state: 'open', version: 'Dropbear sshd 2020.81' },
      { port: 8080, protocol: 'tcp', service: 'http', state: 'open', version: 'UniFi Controller Inform' }
    ],
    activeProtocols: ['SSH', 'LLDP', 'STP', '802.1Q', 'mDNS'],
    firstSeen: '2026-08-26 09:10:10',
    lastSeen: '2026-08-26 09:44:11',
    status: 'online',
    latencyMs: 1.5,
    riskScore: 'Low',
    riskFactors: []
  },
  {
    id: 'dev-ap-01',
    ip: '192.168.1.15',
    mac: '74:83:c2:91:0a:ff',
    vendor: 'Ubiquiti Networks',
    hostname: 'u6-pro-main-hall',
    deviceType: 'access_point',
    vlanId: 1,
    vlanName: 'Default / Management',
    subnet: '192.168.1.0/24',
    osFingerprint: {
      name: 'Linux 5.15 (UniFi Access Point)',
      family: 'Linux',
      accuracy: 92,
      initialTtl: 64,
      tcpWindowSize: 29200,
      details: 'OpenWrt-based custom Linux distribution'
    },
    ports: [
      { port: 22, protocol: 'tcp', service: 'ssh', state: 'open', version: 'Dropbear sshd' }
    ],
    activeProtocols: ['SSH', '802.11ax', '802.1Q', 'LLDP'],
    firstSeen: '2026-08-26 09:10:12',
    lastSeen: '2026-08-26 09:44:00',
    status: 'online',
    latencyMs: 2.1,
    riskScore: 'Low',
    riskFactors: []
  },
  // VLAN 10 (Corporate Servers & LAN)
  {
    id: 'dev-srv-dc01',
    ip: '192.168.10.10',
    mac: '00:50:56:b1:44:77',
    vendor: 'VMware Inc (Virtual Machine)',
    hostname: 'CORP-DC01.corp.local',
    deviceType: 'server',
    vlanId: 10,
    vlanName: 'Corporate Servers & LAN',
    subnet: '192.168.10.0/24',
    osFingerprint: {
      name: 'Microsoft Windows Server 2022 Datacenter',
      family: 'Windows',
      accuracy: 99,
      initialTtl: 128,
      tcpWindowSize: 64512,
      details: 'TTL 128, TCP MWS 64512, Windows RPC Endpoint Mapper + Kerberos & LDAP'
    },
    ports: [
      { port: 53, protocol: 'tcp', service: 'domain', state: 'open', version: 'Microsoft DNS 10.0.20348' },
      { port: 88, protocol: 'tcp', service: 'kerberos-sec', state: 'open', version: 'Microsoft Windows Kerberos' },
      { port: 135, protocol: 'tcp', service: 'msrpc', state: 'open', version: 'Microsoft Windows RPC' },
      { port: 139, protocol: 'tcp', service: 'netbios-ssn', state: 'open', version: 'NetBIOS-SSN', isRisky: true, riskReason: 'Legacy NetBIOS over TCP active' },
      { port: 389, protocol: 'tcp', service: 'ldap', state: 'open', version: 'Microsoft Windows Active Directory LDAP' },
      { port: 445, protocol: 'tcp', service: 'microsoft-ds', state: 'open', version: 'Windows Server 2022 SMBv3' },
      { port: 636, protocol: 'tcp', service: 'ldaps', state: 'open', version: 'Active Directory LDAPS' },
      { port: 3389, protocol: 'tcp', service: 'ms-wbt-server', state: 'open', version: 'Microsoft Terminal Services (RDP)', isRisky: true, riskReason: 'RDP enabled with NLA' }
    ],
    activeProtocols: ['Kerberos', 'LDAP', 'DNS', 'SMBv3', 'MSRPC', 'LLMNR', 'NetBIOS'],
    firstSeen: '2026-08-26 09:11:00',
    lastSeen: '2026-08-26 09:44:20',
    status: 'online',
    latencyMs: 1.1,
    riskScore: 'High',
    riskFactors: ['Legacy NetBIOS port 139 active', 'LLMNR broadcasts detected on LAN', 'Active Directory Domain Controller holds high value credentials']
  },
  {
    id: 'dev-srv-file01',
    ip: '192.168.10.15',
    mac: '00:50:56:b1:44:88',
    vendor: 'VMware Inc (Virtual Machine)',
    hostname: 'CORP-FILE01.corp.local',
    deviceType: 'server',
    vlanId: 10,
    vlanName: 'Corporate Servers & LAN',
    subnet: '192.168.10.0/24',
    osFingerprint: {
      name: 'Ubuntu Linux 24.04 LTS (Kernel 6.8)',
      family: 'Linux',
      accuracy: 97,
      initialTtl: 64,
      tcpWindowSize: 64240,
      details: 'Linux 6.x kernel TCP SYN ACK fingerprint'
    },
    ports: [
      { port: 22, protocol: 'tcp', service: 'ssh', state: 'open', version: 'OpenSSH 9.6p1 Ubuntu' },
      { port: 445, protocol: 'tcp', service: 'netbios-ssn', state: 'open', version: 'Samba 4.19.5' },
      { port: 2049, protocol: 'tcp', service: 'nfs', state: 'open', version: 'NFSv4.2 Network File System' },
      { port: 9100, protocol: 'tcp', service: 'node_exporter', state: 'open', version: 'Prometheus Node Exporter', isRisky: true, riskReason: 'Unauthenticated metric endpoint' }
    ],
    activeProtocols: ['SSH', 'Samba', 'NFS', 'HTTP', 'mDNS'],
    firstSeen: '2026-08-26 09:11:05',
    lastSeen: '2026-08-26 09:44:18',
    status: 'online',
    latencyMs: 0.9,
    riskScore: 'Medium',
    riskFactors: ['Prometheus node exporter exposed without auth on port 9100', 'NFS exports visible on local subnet']
  },
  {
    id: 'dev-srv-db01',
    ip: '192.168.10.20',
    mac: '00:50:56:b1:44:99',
    vendor: 'VMware Inc (Virtual Machine)',
    hostname: 'pg-cluster-node01.corp.local',
    deviceType: 'server',
    vlanId: 10,
    vlanName: 'Corporate Servers & LAN',
    subnet: '192.168.10.0/24',
    osFingerprint: {
      name: 'Debian GNU/Linux 12 (Bookworm)',
      family: 'Linux',
      accuracy: 98,
      initialTtl: 64,
      tcpWindowSize: 64240,
      details: 'Standard Linux TCP stack with SACK, TS'
    },
    ports: [
      { port: 22, protocol: 'tcp', service: 'ssh', state: 'open', version: 'OpenSSH 9.2p1' },
      { port: 5432, protocol: 'tcp', service: 'postgresql', state: 'open', version: 'PostgreSQL 16.2 database' }
    ],
    activeProtocols: ['SSH', 'PostgreSQL'],
    firstSeen: '2026-08-26 09:11:10',
    lastSeen: '2026-08-26 09:44:15',
    status: 'online',
    latencyMs: 0.7,
    riskScore: 'Low',
    riskFactors: []
  },
  {
    id: 'dev-wk-01',
    ip: '192.168.10.101',
    mac: '8c:85:90:12:34:56',
    vendor: 'Dell Inc.',
    hostname: 'FINANCE-PC04.corp.local',
    deviceType: 'workstation',
    vlanId: 10,
    vlanName: 'Corporate Servers & LAN',
    subnet: '192.168.10.0/24',
    osFingerprint: {
      name: 'Microsoft Windows 11 Enterprise 23H2',
      family: 'Windows',
      accuracy: 95,
      initialTtl: 128,
      tcpWindowSize: 64512,
      details: 'Windows 11 TCP/IP signature with SMBv3 + LLMNR active'
    },
    ports: [
      { port: 135, protocol: 'tcp', service: 'msrpc', state: 'open', version: 'Microsoft Windows RPC' },
      { port: 445, protocol: 'tcp', service: 'microsoft-ds', state: 'open', version: 'Windows 11 Workstation' }
    ],
    activeProtocols: ['SMBv3', 'MSRPC', 'LLMNR', 'NetBIOS', 'mDNS'],
    firstSeen: '2026-08-26 09:12:00',
    lastSeen: '2026-08-26 09:44:10',
    status: 'online',
    latencyMs: 3.4,
    riskScore: 'Medium',
    riskFactors: ['LLMNR name resolution enabled (vulnerable to responder poisoning)']
  },
  {
    id: 'dev-wk-02',
    ip: '192.168.10.102',
    mac: '3c:06:30:45:67:89',
    vendor: 'Apple Inc.',
    hostname: 'dev-macbook-pro.local',
    deviceType: 'workstation',
    vlanId: 10,
    vlanName: 'Corporate Servers & LAN',
    subnet: '192.168.10.0/24',
    osFingerprint: {
      name: 'Apple macOS Sonoma 14.4 (Darwin 23.4)',
      family: 'macOS',
      accuracy: 98,
      initialTtl: 64,
      tcpWindowSize: 65535,
      details: 'Darwin TCP signature, Bonjour/mDNS service broadcasts (_airplay._tcp, _companion-link._tcp)'
    },
    ports: [
      { port: 22, protocol: 'tcp', service: 'ssh', state: 'open', version: 'OpenSSH_9.6p1' },
      { port: 5000, protocol: 'tcp', service: 'airplay', state: 'open', version: 'AirPlay Receiver' },
      { port: 7000, protocol: 'tcp', service: 'airplay', state: 'open', version: 'AirPlay Mirroring' }
    ],
    activeProtocols: ['mDNS/Bonjour', 'SSH', 'AirPlay', 'ICMP'],
    firstSeen: '2026-08-26 09:12:30',
    lastSeen: '2026-08-26 09:44:05',
    status: 'online',
    latencyMs: 4.2,
    riskScore: 'Low',
    riskFactors: []
  },
  {
    id: 'dev-wk-03',
    ip: '192.168.10.105',
    mac: 'b8:85:84:aa:bb:cc',
    vendor: 'Lenovo ThinkPad',
    hostname: 'HR-LAPTOP-02.corp.local',
    deviceType: 'workstation',
    vlanId: 10,
    vlanName: 'Corporate Servers & LAN',
    subnet: '192.168.10.0/24',
    osFingerprint: {
      name: 'Microsoft Windows 10 Pro 22H2',
      family: 'Windows',
      accuracy: 94,
      initialTtl: 128,
      tcpWindowSize: 64512,
      details: 'Windows 10 TCP stack'
    },
    ports: [
      { port: 135, protocol: 'tcp', service: 'msrpc', state: 'open', version: 'Microsoft RPC' },
      { port: 445, protocol: 'tcp', service: 'microsoft-ds', state: 'open', version: 'Windows 10' }
    ],
    activeProtocols: ['SMBv3', 'MSRPC', 'LLMNR'],
    firstSeen: '2026-08-26 09:13:00',
    lastSeen: '2026-08-26 09:43:55',
    status: 'online',
    latencyMs: 3.8,
    riskScore: 'Medium',
    riskFactors: ['LLMNR enabled']
  },
  // VLAN 20 (VoIP)
  {
    id: 'dev-voip-pbx',
    ip: '192.168.20.10',
    mac: '00:1e:c9:88:99:aa',
    vendor: 'Sangoma / Asterisk FreePBX',
    hostname: 'pbx01.voip.corp.local',
    deviceType: 'server',
    vlanId: 20,
    vlanName: 'VoIP & Unified Comms',
    subnet: '192.168.20.0/24',
    osFingerprint: {
      name: 'Linux (CentOS 7 Asterisk PBX 20.6)',
      family: 'Linux',
      accuracy: 96,
      initialTtl: 64,
      tcpWindowSize: 29200,
      details: 'Linux 3.10 Asterisk PBX signature'
    },
    ports: [
      { port: 22, protocol: 'tcp', service: 'ssh', state: 'open', version: 'OpenSSH 7.4' },
      { port: 80, protocol: 'tcp', service: 'http', state: 'open', version: 'Apache 2.4.6 (FreePBX GUI)', isRisky: true, riskReason: 'Plaintext HTTP administration portal' },
      { port: 5060, protocol: 'udp', service: 'sip', state: 'open', version: 'Asterisk PBX SIP' },
      { port: 5061, protocol: 'tcp', service: 'sips', state: 'open', version: 'TLS SIP' }
    ],
    activeProtocols: ['SIP', 'RTP', 'HTTP', 'SSH', 'NTP'],
    firstSeen: '2026-08-26 09:10:20',
    lastSeen: '2026-08-26 09:44:00',
    status: 'online',
    latencyMs: 1.4,
    riskScore: 'High',
    riskFactors: ['Unencrypted HTTP administrative web interface on port 80', 'SIP 5060 unencrypted signaling']
  },
  {
    id: 'dev-voip-phone01',
    ip: '192.168.20.51',
    mac: '00:04:f2:12:34:56',
    vendor: 'Polycom VVX 450',
    hostname: 'poly-desk-frontdesk',
    deviceType: 'iot',
    vlanId: 20,
    vlanName: 'VoIP & Unified Comms',
    subnet: '192.168.20.0/24',
    osFingerprint: {
      name: 'Polycom UC Software (Embedded Linux)',
      family: 'Embedded/RTOS',
      accuracy: 97,
      initialTtl: 64,
      tcpWindowSize: 5840,
      details: 'Polycom SIP phone firmware signature'
    },
    ports: [
      { port: 80, protocol: 'tcp', service: 'http', state: 'open', version: 'Polycom Web Configuration', isRisky: true, riskReason: 'Web portal on HTTP' },
      { port: 443, protocol: 'tcp', service: 'https', state: 'open', version: 'Polycom SSL' },
      { port: 5060, protocol: 'udp', service: 'sip', state: 'open', version: 'SIP Client' }
    ],
    activeProtocols: ['SIP', 'RTP', 'LLDP-MED', 'CDP', 'HTTP'],
    firstSeen: '2026-08-26 09:10:25',
    lastSeen: '2026-08-26 09:44:02',
    status: 'online',
    latencyMs: 2.8,
    riskScore: 'Medium',
    riskFactors: ['LLDP-MED voice VLAN discovery advertised', 'HTTP web config enabled']
  },
  {
    id: 'dev-voip-phone02',
    ip: '192.168.20.52',
    mac: '00:04:f2:12:34:78',
    vendor: 'Polycom VVX 450',
    hostname: 'poly-desk-exec',
    deviceType: 'iot',
    vlanId: 20,
    vlanName: 'VoIP & Unified Comms',
    subnet: '192.168.20.0/24',
    osFingerprint: {
      name: 'Polycom UC Software (Embedded Linux)',
      family: 'Embedded/RTOS',
      accuracy: 97,
      initialTtl: 64,
      tcpWindowSize: 5840,
      details: 'Polycom SIP phone firmware signature'
    },
    ports: [
      { port: 443, protocol: 'tcp', service: 'https', state: 'open', version: 'Polycom SSL' },
      { port: 5060, protocol: 'udp', service: 'sip', state: 'open', version: 'SIP Client' }
    ],
    activeProtocols: ['SIP', 'RTP', 'LLDP-MED'],
    firstSeen: '2026-08-26 09:10:28',
    lastSeen: '2026-08-26 09:44:03',
    status: 'online',
    latencyMs: 2.6,
    riskScore: 'Low',
    riskFactors: []
  },
  // VLAN 30 (IoT & Physical Security)
  {
    id: 'dev-cam-01',
    ip: '192.168.30.101',
    mac: '44:19:b6:aa:11:22',
    vendor: 'Hikvision Digital Technology',
    hostname: 'CAM-ENTRANCE-01',
    deviceType: 'iot',
    vlanId: 30,
    vlanName: 'IoT & Physical Security',
    subnet: '192.168.30.0/24',
    osFingerprint: {
      name: 'Embedded Linux 3.0 (Hikvision IP Camera)',
      family: 'Embedded/RTOS',
      accuracy: 95,
      initialTtl: 64,
      tcpWindowSize: 14600,
      details: 'Hikvision camera stack with RTSP 554 and ONVIF discovery'
    },
    ports: [
      { port: 80, protocol: 'tcp', service: 'http', state: 'open', version: 'Hikvision webs server', isRisky: true, riskReason: 'Known legacy authentication endpoints on port 80' },
      { port: 554, protocol: 'tcp', service: 'rtsp', state: 'open', version: 'RTSP Streamer (H.264/H.265)' },
      { port: 8000, protocol: 'tcp', service: 'hik-dvr', state: 'open', version: 'Hikvision SDK Control Port' }
    ],
    activeProtocols: ['RTSP', 'ONVIF', 'HTTP', 'mDNS'],
    firstSeen: '2026-08-26 09:10:40',
    lastSeen: '2026-08-26 09:44:08',
    status: 'online',
    latencyMs: 5.1,
    riskScore: 'High',
    riskFactors: ['Hikvision IP camera firmware may contain legacy vulnerabilities', 'RTSP video feed unencrypted on LAN segment']
  },
  {
    id: 'dev-cam-02',
    ip: '192.168.30.102',
    mac: '44:19:b6:aa:11:33',
    vendor: 'Hikvision Digital Technology',
    hostname: 'CAM-PARKING-02',
    deviceType: 'iot',
    vlanId: 30,
    vlanName: 'IoT & Physical Security',
    subnet: '192.168.30.0/24',
    osFingerprint: {
      name: 'Embedded Linux 3.0 (Hikvision IP Camera)',
      family: 'Embedded/RTOS',
      accuracy: 95,
      initialTtl: 64,
      tcpWindowSize: 14600,
      details: 'Hikvision camera RTSP + ONVIF'
    },
    ports: [
      { port: 80, protocol: 'tcp', service: 'http', state: 'open', version: 'Hikvision webs server' },
      { port: 554, protocol: 'tcp', service: 'rtsp', state: 'open', version: 'RTSP Streamer' },
      { port: 8000, protocol: 'tcp', service: 'hik-dvr', state: 'open', version: 'Hikvision SDK' }
    ],
    activeProtocols: ['RTSP', 'ONVIF', 'HTTP'],
    firstSeen: '2026-08-26 09:10:42',
    lastSeen: '2026-08-26 09:44:09',
    status: 'online',
    latencyMs: 5.4,
    riskScore: 'High',
    riskFactors: ['RTSP unencrypted streaming', 'Embedded web interface on port 80']
  },
  {
    id: 'dev-print-01',
    ip: '192.168.30.50',
    mac: '00:1b:78:33:44:55',
    vendor: 'HP Inc. (Hewlett-Packard)',
    hostname: 'HP-LaserJet-MFP-M428.corp.local',
    deviceType: 'printer',
    vlanId: 30,
    vlanName: 'IoT & Physical Security',
    subnet: '192.168.30.0/24',
    osFingerprint: {
      name: 'HP FutureSmart Firmware / Embedded RTOS',
      family: 'Embedded/RTOS',
      accuracy: 96,
      initialTtl: 64,
      tcpWindowSize: 8192,
      details: 'Raw 9100 JetDirect, IPP 631, and SNMP'
    },
    ports: [
      { port: 80, protocol: 'tcp', service: 'http', state: 'open', version: 'HP Embedded Web Server' },
      { port: 443, protocol: 'tcp', service: 'https', state: 'open', version: 'HP SSL Web Server' },
      { port: 515, protocol: 'tcp', service: 'printer', state: 'open', version: 'LPD/LPR spooler' },
      { port: 631, protocol: 'tcp', service: 'ipp', state: 'open', version: 'Internet Printing Protocol 2.0' },
      { port: 9100, protocol: 'tcp', service: 'jetdirect', state: 'open', version: 'HP Raw JetDirect 9100' }
    ],
    activeProtocols: ['IPP', 'JetDirect', 'HTTP', 'mDNS/Bonjour', 'SNMP', 'WS-Discovery'],
    firstSeen: '2026-08-26 09:10:50',
    lastSeen: '2026-08-26 09:44:11',
    status: 'online',
    latencyMs: 3.2,
    riskScore: 'Medium',
    riskFactors: ['Raw JetDirect port 9100 accepts unauthenticated print jobs', 'WS-Discovery multicast chatter']
  },
  {
    id: 'dev-iot-hvac',
    ip: '192.168.30.70',
    mac: '18:b4:30:66:77:88',
    vendor: 'Nest Labs / Google',
    hostname: 'thermostat-zone1.iot.local',
    deviceType: 'iot',
    vlanId: 30,
    vlanName: 'IoT & Physical Security',
    subnet: '192.168.30.0/24',
    osFingerprint: {
      name: 'FreeRTOS / Weave Embedded',
      family: 'Embedded/RTOS',
      accuracy: 91,
      initialTtl: 64,
      tcpWindowSize: 4380,
      details: 'Lightweight IoT TCP stack'
    },
    ports: [
      { port: 443, protocol: 'tcp', service: 'https', state: 'open', version: 'TLS 1.3 Client Agent' }
    ],
    activeProtocols: ['mDNS', 'TLS', 'CoAP'],
    firstSeen: '2026-08-26 09:10:55',
    lastSeen: '2026-08-26 09:44:00',
    status: 'online',
    latencyMs: 8.5,
    riskScore: 'Low',
    riskFactors: []
  },
  {
    id: 'dev-iot-access',
    ip: '192.168.30.80',
    mac: 'ac:cc:8e:11:22:33',
    vendor: 'Axis Communications',
    hostname: 'axis-door-controller-a1001',
    deviceType: 'iot',
    vlanId: 30,
    vlanName: 'IoT & Physical Security',
    subnet: '192.168.30.0/24',
    osFingerprint: {
      name: 'Axis Embedded Linux 4.9',
      family: 'Linux',
      accuracy: 94,
      initialTtl: 64,
      tcpWindowSize: 14600,
      details: 'Axis Door Access Controller'
    },
    ports: [
      { port: 80, protocol: 'tcp', service: 'http', state: 'open', version: 'Axis Web Administration' },
      { port: 443, protocol: 'tcp', service: 'https', state: 'open', version: 'Axis Secure HTTPS' }
    ],
    activeProtocols: ['HTTPS', 'ONVIF', 'mDNS'],
    firstSeen: '2026-08-26 09:10:58',
    lastSeen: '2026-08-26 09:44:05',
    status: 'online',
    latencyMs: 3.9,
    riskScore: 'Low',
    riskFactors: []
  },
  // VLAN 50 (Guest Wi-Fi)
  {
    id: 'dev-gst-01',
    ip: '192.168.50.105',
    mac: 'a4:83:e7:55:66:77',
    vendor: 'Apple Inc. (iPhone 15)',
    hostname: 'guest-iphone.local',
    deviceType: 'mobile',
    vlanId: 50,
    vlanName: 'Guest Wi-Fi',
    subnet: '192.168.50.0/24',
    osFingerprint: {
      name: 'Apple iOS 17.5.1',
      family: 'Android/iOS',
      accuracy: 97,
      initialTtl: 64,
      tcpWindowSize: 65535,
      details: 'iOS TCP SYN stack with Apple Bonjour mDNS broadcast'
    },
    ports: [],
    activeProtocols: ['mDNS', 'DHCP', 'DNS', 'HTTPS'],
    firstSeen: '2026-08-26 09:30:00',
    lastSeen: '2026-08-26 09:44:12',
    status: 'online',
    latencyMs: 12.4,
    riskScore: 'Low',
    riskFactors: []
  },
  {
    id: 'dev-gst-02',
    ip: '192.168.50.112',
    mac: 'da:a1:19:88:77:66',
    vendor: 'Samsung Electronics (Galaxy S24)',
    hostname: 'Galaxy-S24-Ultra.lan',
    deviceType: 'mobile',
    vlanId: 50,
    vlanName: 'Guest Wi-Fi',
    subnet: '192.168.50.0/24',
    osFingerprint: {
      name: 'Android 14 (Linux Kernel 6.1)',
      family: 'Android/iOS',
      accuracy: 95,
      initialTtl: 64,
      tcpWindowSize: 65535,
      details: 'Android OS network stack with randomized MAC (Private Wi-Fi Address)'
    },
    ports: [],
    activeProtocols: ['mDNS', 'DHCP', 'DNS', 'HTTPS'],
    firstSeen: '2026-08-26 09:32:15',
    lastSeen: '2026-08-26 09:44:10',
    status: 'online',
    latencyMs: 14.1,
    riskScore: 'Low',
    riskFactors: []
  },
  {
    id: 'dev-gst-03',
    ip: '192.168.50.120',
    mac: '48:2a:e3:99:88:11',
    vendor: 'Unknown / Generic',
    hostname: 'guest-unidentified.lan',
    deviceType: 'workstation',
    vlanId: 50,
    vlanName: 'Guest Wi-Fi',
    subnet: '192.168.50.0/24',
    osFingerprint: {
      name: 'Linux 6.x (Possibly Kali / Arch)',
      family: 'Linux',
      accuracy: 89,
      initialTtl: 64,
      tcpWindowSize: 64240,
      details: 'Linux TCP stack with passive ARP probing activity'
    },
    ports: [
      { port: 22, protocol: 'tcp', service: 'ssh', state: 'filtered' }
    ],
    activeProtocols: ['ARP', 'ICMP', 'DNS'],
    firstSeen: '2026-08-26 09:40:00',
    lastSeen: '2026-08-26 09:44:12',
    status: 'online',
    latencyMs: 11.2,
    riskScore: 'Medium',
    riskFactors: ['High rate of outbound ARP discovery probes observed on guest segment']
  },
  {
    id: 'dev-gst-04',
    ip: '192.168.50.135',
    mac: 'f0:18:98:33:22:11',
    vendor: 'Apple Inc. (iPad Pro)',
    hostname: 'Executive-iPad.local',
    deviceType: 'mobile',
    vlanId: 50,
    vlanName: 'Guest Wi-Fi',
    subnet: '192.168.50.0/24',
    osFingerprint: {
      name: 'Apple iPadOS 17.5',
      family: 'Android/iOS',
      accuracy: 96,
      initialTtl: 64,
      tcpWindowSize: 65535,
      details: 'Apple mobile network stack'
    },
    ports: [],
    activeProtocols: ['mDNS', 'HTTPS'],
    firstSeen: '2026-08-26 09:25:00',
    lastSeen: '2026-08-26 09:44:00',
    status: 'online',
    latencyMs: 9.8,
    riskScore: 'Low',
    riskFactors: []
  }
];

export const PROTOCOL_STATS: ProtocolStat[] = [
  {
    protocol: 'HTTPS / TLS',
    port: 443,
    packetCount: 42890,
    percentage: 34.2,
    category: 'Web/App',
    description: 'Encrypted web application traffic and API telemetry',
    securityImplication: 'Encrypted in transit; verified certificates provide confidentiality.',
    isPlaintext: false
  },
  {
    protocol: 'DNS (UDP)',
    port: 53,
    packetCount: 21500,
    percentage: 17.1,
    category: 'Infrastructure',
    description: 'Domain name resolution queries and responses across local resolvers',
    securityImplication: 'Unencrypted standard DNS reveals internal hostnames and accessed domains to passive listeners.',
    isPlaintext: true
  },
  {
    protocol: 'SMBv3 / CIFS',
    port: 445,
    packetCount: 16200,
    percentage: 12.9,
    category: 'File Sharing',
    description: 'Windows Active Directory domain file sharing, RPC and pipeline communications',
    securityImplication: 'Encrypted if SMB signing / encryption enforced; legacy SMBv1 must remain disabled.',
    isPlaintext: false
  },
  {
    protocol: 'mDNS (Multicast DNS)',
    port: 5353,
    packetCount: 11400,
    percentage: 9.1,
    category: 'Discovery',
    description: 'Zero-configuration multicast name resolution (Apple Bonjour, IoT, Printers)',
    securityImplication: 'Multicasts hostnames, device models, and advertised services to everyone on the L2 broadcast domain.',
    isPlaintext: true
  },
  {
    protocol: 'ARP (Address Resolution)',
    port: 'L2 Ethernet',
    packetCount: 9850,
    percentage: 7.8,
    category: 'Infrastructure',
    description: 'Layer 2 IP-to-MAC mapping broadcast requests and replies',
    securityImplication: 'Unauthenticated; vulnerable to ARP cache spoofing and MITM on unmanaged switches.',
    isPlaintext: true
  },
  {
    protocol: 'LLMNR',
    port: 5355,
    packetCount: 6300,
    percentage: 5.0,
    category: 'Legacy/Insecure',
    description: 'Link-Local Multicast Name Resolution used by Windows when DNS fails',
    securityImplication: 'High risk! Responders can easily spoof responses and capture NetNTLMv2 password hashes.',
    isPlaintext: true
  },
  {
    protocol: 'SIP / RTP (VoIP)',
    port: '5060 / 10000-20000',
    packetCount: 5800,
    percentage: 4.6,
    category: 'Web/App',
    description: 'Session Initiation Protocol signaling and Real-time Transport audio voice packets',
    securityImplication: 'Unencrypted SIP reveals caller/callee metadata and call extensions.',
    isPlaintext: true
  },
  {
    protocol: 'SSDP / UPnP',
    port: 1900,
    packetCount: 4200,
    percentage: 3.3,
    category: 'Discovery',
    description: 'Simple Service Discovery Protocol used by media servers, routers, and IoT',
    securityImplication: 'Multicasts XML device capability descriptors across the local subnet.',
    isPlaintext: true
  },
  {
    protocol: 'SNMP',
    port: '161 / 162',
    packetCount: 3100,
    percentage: 2.5,
    category: 'Management',
    description: 'Simple Network Management Protocol queries on network switches and printers',
    securityImplication: 'SNMPv1/v2c uses plaintext community strings ("public"). Prefer SNMPv3 with authPriv.',
    isPlaintext: true
  },
  {
    protocol: 'SSH (Secure Shell)',
    port: 22,
    packetCount: 2900,
    percentage: 2.3,
    category: 'Management',
    description: 'Encrypted administrative remote terminal access to switches and servers',
    securityImplication: 'Strong cryptographic channel; ensure password auth disabled in favor of ED25519 keys.',
    isPlaintext: false
  },
  {
    protocol: 'HTTP (Plaintext)',
    port: '80 / 8080',
    packetCount: 1500,
    percentage: 1.2,
    category: 'Legacy/Insecure',
    description: 'Unencrypted web traffic on IP cameras, PBX web portal, and legacy printers',
    securityImplication: 'Critical: Credentials and session cookies transmitted in cleartext on the wire.',
    isPlaintext: true
  }
];

export const SCAN_PROFILES: ScanProfile[] = [
  {
    id: 'prof-arp-quick',
    name: 'Layer 2 Fast ARP Sweep',
    description: 'Blasts ARP broadcast requests across the local subnet to map all active IP-to-MAC addresses and hardware vendors in under 2 seconds.',
    techniques: ['ARP Broadcast Who-has', 'OUI Vendor Resolution', 'Broadcast Flood Analysis'],
    speed: 'Fast (1-2s)',
    stealthLevel: 'Loud',
    subnets: ['192.168.1.0/24', '192.168.10.0/24', '192.168.20.0/24', '192.168.30.0/24', '192.168.50.0/24']
  },
  {
    id: 'prof-syn-os',
    name: 'Stealth TCP SYN & OS Fingerprint',
    description: 'Sends half-open TCP SYN packets to standard management & service ports. Evaluates initial IP TTL, TCP Window size, and TCP options for OS classification.',
    techniques: ['Half-open TCP SYN', 'IP TTL Heuristics', 'TCP Window Size Analysis', 'Banner Grabbing'],
    speed: 'Balanced (5-10s)',
    stealthLevel: 'Stealth (SYN)',
    subnets: ['192.168.1.0/24', '192.168.10.0/24']
  },
  {
    id: 'prof-vlan-lldp',
    name: 'VLAN & 802.1AB LLDP / CDP Discovery',
    description: 'Captures raw Ethernet 0x88CC (LLDP) and 0x2000 (CDP) frames to reconstruct switch chassis IDs, port numbers, VTP domains, and 802.1Q tagged VLAN trunks.',
    techniques: ['LLDP Frame Sniffing (0x88CC)', 'Cisco CDP Parser (0x2000)', '802.1Q Tag Inspection', 'STP Bridge Root Detection'],
    speed: 'Balanced (5-10s)',
    stealthLevel: 'Passive',
    subnets: ['Management Trunk', 'Core Interconnect']
  },
  {
    id: 'prof-passive-sniff',
    name: 'Passive Stealth LAN Sniffer',
    description: 'Listens passively without sending any packets. Dissects broadcast & multicast chatter (mDNS, SSDP, LLMNR, NetBIOS, ARP) to map active endpoints silently.',
    techniques: ['Zero Active Probes', 'Multicast DNS Sniffing', 'SSDP UPnP Extraction', 'LLMNR Query Listener', 'DHCP Request Parser'],
    speed: 'Deep (15-30s)',
    stealthLevel: 'Passive',
    subnets: ['All Local Subnets']
  },
  {
    id: 'prof-full-audit',
    name: 'Comprehensive On-Premise Audit',
    description: 'Full multi-layer reconnaissance combining ARP discovery, full port audit, service banner extraction, VLAN segmentation analysis, and security hygiene scoring.',
    techniques: ['ARP Sweep', 'ICMP Timestamp/Echo', 'Full Top 100 Port Scan', 'Service Version Detection', 'VLAN Leak Analysis', 'Risk Assessment'],
    speed: 'Deep (15-30s)',
    stealthLevel: 'Normal',
    subnets: ['192.168.1.0/24', '192.168.10.0/24', '192.168.20.0/24', '192.168.30.0/24', '192.168.50.0/24']
  }
];
