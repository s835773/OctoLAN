export interface NetworkDevice {
  id: string;
  ip: string;
  mac: string;
  vendor: string;
  hostname: string;
  deviceType: 'gateway' | 'switch' | 'server' | 'workstation' | 'mobile' | 'iot' | 'printer' | 'access_point' | 'firewall';
  vlanId: number;
  vlanName: string;
  subnet: string;
  osFingerprint: {
    name: string;
    family: 'Linux' | 'Windows' | 'macOS' | 'Cisco IOS' | 'BSD' | 'Embedded/RTOS' | 'Android/iOS' | 'Unknown';
    accuracy: number;
    initialTtl: number;
    tcpWindowSize: number;
    details: string;
  };
  ports: {
    port: number;
    protocol: 'tcp' | 'udp';
    service: string;
    state: 'open' | 'filtered' | 'closed';
    version?: string;
    banner?: string;
    isRisky?: boolean;
    riskReason?: string;
  }[];
  activeProtocols: string[];
  firstSeen: string;
  lastSeen: string;
  status: 'online' | 'intermittent' | 'offline';
  latencyMs: number;
  riskScore: 'Low' | 'Medium' | 'High' | 'Critical';
  riskFactors: string[];
  lldpNeighbor?: {
    chassisId: string;
    systemName: string;
    portId: string;
    vlanTagged: boolean;
  };
}

export interface VlanInfo {
  id: number;
  name: string;
  subnet: string;
  gateway: string;
  deviceCount: number;
  color: string;
  description: string;
  securityZone: 'Management' | 'Trusted' | 'Restricted' | 'Untrusted' | 'Guest' | 'IoT';
  isolated: boolean;
}

export interface ProtocolStat {
  protocol: string;
  port: number | string;
  packetCount: number;
  percentage: number;
  category: 'Infrastructure' | 'Discovery' | 'Web/App' | 'File Sharing' | 'Management' | 'Legacy/Insecure';
  description: string;
  securityImplication: string;
  isPlaintext: boolean;
}

export interface ScanProfile {
  id: string;
  name: string;
  description: string;
  techniques: string[];
  speed: 'Fast (1-2s)' | 'Balanced (5-10s)' | 'Deep (15-30s)';
  stealthLevel: 'Loud' | 'Normal' | 'Passive' | 'Stealth (SYN)';
  subnets: string[];
}

export interface AuditReport {
  timestamp: string;
  networkName: string;
  totalDevices: number;
  totalVlans: number;
  openPortsCount: number;
  riskyServicesCount: number;
  osBreakdown: Record<string, number>;
  recommendations: {
    category: 'VLAN Segmentation' | 'Plaintext Protocols' | 'Default Services' | 'Device Hardening';
    severity: 'Critical' | 'High' | 'Medium' | 'Low';
    title: string;
    description: string;
    remediation: string;
  }[];
}

export interface NetflowRecord {
  id: string;
  timestamp: string;
  srcIp: string;
  srcPort: number;
  srcHostname?: string;
  dstIp: string;
  dstPort: number;
  dstHostname?: string;
  protocol: 'TCP' | 'UDP' | 'ICMP' | 'GRE' | 'ESP';
  application: string;
  bytes: number;
  packets: number;
  durationMs: number;
  tcpFlags: string;
  vlanId: number;
  flowDirection: 'Ingress' | 'Egress' | 'Internal';
  rateMbps: number;
  isAnomalous?: boolean;
  anomalyReason?: string;
}

export interface TopTalker {
  ip: string;
  hostname: string;
  deviceType: string;
  vlanId: number;
  totalBytes: number;
  totalPackets: number;
  bandwidthMbps: number;
  flowCount: number;
  percentage: number;
}

export interface StormMetric {
  timestamp: string;
  broadcastPps: number;
  multicastPps: number;
  unicastPps: number;
  totalBandwidthKbps: number;
  status: 'Normal' | 'Elevated' | 'Warning' | 'Critical Storm';
  topEmitterIp?: string;
  protocolType?: string;
}

export interface StormNodeActivity {
  id: string;
  ip: string;
  hostname: string;
  mac: string;
  vlanId: number;
  broadcastPps: number;
  multicastPps: number;
  dominantProtocol: 'ARP' | 'LLMNR' | 'mDNS' | 'SSDP' | 'DHCP' | 'STP BPDU';
  stormStatus: 'Calm' | 'Flooding' | 'Loop Detected' | 'Suppressed';
  packetRingSize: number; // For EtherApe-style dynamic visualization
}

export interface AlertRule {
  id: string;
  name: string;
  category: 'Rogue Device' | 'Storm / Loop' | 'Port / Service' | 'VLAN Violation' | 'Availability';
  enabled: boolean;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  triggerCondition: string;
  channel: 'email' | 'webhook' | 'syslog' | 'all';
  cooldownMinutes: number;
  lastTriggered?: string;
}

export interface AlertEvent {
  id: string;
  timestamp: string;
  ruleId: string;
  ruleName: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  category: string;
  targetDevice: string;
  targetIp: string;
  message: string;
  deliveredTo: string[];
  status: 'Delivered' | 'Pending' | 'Silenced' | 'Failed';
  technicalDetails: string;
}

export interface AlertConfig {
  smtpServer: string;
  smtpPort: number;
  smtpUser: string;
  smtpFrom: string;
  smtpTo: string;
  enableSsl: boolean;
  webhookUrl: string;
  webhookFormat: 'Generic JSON' | 'Slack / Discord' | 'Microsoft Teams';
  stormThresholdPps: number;
  rogueMacAlert: boolean;
  interVlanLeakAlert: boolean;
}
