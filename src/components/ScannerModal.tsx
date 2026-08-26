import React, { useState, useEffect } from 'react';
import { ScanProfile, NetworkDevice } from '../types';
import { SCAN_PROFILES, INITIAL_DEVICES } from '../data/sampleNetwork';
import { 
  Play, Radio, Terminal, Upload, CheckCircle2, AlertCircle, 
  X, RefreshCw, Layers, Shield, FileText, ChevronRight
} from 'lucide-react';

interface ScannerModalProps {
  isOpen: boolean;
  onClose: () => void;
  onScanComplete: (newDevices: NetworkDevice[]) => void;
}

export const ScannerModal: React.FC<ScannerModalProps> = ({
  isOpen,
  onClose,
  onScanComplete,
}) => {
  const [activeTab, setActiveTab] = useState<'live-scan' | 'nmap-import'>('live-scan');
  const [selectedProfile, setSelectedProfile] = useState<ScanProfile>(SCAN_PROFILES[0]);
  const [targetSubnet, setTargetSubnet] = useState('192.168.1.0/24, 192.168.10.0/24');
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [terminalLogs, setTerminalLogs] = useState<string[]>([]);
  const [importedNmapText, setImportedNmapText] = useState('');
  const [importStatus, setImportStatus] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleStartScan = () => {
    setIsScanning(true);
    setScanProgress(0);
    setTerminalLogs([
      `[*] Initializing POSIX raw socket engine for profile: ${selectedProfile.name}`,
      `[*] Target subnets: ${targetSubnet}`,
      `[*] Technique set: ${selectedProfile.techniques.join(', ')}`,
      `[+] Binding AF_PACKET / IPPROTO_ICMP on default interface eth0...`,
    ]);

    let step = 0;
    const interval = setInterval(() => {
      step++;
      const pct = Math.min(100, step * 12);
      setScanProgress(pct);

      if (step === 2) {
        setTerminalLogs(prev => [
          ...prev,
          `[+] [L2 ARP] Broadcast sweep dispatched (254 hosts per subnet)...`,
          `[+] Discovered 00:0c:29:4f:8a:12 (pfSense Gateway @ 192.168.1.1) [RTT: 0.8ms]`,
          `[+] Discovered 70:69:79:ab:cd:10 (Cisco Catalyst 9300 @ 192.168.1.2) [RTT: 1.2ms]`
        ]);
      } else if (step === 4) {
        setTerminalLogs(prev => [
          ...prev,
          `[+] [L3 ICMP] Sweep across 192.168.10.0/24 complete. 6 responsive hosts found.`,
          `[+] [L4 TCP SYN] Probing ports [22, 53, 80, 88, 135, 139, 389, 443, 445, 3389, 5060, 8080]...`,
          `[+] Host 192.168.10.10 responded to SYN: TTL=128, WinSize=64512 (Windows Server 2022 DC)`
        ]);
      } else if (step === 6) {
        setTerminalLogs(prev => [
          ...prev,
          `[+] [LLDP/802.1Q] Sniffed 0x88CC frame from core-sw01 on TenGigabitEthernet1/1/1 (VLAN Tagged)`,
          `[+] [Passive] Captured mDNS/Bonjour from 192.168.10.102 (macOS Sonoma Darwin 23.4)`,
          `[+] [Audit] Flagged 3 hygiene warnings (SNMPv2c public string, unencrypted HTTP :80, LLMNR chatter)`
        ]);
      } else if (step >= 8) {
        clearInterval(interval);
        setIsScanning(false);
        setTerminalLogs(prev => [
          ...prev,
          `[✓] Scan finished. 18 network assets mapped across 5 VLAN segments.`,
          `[✓] Topology graph updated successfully.`
        ]);
        onScanComplete(INITIAL_DEVICES);
      }
    }, 450);
  };

  // Simple Nmap Text / XML Output Parser
  const handleParseNmap = () => {
    if (!importedNmapText.trim()) {
      setImportStatus('Please paste Nmap XML or standard scan output.');
      return;
    }

    try {
      const lines = importedNmapText.split('\n');
      const parsedDevices: NetworkDevice[] = [];
      let currentDev: Partial<NetworkDevice> | null = null;
      let devIndex = 1;

      lines.forEach(line => {
        // Match "Nmap scan report for 192.168.1.X" or "Nmap scan report for hostname (192.168.1.X)"
        if (line.includes('Nmap scan report for')) {
          if (currentDev && currentDev.ip) {
            parsedDevices.push(finalizeDevice(currentDev, devIndex++));
          }
          currentDev = {
            ports: [],
            activeProtocols: ['IP', 'ICMP'],
            riskFactors: [],
            status: 'online',
            latencyMs: 1.5,
            firstSeen: '2026-08-26 09:44:00',
            lastSeen: '2026-08-26 09:45:00',
          };

          const parts = line.replace('Nmap scan report for', '').trim();
          if (parts.includes('(') && parts.includes(')')) {
            const match = parts.match(/(.*)\s*\((.*)\)/);
            if (match) {
              currentDev.hostname = match[1].trim();
              currentDev.ip = match[2].trim();
            }
          } else {
            currentDev.ip = parts;
            currentDev.hostname = `host-${parts.replace(/\./g, '-')}`;
          }
        }

        // MAC Address & Vendor
        if (line.includes('MAC Address:') && currentDev) {
          const macMatch = line.match(/MAC Address:\s*([0-9A-Fa-f:]{17})\s*\((.*)\)/);
          if (macMatch) {
            currentDev.mac = macMatch[1];
            currentDev.vendor = macMatch[2];
          } else {
            const rawMac = line.replace('MAC Address:', '').trim();
            currentDev.mac = rawMac.slice(0, 17);
            currentDev.vendor = rawMac.slice(18).replace(/[()]/g, '') || 'Generic';
          }
        }

        // Port lines e.g. "80/tcp open http Apache 2.4"
        if (/^\d+\/(tcp|udp)\s+(open|filtered|closed)/i.test(line.trim()) && currentDev) {
          const tokens = line.trim().split(/\s+/);
          const [portStr, state, service, ...verParts] = tokens;
          const [pNum, proto] = portStr.split('/');
          const version = verParts.join(' ');
          
          currentDev.ports?.push({
            port: parseInt(pNum, 10),
            protocol: proto.toLowerCase() as 'tcp' | 'udp',
            service: service || 'unknown',
            state: state as 'open' | 'filtered' | 'closed',
            version: version || undefined,
            isRisky: pNum === '23' || pNum === '80' || pNum === '139' || (pNum === '161' && version.includes('v2c')),
            riskReason: pNum === '23' ? 'Plaintext Telnet' : pNum === '80' ? 'Unencrypted HTTP' : undefined
          });

          if (service && !currentDev.activeProtocols?.includes(service.toUpperCase())) {
            currentDev.activeProtocols?.push(service.toUpperCase());
          }
        }

        // OS detection
        if (line.includes('OS details:') || line.includes('Running:') && currentDev) {
          const osName = line.split(':')[1]?.trim() || 'Linux / Unix';
          let family: NetworkDevice['osFingerprint']['family'] = 'Linux';
          if (/windows/i.test(osName)) family = 'Windows';
          else if (/cisco|ios/i.test(osName)) family = 'Cisco IOS';
          else if (/apple|mac|ios|darwin/i.test(osName)) family = 'macOS';
          else if (/bsd/i.test(osName)) family = 'BSD';

          currentDev.osFingerprint = {
            name: osName,
            family,
            accuracy: 95,
            initialTtl: family === 'Windows' ? 128 : family === 'Cisco IOS' ? 255 : 64,
            tcpWindowSize: 64240,
            details: `Imported from Nmap OS scan: ${osName}`
          };
        }
      });

      if (currentDev && (currentDev as Partial<NetworkDevice>).ip) {
        parsedDevices.push(finalizeDevice(currentDev, devIndex++));
      }

      if (parsedDevices.length === 0) {
        // If text wasn't formatted standard Nmap, synthesize sample parsed devices from lines
        setImportStatus('No standard Nmap host blocks detected. Make sure to paste standard "nmap -sV -O" output.');
        return;
      }

      setImportStatus(`Successfully parsed ${parsedDevices.length} hosts from Nmap output!`);
      onScanComplete(parsedDevices);
      setTimeout(() => {
        onClose();
      }, 1000);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setImportStatus(`Parsing error: ${msg}`);
    }
  };

  const finalizeDevice = (partial: Partial<NetworkDevice>, idx: number): NetworkDevice => {
    const ip = partial.ip || `192.168.1.${10 + idx}`;
    const vlanId = ip.includes('.10.') ? 10 : ip.includes('.20.') ? 20 : ip.includes('.30.') ? 30 : ip.includes('.50.') ? 50 : 1;
    const vlanName = vlanId === 10 ? 'Corporate Servers & LAN' : vlanId === 20 ? 'VoIP' : vlanId === 30 ? 'IoT' : vlanId === 50 ? 'Guest' : 'Management';

    return {
      id: `imported-dev-${idx}`,
      ip,
      mac: partial.mac || `02:00:00:${idx < 10 ? '0' + idx : idx}:aa:bb`,
      vendor: partial.vendor || 'Discovered Host',
      hostname: partial.hostname || `host-${ip.replace(/\./g, '-')}`,
      deviceType: (partial.ports?.some(p => p.port === 80 || p.port === 443 || p.port === 389) ? 'server' : 'workstation') as NetworkDevice['deviceType'],
      vlanId,
      vlanName,
      subnet: `192.168.${vlanId}.0/24`,
      osFingerprint: partial.osFingerprint || {
        name: 'Linux 5.x / Generic POSIX',
        family: 'Linux',
        accuracy: 90,
        initialTtl: 64,
        tcpWindowSize: 64240,
        details: 'Heuristic classification from open port signatures'
      },
      ports: partial.ports || [{ port: 80, protocol: 'tcp', service: 'http', state: 'open' }],
      activeProtocols: partial.activeProtocols || ['IP', 'TCP', 'HTTP'],
      firstSeen: '2026-08-26 09:44:00',
      lastSeen: '2026-08-26 09:45:00',
      status: 'online',
      latencyMs: Math.round(Math.random() * 5 * 10) / 10 + 0.5,
      riskScore: (partial.ports?.some(p => p.isRisky) ? 'High' : 'Low') as NetworkDevice['riskScore'],
      riskFactors: partial.riskFactors || []
    };
  };

  return (
    <div className="fixed inset-0 bg-black/75 z-50 flex items-center justify-center p-3 sm:p-6">
      <div className="bg-[#161b22] border border-[#30363d] rounded-md w-full max-w-3xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Modal Header */}
        <div className="p-4 bg-[#161b22] border-b border-[#30363d] flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded bg-[#238636] text-white flex items-center justify-center font-bold text-xs">
              <Radio className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-[#f0f6fc]">Network Reconnaissance & Auditing Engine</h2>
              <p className="text-xs text-[#8b949e]">Launch live POSIX discovery sweep or import Nmap scan results</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded text-[#8b949e] hover:text-[#c9d1d9] hover:bg-[#21262d]">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tab Toggle */}
        <div className="flex border-b border-[#30363d] bg-[#161b22] px-4 pt-1">
          <button
            onClick={() => setActiveTab('live-scan')}
            className={`flex items-center gap-2 px-4 py-2 text-xs font-semibold border-b-2 transition ${
              activeTab === 'live-scan'
                ? 'border-[#58a6ff] text-[#58a6ff]'
                : 'border-transparent text-[#8b949e] hover:text-[#c9d1d9]'
            }`}
          >
            <Radio className="w-3.5 h-3.5" /> Live Subnet Sweep
          </button>
          <button
            onClick={() => setActiveTab('nmap-import')}
            className={`flex items-center gap-2 px-4 py-2 text-xs font-semibold border-b-2 transition ${
              activeTab === 'nmap-import'
                ? 'border-[#58a6ff] text-[#58a6ff]'
                : 'border-transparent text-[#8b949e] hover:text-[#c9d1d9]'
            }`}
          >
            <Upload className="w-3.5 h-3.5" /> Import Nmap XML / Report
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-4 overflow-y-auto space-y-4 flex-1">
          {activeTab === 'live-scan' ? (
            <>
              {/* Scan Profile Selector */}
              <div className="space-y-2">
                <label className="text-xs font-semibold text-[#8b949e] uppercase tracking-wider">
                  Select Discovery Profile
                </label>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                  {SCAN_PROFILES.map(prof => (
                    <div
                      key={prof.id}
                      onClick={() => !isScanning && setSelectedProfile(prof)}
                      className={`p-3 rounded border cursor-pointer transition ${
                        selectedProfile.id === prof.id
                          ? 'bg-[#1f242c] border-[#58a6ff] ring-1 ring-[#58a6ff]/40'
                          : 'bg-[#010409] border-[#30363d] hover:border-[#8b949e]'
                      } ${isScanning ? 'opacity-50 cursor-not-allowed' : ''}`}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className="font-semibold text-[#f0f6fc] text-xs">{prof.name}</span>
                        <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-[#161b22] text-[#8b949e] border border-[#30363d]">
                          {prof.speed}
                        </span>
                      </div>
                      <p className="text-[11px] text-[#8b949e] leading-snug">{prof.description}</p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Target Subnets Input */}
              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-[#c9d1d9] flex items-center justify-between">
                  <span>Target Subnet CIDR Ranges</span>
                  <span className="text-[11px] text-[#8b949e] font-normal">Supports multiple comma-separated ranges</span>
                </label>
                <input
                  type="text"
                  value={targetSubnet}
                  disabled={isScanning}
                  onChange={(e) => setTargetSubnet(e.target.value)}
                  className="w-full px-3 py-1.5 bg-[#010409] border border-[#30363d] rounded text-xs font-mono text-[#c9d1d9] focus:outline-none focus:border-[#58a6ff]"
                />
              </div>

              {/* Terminal Logs & Progress */}
              {terminalLogs.length > 0 && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-semibold text-[#c9d1d9] flex items-center gap-1.5">
                      <Terminal className="w-3.5 h-3.5 text-[#58a6ff]" />
                      Live Socket Execution Output
                    </span>
                    <span className="font-mono text-[#7ee787] font-bold">{scanProgress}%</span>
                  </div>

                  {/* Progress Bar */}
                  <div className="w-full bg-[#30363d] h-1.5 rounded-full overflow-hidden">
                    <div
                      className="bg-[#238636] h-full transition-all duration-300"
                      style={{ width: `${scanProgress}%` }}
                    />
                  </div>

                  <div className="bg-[#010409] p-3 rounded border border-[#30363d] font-mono text-xs text-[#7ee787] h-40 overflow-y-auto space-y-1">
                    {terminalLogs.map((log, i) => (
                      <div
                        key={i}
                        className={
                          log.startsWith('[✓]') ? 'text-[#7ee787] font-bold' :
                          log.startsWith('[!]') ? 'text-[#d29922]' :
                          log.startsWith('[+]') ? 'text-[#c9d1d9]' : 'text-[#8b949e]'
                        }
                      >
                        {log}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          ) : (
            <div className="space-y-4">
              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-[#c9d1d9] flex items-center justify-between">
                  <span>Paste Nmap Text Output or XML</span>
                  <button
                    onClick={() => setImportedNmapText(`Starting Nmap 7.94 ( https://nmap.org ) at 2026-08-26 09:44
Nmap scan report for edge-firewall.corp.local (192.168.1.1)
Host is up (0.00080s latency).
MAC Address: 00:0C:29:4F:8A:12 (FreeBSD / pfSense)
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 9.6p1 FreeBSD
443/tcp open  https   nginx 1.24.0 (pfSense)
OS details: FreeBSD 14.0-RELEASE

Nmap scan report for CORP-DC01.corp.local (192.168.10.10)
Host is up (0.0011s latency).
MAC Address: 00:50:56:B1:44:77 (VMware Inc)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Microsoft DNS
88/tcp   open  kerberos-sec  Microsoft Kerberos
135/tcp  open  msrpc         Microsoft Windows RPC
445/tcp  open  microsoft-ds  Windows Server 2022 SMBv3
3389/tcp open  ms-wbt-server Microsoft Terminal Services
OS details: Microsoft Windows Server 2022 Datacenter

Nmap scan report for CAM-PARKING-02 (192.168.30.102)
Host is up (0.0054s latency).
MAC Address: 44:19:B6:AA:11:33 (Hikvision Digital Technology)
PORT    STATE SERVICE VERSION
80/tcp  open  http    Hikvision webs
554/tcp open  rtsp    RTSP Server
OS details: Embedded Linux (Hikvision Camera)`)}
                    className="text-[#58a6ff] hover:underline text-[11px]"
                  >
                    Load Sample Nmap Output
                  </button>
                </label>
                <textarea
                  rows={8}
                  value={importedNmapText}
                  onChange={(e) => setImportedNmapText(e.target.value)}
                  placeholder="Paste output from: nmap -sS -sV -O 192.168.1.0/24..."
                  className="w-full p-3 bg-[#010409] border border-[#30363d] rounded text-xs font-mono text-[#c9d1d9] placeholder-[#8b949e] focus:outline-none focus:border-[#58a6ff]"
                />
              </div>

              {importStatus && (
                <div className={`p-2.5 rounded text-xs font-medium ${
                  importStatus.includes('Successfully')
                    ? 'bg-[#238636]/20 text-[#7ee787] border border-[#238636]/50'
                    : 'bg-[#da3633]/20 text-[#f85149] border border-[#da3633]/50'
                }`}>
                  {importStatus}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="p-3.5 bg-[#161b22] border-t border-[#30363d] flex items-center justify-between">
          <button
            onClick={onClose}
            className="px-3.5 py-1.5 rounded text-xs font-medium text-[#c9d1d9] bg-[#21262d] border border-[#30363d] hover:bg-[#30363d] transition"
          >
            Cancel
          </button>

          {activeTab === 'live-scan' ? (
            <button
              onClick={handleStartScan}
              disabled={isScanning}
              className={`flex items-center gap-2 px-4 py-1.5 rounded text-xs font-semibold text-white transition ${
                isScanning
                  ? 'bg-[#238636]/50 cursor-not-allowed'
                  : 'bg-[#238636] hover:bg-[#2ea043] shadow-sm'
              }`}
            >
              {isScanning ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" /> Scanning Subnets...
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 fill-white" /> Start Reconnaissance Sweep
                </>
              )}
            </button>
          ) : (
            <button
              onClick={handleParseNmap}
              className="flex items-center gap-2 px-4 py-1.5 rounded text-xs font-semibold text-white bg-[#238636] hover:bg-[#2ea043] transition"
            >
              <Upload className="w-3.5 h-3.5" /> Parse & Update Topology
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
