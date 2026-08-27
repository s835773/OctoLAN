import React from 'react';
import { NetworkDevice, VlanInfo } from '../types';
import { 
  X, Shield, AlertTriangle, CheckCircle2, Cpu, 
  Layers, HardDrive, Globe, Terminal, Activity,
  Copy, ExternalLink, Hash, Clock
} from 'lucide-react';

interface DeviceDrawerProps {
  device: NetworkDevice | null;
  vlan: VlanInfo | undefined;
  onClose: () => void;
}

export const DeviceDrawer: React.FC<DeviceDrawerProps> = ({ device, vlan, onClose }) => {
  if (!device) return null;

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const getRiskBadge = (score: NetworkDevice['riskScore']) => {
    switch (score) {
      case 'Critical':
        return (
          <span className="px-2 py-0.5 rounded text-xs font-semibold bg-[#da3633]/20 text-[#f85149] border border-[#da3633]/40 flex items-center gap-1">
            <AlertTriangle className="w-3 h-3" /> Critical Risk
          </span>
        );
      case 'High':
        return (
          <span className="px-2 py-0.5 rounded text-xs font-semibold bg-[#da3633]/20 text-[#f85149] border border-[#da3633]/40 flex items-center gap-1">
            <AlertTriangle className="w-3 h-3" /> High Risk
          </span>
        );
      case 'Medium':
        return (
          <span className="px-2 py-0.5 rounded text-xs font-semibold bg-[#d29922]/20 text-[#d29922] border border-[#d29922]/40 flex items-center gap-1">
            <AlertTriangle className="w-3 h-3" /> Medium Risk
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 rounded text-xs font-semibold bg-[#238636]/20 text-[#7ee787] border border-[#238636]/40 flex items-center gap-1">
            <CheckCircle2 className="w-3 h-3" /> Good Hygiene
          </span>
        );
    }
  };

  return (
    <div className="fixed inset-y-0 right-0 w-full sm:w-[480px] bg-[#161b22] border-l border-[#30363d] shadow-2xl z-50 flex flex-col overflow-hidden">
      {/* Header */}
      <div className="p-4 bg-[#161b22] border-b border-[#30363d] flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-base font-bold text-[#f0f6fc]">{device.hostname || device.ip}</h2>
            {getRiskBadge(device.riskScore)}
          </div>
          <div className="flex items-center gap-2 mt-1 text-xs text-[#8b949e]">
            <span className="font-mono bg-[#010409] px-1.5 py-0.5 rounded text-[#58a6ff] border border-[#30363d]">{device.ip}</span>
            <span>•</span>
            <span className="font-mono text-[#c9d1d9]">{device.mac}</span>
          </div>
        </div>
        <button
          onClick={onClose}
          className="p-1.5 rounded text-[#8b949e] hover:text-[#c9d1d9] hover:bg-[#21262d] transition"
        >
          <X className="w-5 h-5" />
        </button>
      </div>

      {/* Body Scrollable */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4 text-[#c9d1d9] text-sm">
        {/* Quick Stats Grid */}
        <div className="grid grid-cols-2 gap-2.5">
          <div className="bg-[#010409] p-3 rounded border border-[#30363d]">
            <span className="text-[11px] text-[#8b949e] font-medium">VLAN Segment</span>
            <div className="flex items-center gap-1.5 mt-1">
              <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: vlan?.color || '#58a6ff' }} />
              <span className="font-semibold text-[#f0f6fc]">VLAN {device.vlanId}</span>
            </div>
            <span className="text-[11px] text-[#8b949e] truncate block mt-0.5">{device.vlanName}</span>
          </div>

          <div className="bg-[#010409] p-3 rounded border border-[#30363d]">
            <span className="text-[11px] text-[#8b949e] font-medium">Hardware / OUI Vendor</span>
            <div className="font-semibold text-[#f0f6fc] mt-1 truncate">{device.vendor}</div>
            <span className="text-[11px] text-[#8b949e]">Device: {device.deviceType}</span>
          </div>

          <div className="bg-[#010409] p-3 rounded border border-[#30363d]">
            <span className="text-[11px] text-[#8b949e] font-medium">Round-Trip Latency</span>
            <div className="font-semibold text-[#58a6ff] mt-1 font-mono">{device.latencyMs} ms</div>
            <span className="text-[11px] text-[#7ee787] flex items-center gap-1">
              <Activity className="w-3 h-3" /> Live & Responding
            </span>
          </div>

          <div className="bg-[#010409] p-3 rounded border border-[#30363d]">
            <span className="text-[11px] text-[#8b949e] font-medium">Last Probed</span>
            <div className="font-semibold text-[#f0f6fc] mt-1 text-xs">{device.lastSeen.split(' ')[1]}</div>
            <span className="text-[11px] text-[#8b949e]">First: {device.firstSeen.split(' ')[1]}</span>
          </div>
        </div>

        {/* Operating System Fingerprint Card */}
        <div className="bg-[#010409] p-3.5 rounded border border-[#30363d] space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-[#58a6ff] font-semibold text-xs uppercase tracking-wider">
              <Cpu className="w-4 h-4" /> OS Fingerprint Heuristics
            </div>
            <span className="text-xs bg-[#58a6ff]/15 text-[#58a6ff] font-mono px-2 py-0.5 rounded border border-[#58a6ff]/30">
              {device.osFingerprint.accuracy}% Match
            </span>
          </div>

          <div>
            <div className="text-sm font-bold text-[#f0f6fc]">{device.osFingerprint.name}</div>
            <div className="text-xs text-[#8b949e] mt-0.5">Family: <span className="text-[#c9d1d9] font-medium">{device.osFingerprint.family}</span></div>
          </div>

          <div className="grid grid-cols-2 gap-2 text-xs bg-[#161b22] p-2.5 rounded border border-[#30363d] font-mono">
            <div>
              <span className="text-[#8b949e] block text-[10px]">Initial IP TTL</span>
              <span className="text-[#58a6ff] font-bold">{device.osFingerprint.initialTtl}</span>
              <span className="text-[10px] text-[#8b949e] block">
                {device.osFingerprint.initialTtl <= 64 ? '(POSIX/Linux)' : device.osFingerprint.initialTtl <= 128 ? '(Windows NT)' : '(Cisco/Router)'}
              </span>
            </div>
            <div>
              <span className="text-[#8b949e] block text-[10px]">TCP Window Size</span>
              <span className="text-[#58a6ff] font-bold">{device.osFingerprint.tcpWindowSize}</span>
              <span className="text-[10px] text-[#8b949e] block">SYN ACK Window</span>
            </div>
          </div>

          <p className="text-xs text-[#8b949e] leading-relaxed bg-[#161b22] p-2.5 rounded border border-[#21262d]">
            {device.osFingerprint.details}
          </p>
        </div>

        {/* Security Hygiene & Risk Factors */}
        {device.riskFactors.length > 0 && (
          <div className="bg-[#da3633]/10 p-3.5 rounded border border-[#da3633]/40 space-y-2">
            <div className="flex items-center gap-2 text-[#f85149] font-semibold text-xs uppercase tracking-wider">
              <AlertTriangle className="w-4 h-4" /> Discovered Hygiene & Risk Warnings
            </div>
            <ul className="space-y-1.5 text-xs text-[#f85149]">
              {device.riskFactors.map((rf, idx) => (
                <li key={idx} className="flex items-start gap-2">
                  <span className="text-[#da3633] font-bold mt-0.5">•</span>
                  <span>{rf}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Open Ports & Services Audit */}
        <div className="space-y-2.5">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-[#8b949e] flex items-center gap-2">
              <Terminal className="w-4 h-4 text-[#8b949e]" />
              Open Ports & Services ({device.ports.length})
            </h3>
          </div>

          {device.ports.length === 0 ? (
            <div className="p-3 bg-[#010409] rounded border border-[#30363d] text-xs text-[#8b949e] text-center">
              No exposed TCP/UDP listening services discovered on tested common ports.
            </div>
          ) : (
            <div className="space-y-2">
              {device.ports.map((p, idx) => (
                <div 
                  key={idx} 
                  className={`p-2.5 rounded border text-xs flex flex-col gap-1 ${
                    p.isRisky 
                      ? 'bg-[#d29922]/10 border-[#d29922]/40 text-[#d29922]' 
                      : 'bg-[#010409] border-[#30363d] text-[#c9d1d9]'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold text-[#58a6ff] bg-[#161b22] px-1.5 py-0.5 rounded border border-[#30363d]">
                        {p.port}/{p.protocol.toUpperCase()}
                      </span>
                      <span className="font-semibold text-[#f0f6fc] uppercase">{p.service}</span>
                    </div>
                    <span className="text-[10px] text-[#7ee787] font-mono font-medium">STATE: {p.state}</span>
                  </div>

                  {p.version && (
                    <div className="text-[11px] font-mono text-[#8b949e] pl-1 border-l-2 border-[#30363d]">
                      {p.version}
                    </div>
                  )}

                  {p.isRisky && p.riskReason && (
                    <div className="text-[10px] text-[#d29922] flex items-center gap-1 font-medium mt-0.5">
                      <AlertTriangle className="w-3 h-3 flex-shrink-0" /> {p.riskReason}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* LLDP / 802.1Q Neighbor Info */}
        {device.lldpNeighbor && (
          <div className="bg-[#010409] p-3.5 rounded border border-[#30363d] space-y-2">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-[#8b949e] flex items-center gap-2">
              <Layers className="w-4 h-4 text-[#8b949e]" />
              802.1AB LLDP / CDP Switchport Binding
            </h3>
            <div className="text-xs space-y-1 font-mono bg-[#161b22] p-2.5 rounded border border-[#30363d]">
              <div><span className="text-[#8b949e]">Switch Name:</span> {device.lldpNeighbor.systemName}</div>
              <div><span className="text-[#8b949e]">Switch Port:</span> {device.lldpNeighbor.portId}</div>
              <div><span className="text-[#8b949e]">Chassis ID:</span> {device.lldpNeighbor.chassisId}</div>
              <div><span className="text-[#8b949e]">Trunk Tagged:</span> {device.lldpNeighbor.vlanTagged ? 'Yes (802.1Q Trunk)' : 'Access Port'}</div>
            </div>
          </div>
        )}

        {/* Active Protocols On Wire */}
        <div className="space-y-2">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-[#8b949e]">
            Observed Protocols On Wire
          </h3>
          <div className="flex flex-wrap gap-1.5">
            {device.activeProtocols.map((proto, i) => (
              <span key={i} className="text-xs px-2 py-0.5 rounded bg-[#010409] border border-[#30363d] text-[#c9d1d9] font-mono">
                {proto}
              </span>
            ))}
          </div>
        </div>

        {/* Quick CLI Testing Commands */}
        <div className="space-y-2 pt-2 border-t border-[#30363d]">
          <span className="text-xs font-semibold text-[#8b949e]">CLI Verification Commands</span>
          <div className="bg-[#010409] p-2.5 rounded border border-[#30363d] flex items-center justify-between text-xs font-mono text-[#c9d1d9]">
            <span className="truncate mr-2">nmap -sS -sV -O {device.ip}</span>
            <button
              onClick={() => copyToClipboard(`nmap -sS -sV -O ${device.ip}`)}
              className="p-1 text-[#8b949e] hover:text-[#58a6ff]"
              title="Copy Command"
            >
              <Copy className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
