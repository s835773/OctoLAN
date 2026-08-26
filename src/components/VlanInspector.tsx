import React from 'react';
import { VlanInfo, NetworkDevice } from '../types';
import { Layers, ShieldCheck, ShieldAlert, Network, ArrowRightLeft, Lock, Unlock, Server } from 'lucide-react';

interface VlanInspectorProps {
  vlans: VlanInfo[];
  devices: NetworkDevice[];
  onSelectVlan: (vlanId: number) => void;
}

export const VlanInspector: React.FC<VlanInspectorProps> = ({ vlans, devices, onSelectVlan }) => {
  return (
    <div className="space-y-4">
      {/* Intro Header */}
      <div className="bg-[#161b22] border border-[#30363d] p-4 rounded flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-sm font-bold text-[#f0f6fc] flex items-center gap-2">
            <Layers className="w-4 h-4 text-[#58a6ff]" />
            IEEE 802.1Q VLAN Segmentation & Topology Audit
          </h2>
          <p className="text-xs text-[#8b949e] mt-1 max-w-2xl leading-relaxed">
            Inspection of Layer 2 virtual broadcast domains, trunk links, inter-VLAN ACL routing enforcement, and guest/IoT isolation boundaries discovered via LLDP/CDP and ARP broadcast sniffs.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <div className="bg-[#010409] px-3 py-1.5 rounded border border-[#30363d] text-center">
            <span className="text-[10px] text-[#8b949e] uppercase block font-semibold">Active VLANs</span>
            <span className="text-sm font-bold text-[#58a6ff] font-mono">{vlans.length}</span>
          </div>
          <div className="bg-[#010409] px-3 py-1.5 rounded border border-[#30363d] text-center">
            <span className="text-[10px] text-[#8b949e] uppercase block font-semibold">Isolated Subnets</span>
            <span className="text-sm font-bold text-[#7ee787] font-mono">
              {vlans.filter(v => v.isolated).length}
            </span>
          </div>
        </div>
      </div>

      {/* VLAN Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {vlans.map(vlan => {
          const vDevices = devices.filter(d => d.vlanId === vlan.id);
          const hasRisk = vDevices.some(d => d.riskScore === 'High' || d.riskScore === 'Critical');

          return (
            <div
              key={vlan.id}
              onClick={() => onSelectVlan(vlan.id)}
              className="bg-[#161b22] border border-[#30363d] rounded p-3.5 hover:border-[#58a6ff] transition cursor-pointer flex flex-col justify-between group"
            >
              <div className="space-y-2.5">
                {/* Header */}
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-center gap-1.5">
                      <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: vlan.color }} />
                      <span 
                        className="text-[10px] font-mono font-bold uppercase"
                        style={{ color: vlan.color }}
                      >
                        VLAN {vlan.id}
                      </span>
                    </div>
                    <h3 className="text-sm font-bold text-[#f0f6fc] mt-1 group-hover:text-[#58a6ff] transition">
                      {vlan.name}
                    </h3>
                  </div>

                  {vlan.isolated ? (
                    <span className="flex items-center gap-1 text-[10px] text-[#7ee787] bg-[#238636]/15 px-2 py-0.5 rounded border border-[#238636]/30 font-medium">
                      <Lock className="w-3 h-3" /> Isolated
                    </span>
                  ) : (
                    <span className="flex items-center gap-1 text-[10px] text-[#d29922] bg-[#d29922]/10 px-2 py-0.5 rounded border border-[#d29922]/30 font-medium">
                      <ArrowRightLeft className="w-3 h-3" /> Routed
                    </span>
                  )}
                </div>

                {/* Subnet & Gateway */}
                <div className="bg-[#010409] p-2.5 rounded border border-[#30363d] font-mono text-xs space-y-1">
                  <div className="flex justify-between">
                    <span className="text-[#8b949e]">Subnet:</span>
                    <span className="text-[#c9d1d9] font-semibold">{vlan.subnet}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#8b949e]">Gateway:</span>
                    <span className="text-[#8b949e]">{vlan.gateway}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#8b949e]">Zone:</span>
                    <span className="text-[#58a6ff]">{vlan.securityZone}</span>
                  </div>
                </div>

                <p className="text-xs text-[#8b949e] leading-relaxed">
                  {vlan.description}
                </p>
              </div>

              {/* Footer Host Count */}
              <div className="mt-3 pt-2.5 border-t border-[#30363d] flex items-center justify-between text-xs">
                <span className="text-[#8b949e] flex items-center gap-1.5">
                  <Server className="w-3.5 h-3.5 text-[#8b949e]" />
                  {vDevices.length} Connected Hosts
                </span>
                {hasRisk && (
                  <span className="text-[10px] text-[#f85149] font-medium flex items-center gap-1">
                    <ShieldAlert className="w-3 h-3" /> Risk Flagged
                  </span>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* VLAN Hopping & Segmentation Security Notice */}
      <div className="bg-[#161b22] border border-[#30363d] p-3.5 rounded text-xs space-y-1.5 text-[#c9d1d9]">
        <h4 className="font-bold text-[#58a6ff] flex items-center gap-2 text-xs uppercase tracking-wider">
          <ShieldCheck className="w-4 h-4 text-[#58a6ff]" />
          Defensive Segmentation & VLAN Hopping Considerations
        </h4>
        <p className="text-[#8b949e] leading-relaxed">
          Ensure that native VLAN 1 is never used on user-facing switch access ports, and disable Dynamic Trunking Protocol (DTP) to prevent unauthorized switch spoofing. Double-tagging (802.1Q-in-Q) attacks can be mitigated by keeping the native VLAN on trunks distinct from all access VLAN IDs.
        </p>
      </div>
    </div>
  );
};
