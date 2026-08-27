import React, { useState } from 'react';
import { VlanInfo, NetworkDevice } from '../types';
import { 
  Layers, Shield, Server, Laptop, Wifi, Printer, Radio, 
  HardDrive, Smartphone, ChevronDown, ChevronRight, Lock, 
  ArrowRightLeft, AlertTriangle, CheckCircle2, Search, ExternalLink,
  ShieldCheck, ShieldAlert
} from 'lucide-react';

interface MobileVlanClustersProps {
  vlans: VlanInfo[];
  devices: NetworkDevice[];
  selectedDevice: NetworkDevice | null;
  onSelectDevice: (device: NetworkDevice) => void;
  filterVlan: number | 'all';
  onFilterVlanChange: (vlanId: number | 'all') => void;
  searchQuery?: string;
  hideEmbeddedSearch?: boolean;
}

export const MobileVlanClusters: React.FC<MobileVlanClustersProps> = ({
  vlans,
  devices,
  selectedDevice,
  onSelectDevice,
  filterVlan,
  onFilterVlanChange,
  searchQuery = '',
  hideEmbeddedSearch = true
}) => {
  const [expandedVlans, setExpandedVlans] = useState<Record<number, boolean>>(() => {
    // Expand the first 2 VLANs by default for quick browsing
    const initial: Record<number, boolean> = {};
    vlans.forEach((v, idx) => {
      initial[v.id] = idx < 2;
    });
    return initial;
  });

  const [localSearch, setLocalSearch] = useState('');
  const activeSearch = searchQuery !== '' ? searchQuery : localSearch;

  const toggleVlan = (vlanId: number) => {
    setExpandedVlans(prev => ({
      ...prev,
      [vlanId]: !prev[vlanId]
    }));
  };

  const expandAll = () => {
    const next: Record<number, boolean> = {};
    vlans.forEach(v => { next[v.id] = true; });
    setExpandedVlans(next);
  };

  const collapseAll = () => {
    const next: Record<number, boolean> = {};
    vlans.forEach(v => { next[v.id] = false; });
    setExpandedVlans(next);
  };

  const getDeviceIcon = (type: NetworkDevice['deviceType']) => {
    switch (type) {
      case 'firewall':
      case 'gateway': return <Shield className="w-3.5 h-3.5" />;
      case 'switch': return <Layers className="w-3.5 h-3.5" />;
      case 'access_point': return <Wifi className="w-3.5 h-3.5" />;
      case 'server': return <Server className="w-3.5 h-3.5" />;
      case 'workstation': return <Laptop className="w-3.5 h-3.5" />;
      case 'mobile': return <Smartphone className="w-3.5 h-3.5" />;
      case 'printer': return <Printer className="w-3.5 h-3.5" />;
      case 'iot': return <Radio className="w-3.5 h-3.5" />;
      default: return <HardDrive className="w-3.5 h-3.5" />;
    }
  };

  // Filter VLANs according to global filter if set
  const displayedVlans = filterVlan === 'all' 
    ? vlans 
    : vlans.filter(v => v.id === filterVlan);

  // Core network infrastructure (Gateway & Switch)
  const coreInfrastructure = devices.filter(
    d => d.deviceType === 'gateway' || d.deviceType === 'firewall' || (d.deviceType === 'switch' && d.id.includes('core'))
  );

  return (
    <div className="space-y-3">
      {/* Quick Controls bar (when embedded search is not hidden) */}
      {!hideEmbeddedSearch && (
        <div className="bg-[#161b22] border border-[#30363d] p-3 rounded-lg space-y-2.5">
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-[#8b949e]" />
            <input
              type="text"
              placeholder="Quick search IP, host, MAC in clusters..."
              value={localSearch}
              onChange={(e) => setLocalSearch(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 bg-[#010409] border border-[#30363d] rounded text-xs text-[#c9d1d9] placeholder-[#8b949e] focus:outline-none focus:border-[#58a6ff]"
            />
          </div>

          <div className="flex items-center justify-between text-xs pt-1 border-t border-[#21262d]">
            <div className="flex items-center gap-1">
              <span className="text-[#8b949e] text-[11px]">VLAN Filter:</span>
              <select
                value={filterVlan}
                onChange={(e) => onFilterVlanChange(e.target.value === 'all' ? 'all' : Number(e.target.value))}
                className="bg-[#010409] border border-[#30363d] text-[11px] text-[#c9d1d9] rounded px-2 py-1 focus:outline-none focus:border-[#58a6ff]"
              >
                <option value="all">All ({vlans.length} VLANs)</option>
                {vlans.map(v => (
                  <option key={v.id} value={v.id}>VLAN {v.id} - {v.name}</option>
                ))}
              </select>
            </div>

            <div className="flex items-center gap-2 text-[11px]">
              <button 
                onClick={expandAll}
                className="text-[#58a6ff] hover:underline"
              >
                Expand All
              </button>
              <span className="text-[#30363d]">|</span>
              <button 
                onClick={collapseAll}
                className="text-[#8b949e] hover:underline"
              >
                Collapse
              </button>
            </div>
          </div>
        </div>
      )}

      {/* When hideEmbeddedSearch is true, show clean Expand / Collapse buttons header if needed */}
      {hideEmbeddedSearch && (
        <div className="flex items-center justify-between px-1 text-xs text-[#8b949e]">
          <span>Showing {displayedVlans.length} VLAN clusters</span>
          <div className="flex items-center gap-2 text-[11px]">
            <button 
              onClick={expandAll}
              className="text-[#58a6ff] hover:underline font-medium"
            >
              Expand All Cards
            </button>
            <span className="text-[#30363d]">|</span>
            <button 
              onClick={collapseAll}
              className="text-[#8b949e] hover:underline"
            >
              Collapse All
            </button>
          </div>
        </div>
      )}

      {/* Core Gateway & Backbone Card */}
      {filterVlan === 'all' && (
        <div className="bg-[#161b22] border border-[#30363d] rounded-lg overflow-hidden border-t-2 border-t-[#58a6ff]">
          <div className="p-3 bg-[#1c2128] flex items-center justify-between border-b border-[#30363d]">
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4 text-[#58a6ff]" />
              <div>
                <h3 className="text-xs font-bold text-[#f0f6fc]">Core Gateway & Switch Backbone</h3>
                <span className="text-[10px] text-[#8b949e] font-mono">IEEE 802.1Q 10G Trunk Master</span>
              </div>
            </div>
            <span className="text-[10px] px-2 py-0.5 rounded bg-[#238636]/20 text-[#7ee787] font-medium border border-[#238636]/40">
              Online
            </span>
          </div>

          <div className="p-2.5 grid grid-cols-1 sm:grid-cols-2 gap-2 bg-[#0d1117]">
            {coreInfrastructure.map(dev => {
              const isSelected = selectedDevice?.id === dev.id;
              return (
                <div
                  key={dev.id}
                  onClick={() => onSelectDevice(dev)}
                  className={`p-2.5 rounded border transition cursor-pointer flex items-center justify-between ${
                    isSelected 
                      ? 'bg-[#161b22] border-[#58a6ff] ring-1 ring-[#58a6ff]' 
                      : 'bg-[#161b22] border-[#30363d] hover:border-[#8b949e]'
                  }`}
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    <div className="w-7 h-7 rounded bg-[#58a6ff]/15 text-[#58a6ff] flex items-center justify-center flex-shrink-0">
                      {getDeviceIcon(dev.deviceType)}
                    </div>
                    <div className="min-w-0">
                      <div className="text-xs font-semibold text-[#f0f6fc] truncate">
                        {dev.hostname || dev.ip}
                      </div>
                      <div className="text-[10px] font-mono text-[#58a6ff]">
                        {dev.ip} <span className="text-[#8b949e] font-sans">({dev.vendor})</span>
                      </div>
                    </div>
                  </div>
                  <ChevronRight className="w-3.5 h-3.5 text-[#8b949e] flex-shrink-0" />
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* VLAN Cluster Cards */}
      <div className="space-y-3">
        {displayedVlans.map(vlan => {
          const isExpanded = expandedVlans[vlan.id] ?? true;
          
          // Filter devices for this VLAN
          let vlanDevices = devices.filter(d => 
            d.vlanId === vlan.id && 
            !coreInfrastructure.some(c => c.id === d.id)
          );

          if (activeSearch) {
            const query = activeSearch.toLowerCase();
            vlanDevices = vlanDevices.filter(d =>
              d.ip.toLowerCase().includes(query) ||
              d.hostname.toLowerCase().includes(query) ||
              d.mac.toLowerCase().includes(query) ||
              d.vendor.toLowerCase().includes(query) ||
              d.osFingerprint.name.toLowerCase().includes(query)
            );
          }

          const hasRisks = vlanDevices.some(d => d.riskScore === 'High' || d.riskScore === 'Critical');

          return (
            <div
              key={vlan.id}
              className="bg-[#161b22] border border-[#30363d] rounded-lg overflow-hidden shadow-sm transition"
              style={{ borderTop: `3px solid ${vlan.color}` }}
            >
              {/* Card Header (Accordion toggle) */}
              <div
                onClick={() => toggleVlan(vlan.id)}
                className="p-3 bg-[#161b22] hover:bg-[#1c2128] cursor-pointer flex items-center justify-between transition"
              >
                <div className="flex items-center gap-2.5 min-w-0">
                  <span 
                    className="w-3 h-3 rounded-full flex-shrink-0"
                    style={{ backgroundColor: vlan.color }}
                  />
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span 
                        className="text-xs font-mono font-bold uppercase"
                        style={{ color: vlan.color }}
                      >
                        VLAN {vlan.id}
                      </span>
                      <h4 className="text-xs font-bold text-[#f0f6fc] truncate">
                        {vlan.name}
                      </h4>
                    </div>
                    <div className="text-[10px] text-[#8b949e] font-mono flex items-center gap-2 mt-0.5">
                      <span>{vlan.subnet}</span>
                      <span>•</span>
                      <span>GW: {vlan.gateway}</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2 flex-shrink-0">
                  {vlan.isolated ? (
                    <span className="flex items-center gap-1 text-[9px] text-[#7ee787] bg-[#238636]/15 px-1.5 py-0.5 rounded border border-[#238636]/30">
                      <Lock className="w-2.5 h-2.5" /> Iso
                    </span>
                  ) : (
                    <span className="flex items-center gap-1 text-[9px] text-[#d29922] bg-[#d29922]/10 px-1.5 py-0.5 rounded border border-[#d29922]/30">
                      <ArrowRightLeft className="w-2.5 h-2.5" /> Route
                    </span>
                  )}

                  <span className="text-[11px] font-mono font-semibold px-2 py-0.5 rounded bg-[#010409] text-[#c9d1d9] border border-[#30363d]">
                    {vlanDevices.length} hosts
                  </span>

                  {isExpanded ? (
                    <ChevronDown className="w-4 h-4 text-[#58a6ff]" />
                  ) : (
                    <ChevronRight className="w-4 h-4 text-[#8b949e]" />
                  )}
                </div>
              </div>

              {/* Card Body - Connected Device Nodes */}
              {isExpanded && (
                <div className="p-2.5 bg-[#0d1117] border-t border-[#21262d] space-y-2">
                  <div className="text-[10px] text-[#8b949e] px-1 flex items-center justify-between">
                    <span>{vlan.description}</span>
                    <span className="text-[#58a6ff] font-medium">{vlan.securityZone}</span>
                  </div>

                  {vlanDevices.length === 0 ? (
                    <div className="p-4 text-center text-xs text-[#8b949e] bg-[#161b22]/40 rounded border border-dashed border-[#30363d]">
                      {activeSearch ? 'No matching devices found in this cluster.' : 'No endpoints currently assigned to this VLAN.'}
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                      {vlanDevices.map(device => {
                        const isSelected = selectedDevice?.id === device.id;
                        const hasRisk = device.riskScore === 'High' || device.riskScore === 'Critical';

                        return (
                          <div
                            key={device.id}
                            onClick={() => onSelectDevice(device)}
                            className={`p-2.5 rounded-lg border transition cursor-pointer flex items-center justify-between ${
                              isSelected 
                                ? 'bg-[#161b22] border-[#58a6ff] ring-1 ring-[#58a6ff]' 
                                : 'bg-[#161b22] border-[#30363d] hover:border-[#8b949e]'
                            }`}
                          >
                            <div className="flex items-center gap-2.5 min-w-0">
                              {/* Icon + Status */}
                              <div className="relative flex-shrink-0">
                                <div 
                                  className="w-8 h-8 rounded-lg flex items-center justify-center"
                                  style={{ backgroundColor: `${vlan.color}20`, color: vlan.color }}
                                >
                                  {getDeviceIcon(device.deviceType)}
                                </div>
                                {hasRisk ? (
                                  <span className="absolute -top-1 -right-1 w-3.5 h-3.5 bg-[#da3633] rounded-full flex items-center justify-center text-white text-[9px] font-bold ring-1 ring-[#161b22]">
                                    !
                                  </span>
                                ) : (
                                  <span className="absolute -bottom-0.5 -right-0.5 w-2 h-2 bg-[#238636] rounded-full ring-1 ring-[#161b22]" />
                                )}
                              </div>

                              {/* Host Details */}
                              <div className="min-w-0">
                                <div className="text-xs font-semibold text-[#f0f6fc] truncate">
                                  {device.hostname || device.ip}
                                </div>
                                <div className="text-[10px] font-mono text-[#58a6ff] flex items-center gap-1.5">
                                  <span>{device.ip}</span>
                                  <span className="text-[#8b949e] font-sans">• {device.vendor}</span>
                                </div>
                                <div className="flex items-center gap-1 mt-0.5">
                                  <span className="text-[9px] px-1 py-0.2 rounded bg-[#010409] text-[#8b949e] border border-[#30363d] font-mono">
                                    TTL {device.osFingerprint.ttl}
                                  </span>
                                  <span className="text-[9px] text-[#8b949e] truncate max-w-[120px]">
                                    {device.osFingerprint.name.split(' ')[0]}
                                  </span>
                                </div>
                              </div>
                            </div>

                            <div className="flex items-center gap-1 flex-shrink-0 pl-2">
                              {hasRisk && (
                                <span className="text-[9px] px-1.5 py-0.5 rounded bg-[#da3633]/20 text-[#f85149] font-medium border border-[#da3633]/30">
                                  Risk
                                </span>
                              )}
                              <ChevronRight className="w-3.5 h-3.5 text-[#8b949e]" />
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
