import React, { useState } from 'react';
import { NetworkDevice, VlanInfo } from '../types';
import { 
  Server, Laptop, Shield, Wifi, Printer, Radio, 
  Layers, HardDrive, Smartphone, AlertTriangle, CheckCircle2,
  ChevronDown, ChevronRight, Search, Lock, ArrowRightLeft,
  FolderTree, GitFork, Cpu, ShieldAlert, Zap
} from 'lucide-react';

interface NetworkTreeViewProps {
  devices: NetworkDevice[];
  vlans: VlanInfo[];
  selectedDevice: NetworkDevice | null;
  onSelectDevice: (device: NetworkDevice) => void;
  filterVlan: number | 'all';
  onFilterVlanChange: (vlanId: number | 'all') => void;
  searchQuery?: string;
  hideEmbeddedSearch?: boolean;
}

export const NetworkTreeView: React.FC<NetworkTreeViewProps> = ({
  devices,
  vlans,
  selectedDevice,
  onSelectDevice,
  filterVlan,
  onFilterVlanChange,
  searchQuery = '',
  hideEmbeddedSearch = true
}) => {
  const [localSearch, setLocalSearch] = useState('');
  const activeSearch = searchQuery !== '' ? searchQuery : localSearch;
  
  // Track open state of root, switch, and individual VLAN branches
  const [expandedNodes, setExpandedNodes] = useState<Record<string, boolean>>({
    'root-gateway': true,
    'core-switch': true,
    ...vlans.reduce((acc, v) => ({ ...acc, [`vlan-${v.id}`]: true }), {})
  });

  const toggleNode = (nodeId: string) => {
    setExpandedNodes(prev => ({
      ...prev,
      [nodeId]: !prev[nodeId]
    }));
  };

  const expandAll = () => {
    const next: Record<string, boolean> = {
      'root-gateway': true,
      'core-switch': true
    };
    vlans.forEach(v => { next[`vlan-${v.id}`] = true; });
    setExpandedNodes(next);
  };

  const collapseAll = () => {
    setExpandedNodes({
      'root-gateway': true,
      'core-switch': false
    });
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

  const gateway = devices.find(d => d.deviceType === 'firewall' || d.deviceType === 'gateway');
  const coreSwitch = devices.find(d => d.deviceType === 'switch' && d.id.includes('core'));

  const displayedVlans = filterVlan === 'all' 
    ? vlans 
    : vlans.filter(v => v.id === filterVlan);

  return (
    <div className="space-y-3">
      {/* Search & Tree Controls Toolbar (when not hidden) */}
      {!hideEmbeddedSearch && (
        <div className="bg-[#161b22] border border-[#30363d] p-3 rounded-lg flex flex-wrap items-center justify-between gap-2.5">
          <div className="flex items-center gap-2 flex-1 min-w-[240px]">
            <div className="relative flex-1 max-w-sm">
              <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-[#8b949e]" />
              <input
                type="text"
                placeholder="Search tree nodes by IP, hostname, MAC..."
                value={localSearch}
                onChange={(e) => setLocalSearch(e.target.value)}
                className="w-full pl-9 pr-3 py-1.5 bg-[#010409] border border-[#30363d] rounded text-xs text-[#c9d1d9] placeholder-[#8b949e] focus:outline-none focus:border-[#58a6ff]"
              />
            </div>

            <div className="flex items-center gap-1">
              <span className="text-[#8b949e] text-xs">VLAN:</span>
              <select
                value={filterVlan}
                onChange={(e) => onFilterVlanChange(e.target.value === 'all' ? 'all' : Number(e.target.value))}
                className="bg-[#010409] border border-[#30363d] text-xs text-[#c9d1d9] rounded px-2.5 py-1.5 focus:outline-none focus:border-[#58a6ff]"
              >
                <option value="all">All ({vlans.length} VLANs)</option>
                {vlans.map(v => (
                  <option key={v.id} value={v.id}>VLAN {v.id} - {v.name}</option>
                ))}
              </select>
            </div>
          </div>

          <div className="flex items-center gap-2 text-xs">
            <button
              onClick={expandAll}
              className="px-2.5 py-1 rounded bg-[#21262d] text-[#58a6ff] hover:bg-[#30363d] font-medium border border-[#30363d] transition"
            >
              Expand All Tree
            </button>
            <button
              onClick={collapseAll}
              className="px-2.5 py-1 rounded bg-[#21262d] text-[#8b949e] hover:text-[#c9d1d9] hover:bg-[#30363d] font-medium border border-[#30363d] transition"
            >
              Collapse All
            </button>
          </div>
        </div>
      )}

      {/* When hideEmbeddedSearch is true, show clean header bar */}
      {hideEmbeddedSearch && (
        <div className="flex items-center justify-between px-1 text-xs text-[#8b949e]">
          <span>Tree Hierarchy: WAN Gateway → Core Switch → {displayedVlans.length} VLAN Trunks</span>
          <div className="flex items-center gap-2 text-xs">
            <button
              onClick={expandAll}
              className="px-2 py-0.5 rounded bg-[#21262d] text-[#58a6ff] hover:bg-[#30363d] font-medium border border-[#30363d] transition text-[11px]"
            >
              Expand All
            </button>
            <button
              onClick={collapseAll}
              className="px-2 py-0.5 rounded bg-[#21262d] text-[#8b949e] hover:text-[#c9d1d9] hover:bg-[#30363d] font-medium border border-[#30363d] transition text-[11px]"
            >
              Collapse All
            </button>
          </div>
        </div>
      )}

      {/* Hierarchical Tree Container */}
      <div className="bg-[#0d1117] border border-[#30363d] rounded-lg p-4 font-mono text-xs overflow-x-auto">
        <div className="min-w-[620px] space-y-1">

          {/* LEVEL 0: WAN / Gateway Root Node */}
          {gateway && (
            <div className="relative">
              <div 
                onClick={() => toggleNode('root-gateway')}
                className={`p-2.5 rounded-lg border transition cursor-pointer flex items-center justify-between ${
                  selectedDevice?.id === gateway.id
                    ? 'bg-[#161b22] border-[#58a6ff] ring-1 ring-[#58a6ff]'
                    : 'bg-[#161b22] border-[#30363d] hover:border-[#8b949e]'
                }`}
              >
                <div className="flex items-center gap-2.5">
                  <button 
                    onClick={(e) => { e.stopPropagation(); toggleNode('root-gateway'); }}
                    className="text-[#8b949e] hover:text-[#58a6ff]"
                  >
                    {expandedNodes['root-gateway'] ? (
                      <ChevronDown className="w-4 h-4 text-[#58a6ff]" />
                    ) : (
                      <ChevronRight className="w-4 h-4" />
                    )}
                  </button>

                  <div className="w-7 h-7 rounded bg-[#6366f1]/20 text-[#818cf8] flex items-center justify-center flex-shrink-0">
                    <Shield className="w-4 h-4" />
                  </div>

                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-[#f0f6fc] text-xs font-sans">
                        {gateway.hostname || gateway.ip}
                      </span>
                      <span className="px-1.5 py-0.2 rounded text-[10px] bg-[#6366f1]/20 text-[#818cf8] border border-[#6366f1]/40 font-mono">
                        WAN / Gateway Root
                      </span>
                      <span className="text-[10px] text-[#7ee787] flex items-center gap-1 font-sans">
                        <span className="w-1.5 h-1.5 rounded-full bg-[#238636]" /> Online
                      </span>
                    </div>
                    <div className="text-[11px] text-[#8b949e] flex items-center gap-2 mt-0.5">
                      <span className="text-[#58a6ff] font-semibold">{gateway.ip}</span>
                      <span>•</span>
                      <span>MAC: {gateway.mac}</span>
                      <span>•</span>
                      <span>{gateway.vendor}</span>
                    </div>
                  </div>
                </div>

                <button
                  onClick={(e) => { e.stopPropagation(); onSelectDevice(gateway); }}
                  className="px-2 py-1 rounded text-[11px] bg-[#21262d] text-[#58a6ff] hover:bg-[#30363d] border border-[#30363d] font-sans"
                >
                  Inspect Node
                </button>
              </div>

              {/* Trunk branch line to Core Switch */}
              {expandedNodes['root-gateway'] && (
                <div className="ml-5 pl-5 border-l-2 border-dashed border-[#58a6ff]/40 mt-2 space-y-3">
                  
                  {/* LEVEL 1: Core Switch Node */}
                  {coreSwitch && (
                    <div className="relative">
                      <div className="absolute -left-5 top-4 w-5 h-0.5 border-t-2 border-dashed border-[#58a6ff]/40" />
                      
                      <div 
                        onClick={() => toggleNode('core-switch')}
                        className={`p-2.5 rounded-lg border transition cursor-pointer flex items-center justify-between ${
                          selectedDevice?.id === coreSwitch.id
                            ? 'bg-[#161b22] border-[#58a6ff] ring-1 ring-[#58a6ff]'
                            : 'bg-[#161b22] border-[#30363d] hover:border-[#8b949e]'
                        }`}
                      >
                        <div className="flex items-center gap-2.5">
                          <button 
                            onClick={(e) => { e.stopPropagation(); toggleNode('core-switch'); }}
                            className="text-[#8b949e] hover:text-[#58a6ff]"
                          >
                            {expandedNodes['core-switch'] ? (
                              <ChevronDown className="w-4 h-4 text-[#58a6ff]" />
                            ) : (
                              <ChevronRight className="w-4 h-4" />
                            )}
                          </button>

                          <div className="w-7 h-7 rounded bg-[#58a6ff]/20 text-[#58a6ff] flex items-center justify-center flex-shrink-0">
                            <Layers className="w-4 h-4" />
                          </div>

                          <div>
                            <div className="flex items-center gap-2">
                              <span className="font-bold text-[#f0f6fc] text-xs font-sans">
                                {coreSwitch.hostname || coreSwitch.ip}
                              </span>
                              <span className="px-1.5 py-0.2 rounded text-[10px] bg-[#58a6ff]/20 text-[#58a6ff] border border-[#58a6ff]/40 font-mono">
                                802.1Q Core Trunk Switch
                              </span>
                              <span className="text-[10px] text-[#8b949e]">
                                [24 Port Gigabit + 4x 10G SFP+]
                              </span>
                            </div>
                            <div className="text-[11px] text-[#8b949e] flex items-center gap-2 mt-0.5">
                              <span className="text-[#58a6ff] font-semibold">{coreSwitch.ip}</span>
                              <span>•</span>
                              <span>MAC: {coreSwitch.mac}</span>
                              <span>•</span>
                              <span>{coreSwitch.vendor}</span>
                            </div>
                          </div>
                        </div>

                        <button
                          onClick={(e) => { e.stopPropagation(); onSelectDevice(coreSwitch); }}
                          className="px-2 py-1 rounded text-[11px] bg-[#21262d] text-[#58a6ff] hover:bg-[#30363d] border border-[#30363d] font-sans"
                        >
                          Inspect Switch
                        </button>
                      </div>

                      {/* LEVEL 2: VLAN Sub-Branches */}
                      {expandedNodes['core-switch'] && (
                        <div className="ml-5 pl-5 border-l-2 border-solid border-[#30363d] mt-2 space-y-3">
                          {displayedVlans.map((vlan, vlanIdx) => {
                            const isVlanExpanded = expandedNodes[`vlan-${vlan.id}`] ?? true;
                            
                            // Get devices belonging to this VLAN (excluding root gateway/switch to avoid duplicates)
                            let vlanDevices = devices.filter(d => 
                              d.vlanId === vlan.id && 
                              d.id !== gateway.id && 
                              d.id !== coreSwitch.id
                            );

                            if (activeSearch) {
                              const q = activeSearch.toLowerCase();
                              vlanDevices = vlanDevices.filter(d =>
                                d.ip.toLowerCase().includes(q) ||
                                d.hostname.toLowerCase().includes(q) ||
                                d.mac.toLowerCase().includes(q) ||
                                d.vendor.toLowerCase().includes(q) ||
                                d.osFingerprint.name.toLowerCase().includes(q)
                              );
                            }

                            return (
                              <div key={vlan.id} className="relative">
                                {/* Connector arm to switch trunk */}
                                <div 
                                  className="absolute -left-5 top-4 w-5 h-0.5"
                                  style={{ backgroundColor: vlan.color }}
                                />

                                {/* VLAN Header Branch Node */}
                                <div 
                                  onClick={() => toggleNode(`vlan-${vlan.id}`)}
                                  className="p-2.5 rounded-lg border bg-[#161b22] hover:bg-[#1c2128] transition cursor-pointer flex items-center justify-between"
                                  style={{ borderLeft: `4px solid ${vlan.color}`, borderColor: '#30363d' }}
                                >
                                  <div className="flex items-center gap-2">
                                    <button 
                                      onClick={(e) => { e.stopPropagation(); toggleNode(`vlan-${vlan.id}`)} }
                                      className="text-[#8b949e] hover:text-[#58a6ff]"
                                    >
                                      {isVlanExpanded ? (
                                        <ChevronDown className="w-3.5 h-3.5 text-[#58a6ff]" />
                                      ) : (
                                        <ChevronRight className="w-3.5 h-3.5" />
                                      )}
                                    </button>

                                    <span 
                                      className="w-2.5 h-2.5 rounded-full"
                                      style={{ backgroundColor: vlan.color }}
                                    />

                                    <div>
                                      <div className="flex items-center gap-2">
                                        <span className="font-bold text-xs" style={{ color: vlan.color }}>
                                          VLAN {vlan.id} — {vlan.name}
                                        </span>
                                        <span className="text-[10px] text-[#8b949e] font-sans">
                                          ({vlan.subnet})
                                        </span>
                                      </div>
                                      <div className="text-[10px] text-[#8b949e] flex items-center gap-2 mt-0.5">
                                        <span>Gateway: {vlan.gateway}</span>
                                        <span>•</span>
                                        <span>Security: {vlan.securityZone}</span>
                                        <span>•</span>
                                        <span>{vlan.isolated ? '🔒 Isolated Segment' : '↔️ Routed Segment'}</span>
                                      </div>
                                    </div>
                                  </div>

                                  <span className="text-[10px] px-2 py-0.5 rounded bg-[#010409] text-[#c9d1d9] border border-[#30363d]">
                                    {vlanDevices.length} endpoints
                                  </span>
                                </div>

                                {/* LEVEL 3: Connected Leaf Devices */}
                                {isVlanExpanded && (
                                  <div 
                                    className="ml-5 pl-5 border-l-2 mt-1.5 space-y-1.5"
                                    style={{ borderColor: `${vlan.color}50` }}
                                  >
                                    {vlanDevices.length === 0 ? (
                                      <div className="py-2 px-3 text-xs text-[#8b949e] italic bg-[#161b22]/30 rounded">
                                        {activeSearch ? 'No matching devices in this branch' : 'No devices connected on this VLAN'}
                                      </div>
                                    ) : (
                                      vlanDevices.map(device => {
                                        const isSelected = selectedDevice?.id === device.id;
                                        const hasRisk = device.riskScore === 'High' || device.riskScore === 'Critical';

                                        return (
                                          <div key={device.id} className="relative">
                                            {/* Branch connection horizontal line */}
                                            <div 
                                              className="absolute -left-5 top-4 w-5 h-0.5"
                                              style={{ backgroundColor: `${vlan.color}60` }}
                                            />

                                            <div
                                              onClick={() => onSelectDevice(device)}
                                              className={`p-2 rounded-lg border transition cursor-pointer flex items-center justify-between ${
                                                isSelected 
                                                  ? 'bg-[#161b22] border-[#58a6ff] ring-1 ring-[#58a6ff]' 
                                                  : 'bg-[#161b22]/80 border-[#21262d] hover:border-[#8b949e] hover:bg-[#161b22]'
                                              }`}
                                            >
                                              <div className="flex items-center gap-2.5 min-w-0">
                                                <div 
                                                  className="w-6 h-6 rounded flex items-center justify-center flex-shrink-0"
                                                  style={{ backgroundColor: `${vlan.color}20`, color: vlan.color }}
                                                >
                                                  {getDeviceIcon(device.deviceType)}
                                                </div>

                                                <div className="min-w-0">
                                                  <div className="flex items-center gap-2">
                                                    <span className="font-semibold text-xs text-[#f0f6fc] truncate font-sans">
                                                      {device.hostname || device.ip}
                                                    </span>
                                                    <span className="text-[11px] text-[#58a6ff] font-mono">
                                                      {device.ip}
                                                    </span>
                                                  </div>
                                                  <div className="text-[10px] text-[#8b949e] flex items-center gap-2 truncate">
                                                    <span>MAC: {device.mac}</span>
                                                    <span>•</span>
                                                    <span className="truncate">{device.vendor}</span>
                                                    <span>•</span>
                                                    <span>TTL {device.osFingerprint.ttl} ({device.osFingerprint.family})</span>
                                                  </div>
                                                </div>
                                              </div>

                                              <div className="flex items-center gap-2 flex-shrink-0">
                                                {hasRisk ? (
                                                  <span className="text-[9px] px-1.5 py-0.5 rounded bg-[#da3633]/20 text-[#f85149] border border-[#da3633]/30 font-sans flex items-center gap-1 font-semibold">
                                                    <AlertTriangle className="w-2.5 h-2.5" /> High Risk
                                                  </span>
                                                ) : (
                                                  <span className="text-[9px] px-1.5 py-0.5 rounded bg-[#238636]/15 text-[#7ee787] border border-[#238636]/30 font-sans">
                                                    Normal
                                                  </span>
                                                )}
                                                <span className="text-[10px] text-[#8b949e] font-sans hover:text-[#58a6ff]">
                                                  Inspect →
                                                </span>
                                              </div>
                                            </div>
                                          </div>
                                        );
                                      })
                                    )}
                                  </div>
                                )}
                              </div>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

        </div>
      </div>
    </div>
  );
};
