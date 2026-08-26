import React, { useState, useRef, useMemo } from 'react';
import { NetworkDevice, VlanInfo } from '../types';
import { 
  Server, Laptop, Shield, Wifi, Printer, Radio, 
  Layers, HardDrive, Smartphone, AlertTriangle, CheckCircle2,
  ZoomIn, ZoomOut, RotateCcw, Filter, Search
} from 'lucide-react';

interface TopologyGraphProps {
  devices: NetworkDevice[];
  vlans: VlanInfo[];
  selectedDevice: NetworkDevice | null;
  onSelectDevice: (dev: NetworkDevice) => void;
  filterVlan: number | 'all';
  onFilterVlanChange: (vlanId: number | 'all') => void;
}

export const TopologyGraph: React.FC<TopologyGraphProps> = ({
  devices,
  vlans,
  selectedDevice,
  onSelectDevice,
  filterVlan,
  onFilterVlanChange,
}) => {
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [searchQuery, setSearchQuery] = useState('');
  const [layoutMode, setLayoutMode] = useState<'vlan-clusters' | 'hierarchical'>('vlan-clusters');

  const containerRef = useRef<HTMLDivElement>(null);

  // Filtered devices
  const filteredDevices = useMemo(() => {
    return devices.filter(d => {
      const matchesVlan = filterVlan === 'all' || d.vlanId === filterVlan;
      const matchesSearch = searchQuery === '' || 
        d.ip.toLowerCase().includes(searchQuery.toLowerCase()) ||
        d.hostname.toLowerCase().includes(searchQuery.toLowerCase()) ||
        d.mac.toLowerCase().includes(searchQuery.toLowerCase()) ||
        d.osFingerprint.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        d.vendor.toLowerCase().includes(searchQuery.toLowerCase());
      return matchesVlan && matchesSearch;
    });
  }, [devices, filterVlan, searchQuery]);

  // Compute layout coordinates for nodes
  const nodePositions = useMemo(() => {
    const posMap = new Map<string, { x: number; y: number; vlanColor: string }>();
    
    // Core gateway & switch at the top center
    const gateway = devices.find(d => d.deviceType === 'firewall' || d.deviceType === 'gateway');
    const coreSwitch = devices.find(d => d.deviceType === 'switch' && d.id.includes('core'));

    const centerX = 500;
    if (gateway) {
      posMap.set(gateway.id, { x: centerX, y: 80, vlanColor: '#6366f1' });
    }
    if (coreSwitch) {
      posMap.set(coreSwitch.id, { x: centerX, y: 190, vlanColor: '#6366f1' });
    }

    if (layoutMode === 'vlan-clusters') {
      // Group remaining devices by VLAN
      const vlanGroups = new Map<number, NetworkDevice[]>();
      vlans.forEach(v => vlanGroups.set(v.id, []));

      filteredDevices.forEach(d => {
        if (d.id !== gateway?.id && d.id !== coreSwitch?.id) {
          const list = vlanGroups.get(d.vlanId) || [];
          list.push(d);
          vlanGroups.set(d.vlanId, list);
        }
      });

      const activeVlans = vlans.filter(v => (vlanGroups.get(v.id)?.length || 0) > 0);
      const vlanCount = Math.max(1, activeVlans.length);
      const spacingX = 900 / (vlanCount + 1);

      activeVlans.forEach((vlan, vIndex) => {
        const clusterCenterX = 100 + (vIndex + 1) * spacingX;
        const clusterCenterY = 380;
        const vDevices = vlanGroups.get(vlan.id) || [];

        vDevices.forEach((dev, dIndex) => {
          // Circle or grid layout inside cluster
          const angle = (dIndex / Math.max(1, vDevices.length)) * 2 * Math.PI;
          const radius = vDevices.length > 1 ? 110 : 0;
          const x = clusterCenterX + Math.cos(angle) * radius;
          const y = clusterCenterY + Math.sin(angle) * radius;
          posMap.set(dev.id, { x, y, vlanColor: vlan.color });
        });
      });
    } else {
      // Hierarchical layout
      const layers: { [key: string]: NetworkDevice[] } = {
        switches: [],
        servers: [],
        clients: [],
        iot: []
      };

      filteredDevices.forEach(d => {
        if (d.id === gateway?.id || d.id === coreSwitch?.id) return;
        if (d.deviceType === 'switch' || d.deviceType === 'access_point') layers.switches.push(d);
        else if (d.deviceType === 'server') layers.servers.push(d);
        else if (d.deviceType === 'workstation' || d.deviceType === 'mobile') layers.clients.push(d);
        else layers.iot.push(d);
      });

      const assignRow = (devs: NetworkDevice[], y: number) => {
        const step = 800 / (devs.length + 1);
        devs.forEach((d, i) => {
          const vColor = vlans.find(v => v.id === d.vlanId)?.color || '#64748b';
          posMap.set(d.id, { x: 100 + (i + 1) * step, y, vlanColor: vColor });
        });
      };

      assignRow(layers.switches, 280);
      assignRow(layers.servers, 390);
      assignRow(layers.clients, 500);
      assignRow(layers.iot, 610);
    }

    return posMap;
  }, [devices, filteredDevices, vlans, layoutMode]);

  // Pan handlers
  const handleMouseDown = (e: React.MouseEvent) => {
    if (e.target === containerRef.current || (e.target as HTMLElement).tagName === 'svg') {
      setIsDragging(true);
      setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
    }
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (isDragging) {
      setPan({
        x: e.clientX - dragStart.x,
        y: e.clientY - dragStart.y,
      });
    }
  };

  const handleMouseUp = () => setIsDragging(false);

  const getDeviceIcon = (type: NetworkDevice['deviceType']) => {
    switch (type) {
      case 'firewall':
      case 'gateway': return <Shield className="w-4 h-4" />;
      case 'switch': return <Layers className="w-4 h-4" />;
      case 'access_point': return <Wifi className="w-4 h-4" />;
      case 'server': return <Server className="w-4 h-4" />;
      case 'workstation': return <Laptop className="w-4 h-4" />;
      case 'mobile': return <Smartphone className="w-4 h-4" />;
      case 'printer': return <Printer className="w-4 h-4" />;
      case 'iot': return <Radio className="w-4 h-4" />;
      default: return <HardDrive className="w-4 h-4" />;
    }
  };

  return (
    <div className="relative w-full h-[650px] bg-[#0d1117] border border-[#30363d] rounded-md overflow-hidden flex flex-col select-none">
      {/* Top Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-2 p-3 bg-[#161b22] border-b border-[#30363d] z-10">
        <div className="flex items-center gap-2 flex-1 min-w-[240px]">
          <div className="relative flex-1 max-w-xs">
            <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-[#8b949e]" />
            <input
              type="text"
              placeholder="Search IP, MAC, hostname, OS..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 bg-[#010409] border border-[#30363d] rounded text-xs text-[#c9d1d9] placeholder-[#8b949e] focus:outline-none focus:border-[#58a6ff]"
            />
          </div>

          {/* VLAN Filter */}
          <div className="flex items-center gap-1">
            <Filter className="w-3.5 h-3.5 text-[#8b949e]" />
            <select
              value={filterVlan}
              onChange={(e) => onFilterVlanChange(e.target.value === 'all' ? 'all' : Number(e.target.value))}
              className="bg-[#010409] border border-[#30363d] text-xs text-[#c9d1d9] rounded px-2.5 py-1.5 focus:outline-none focus:border-[#58a6ff]"
            >
              <option value="all">All VLANs ({devices.length} hosts)</option>
              {vlans.map(v => (
                <option key={v.id} value={v.id}>
                  VLAN {v.id} - {v.name}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Controls & Layout */}
        <div className="flex items-center gap-2">
          <div className="flex bg-[#010409] p-0.5 rounded border border-[#30363d] text-xs">
            <button
              onClick={() => setLayoutMode('vlan-clusters')}
              className={`px-2.5 py-1 rounded transition ${layoutMode === 'vlan-clusters' ? 'bg-[#21262d] text-[#58a6ff] font-semibold border border-[#30363d]' : 'text-[#8b949e] hover:text-[#c9d1d9]'}`}
            >
              VLAN Clusters
            </button>
            <button
              onClick={() => setLayoutMode('hierarchical')}
              className={`px-2.5 py-1 rounded transition ${layoutMode === 'hierarchical' ? 'bg-[#21262d] text-[#58a6ff] font-semibold border border-[#30363d]' : 'text-[#8b949e] hover:text-[#c9d1d9]'}`}
            >
              Layer 2/3 Hierarchy
            </button>
          </div>

          <div className="flex items-center bg-[#010409] rounded border border-[#30363d] p-0.5">
            <button
              onClick={() => setZoom(z => Math.min(1.8, z + 0.15))}
              className="p-1.5 text-[#8b949e] hover:text-[#c9d1d9] rounded"
              title="Zoom In"
            >
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => setZoom(z => Math.max(0.5, z - 0.15))}
              className="p-1.5 text-[#8b949e] hover:text-[#c9d1d9] rounded"
              title="Zoom Out"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => { setZoom(1); setPan({ x: 0, y: 0 }); }}
              className="p-1.5 text-[#8b949e] hover:text-[#c9d1d9] rounded"
              title="Reset View"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Main Canvas / SVG Interactive Area */}
      <div 
        ref={containerRef}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        className="flex-1 w-full h-full relative cursor-grab active:cursor-grabbing overflow-hidden bg-[#0d1117] bg-[radial-gradient(#21262d_1px,transparent_1px)] [background-size:20px_20px]"
      >
        <svg 
          className="w-full h-full absolute inset-0 pointer-events-none"
          style={{
            transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
            transformOrigin: '500px 300px',
            transition: isDragging ? 'none' : 'transform 0.1s ease-out'
          }}
          viewBox="0 0 1000 700"
        >
          <defs>
            <linearGradient id="trunkLine" x1="0%" y1="0%" x2="0%" y2="100%">
              <stop offset="0%" stopColor="#58a6ff" stopOpacity="0.8" />
              <stop offset="100%" stopColor="#238636" stopOpacity="0.4" />
            </linearGradient>
            <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feComposite in="SourceGraphic" in2="blur" operator="over" />
            </filter>
          </defs>

          {/* Links: Gateway -> Core Switch */}
          {(() => {
            const gw = devices.find(d => d.deviceType === 'firewall' || d.deviceType === 'gateway');
            const sw = devices.find(d => d.deviceType === 'switch' && d.id.includes('core'));
            if (!gw || !sw) return null;
            const p1 = nodePositions.get(gw.id);
            const p2 = nodePositions.get(sw.id);
            if (!p1 || !p2) return null;

            return (
              <g key="gw-sw-link">
                <line
                  x1={p1.x}
                  y1={p1.y}
                  x2={p2.x}
                  y2={p2.y}
                  stroke="#58a6ff"
                  strokeWidth="2.5"
                  strokeDasharray="4 2"
                />
                <text x={(p1.x + p2.x) / 2 + 10} y={(p1.y + p2.y) / 2} fill="#58a6ff" fontSize="10" fontFamily="monospace">
                  802.1Q 10G Trunk
                </text>
              </g>
            );
          })()}

          {/* Links: Core Switch -> Other Devices */}
          {(() => {
            const sw = devices.find(d => d.deviceType === 'switch' && d.id.includes('core'));
            if (!sw) return null;
            const pSw = nodePositions.get(sw.id);
            if (!pSw) return null;

            return filteredDevices.map(dev => {
              if (dev.id === sw.id || dev.deviceType === 'firewall' || dev.deviceType === 'gateway') return null;
              const pDev = nodePositions.get(dev.id);
              if (!pDev) return null;

              const isSelected = selectedDevice?.id === dev.id;
              const vlanColor = pDev.vlanColor || '#30363d';

              return (
                <g key={`link-${dev.id}`}>
                  <line
                    x1={pSw.x}
                    y1={pSw.y}
                    x2={pDev.x}
                    y2={pDev.y}
                    stroke={isSelected ? '#da3633' : vlanColor}
                    strokeWidth={isSelected ? '2.5' : '1.2'}
                    strokeOpacity={isSelected ? 0.9 : 0.4}
                  />
                </g>
              );
            });
          })()}

          {/* VLAN Cluster Background Rings */}
          {layoutMode === 'vlan-clusters' && filterVlan === 'all' && vlans.map((v, i) => {
            const activeCount = filteredDevices.filter(d => d.vlanId === v.id).length;
            if (activeCount === 0) return null;
            const vlanCount = vlans.length;
            const spacingX = 900 / (vlanCount + 1);
            const cx = 100 + (i + 1) * spacingX;
            const cy = 380;

            return (
              <g key={`vlan-bg-${v.id}`} opacity="0.35">
                <circle
                  cx={cx}
                  cy={cy}
                  r="135"
                  fill="none"
                  stroke={v.color}
                  strokeWidth="1.5"
                  strokeDasharray="6 4"
                />
                <text
                  x={cx}
                  y={cy - 145}
                  textAnchor="middle"
                  fill={v.color}
                  fontSize="11"
                  fontWeight="600"
                  fontFamily="sans-serif"
                >
                  VLAN {v.id}: {v.name} ({v.subnet})
                </text>
              </g>
            );
          })}
        </svg>

        {/* HTML Rendered Device Nodes */}
        <div
          className="absolute inset-0 pointer-events-none"
          style={{
            transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
            transformOrigin: '500px 300px',
            transition: isDragging ? 'none' : 'transform 0.1s ease-out'
          }}
        >
          {filteredDevices.map(device => {
            const pos = nodePositions.get(device.id);
            if (!pos) return null;

            const isSelected = selectedDevice?.id === device.id;
            const hasRisks = device.riskScore === 'High' || device.riskScore === 'Critical';

            return (
              <div
                key={device.id}
                onClick={(e) => {
                  e.stopPropagation();
                  onSelectDevice(device);
                }}
                className={`absolute pointer-events-auto transform -translate-x-1/2 -translate-y-1/2 cursor-pointer transition-all duration-200 ${
                  isSelected ? 'scale-115 z-30' : 'hover:scale-105 z-20'
                }`}
                style={{
                  left: `${pos.x}px`,
                  top: `${pos.y}px`,
                }}
              >
                <div 
                  className={`flex flex-col items-center p-2 rounded border transition-colors ${
                    isSelected 
                      ? 'bg-[#161b22] border-[#58a6ff] ring-2 ring-[#58a6ff]/40 shadow-lg' 
                      : 'bg-[#161b22] border-[#30363d] hover:border-[#8b949e]'
                  }`}
                  style={{
                    borderTopColor: pos.vlanColor,
                    borderTopWidth: '3px'
                  }}
                >
                  {/* Icon + Status Badge */}
                  <div className="relative">
                    <div 
                      className="w-8 h-8 rounded flex items-center justify-center"
                      style={{ backgroundColor: `${pos.vlanColor}20`, color: pos.vlanColor }}
                    >
                      {getDeviceIcon(device.deviceType)}
                    </div>

                    {/* Risk / Health Indicator */}
                    {hasRisks ? (
                      <span className="absolute -top-1 -right-1 w-3.5 h-3.5 bg-[#da3633] rounded-full flex items-center justify-center text-white text-[9px] font-bold ring-2 ring-[#161b22]">
                        !
                      </span>
                    ) : (
                      <span className="absolute -bottom-0.5 -right-0.5 w-2 h-2 bg-[#238636] rounded-full ring-2 ring-[#161b22]" />
                    )}
                  </div>

                  {/* Device Info */}
                  <span className="text-[11px] font-semibold text-[#f0f6fc] mt-1 max-w-[110px] truncate text-center">
                    {device.hostname || device.ip}
                  </span>
                  <span className="text-[10px] font-mono text-[#58a6ff]">
                    {device.ip}
                  </span>
                  
                  {/* Small tag badge */}
                  <div className="flex items-center gap-1 mt-1">
                    <span 
                      className="text-[9px] px-1.5 py-0.2 rounded font-mono font-medium"
                      style={{ backgroundColor: `${pos.vlanColor}25`, color: pos.vlanColor }}
                    >
                      VLAN {device.vlanId}
                    </span>
                    <span className="text-[9px] px-1 py-0.2 rounded bg-[#010409] text-[#8b949e] border border-[#30363d]">
                      {device.osFingerprint.family.slice(0, 5)}
                    </span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Legend Footer */}
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-2 bg-[#161b22] border-t border-[#30363d] text-[11px] text-[#8b949e]">
        <div className="flex items-center gap-4 flex-wrap">
          <span className="font-semibold text-[#c9d1d9]">VLAN Map:</span>
          {vlans.map(v => (
            <div key={v.id} className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: v.color }} />
              <span className="text-[#c9d1d9]">VLAN {v.id} ({v.name.split('/')[0].trim()})</span>
            </div>
          ))}
        </div>

        <div className="flex items-center gap-3 font-medium">
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-[#238636]" /> Normal
          </span>
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-[#da3633]" /> Hygiene Alert
          </span>
        </div>
      </div>
    </div>
  );
};
