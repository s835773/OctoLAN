import React, { useState, useRef, useMemo } from 'react';
import { NetworkDevice, VlanInfo } from '../types';
import { MobileVlanClusters } from './MobileVlanClusters';
import { NetworkTreeView } from './NetworkTreeView';
import { 
  Server, Laptop, Shield, Wifi, Printer, Radio, 
  Layers, HardDrive, Smartphone, AlertTriangle, CheckCircle2,
  ZoomIn, ZoomOut, RotateCcw, Filter, Search, LayoutGrid, Network,
  FolderTree, GitFork, X, ChevronDown, ChevronUp, Minimize2, Maximize2
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
  const [zoom, setZoom] = useState(0.85);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [searchQuery, setSearchQuery] = useState('');
  const [layoutMode, setLayoutMode] = useState<'vlan-clusters' | 'hierarchical'>('vlan-clusters');
  const [viewMode, setViewMode] = useState<'cards' | 'tree' | 'graph'>('graph');
  const [isControlsCollapsed, setIsControlsCollapsed] = useState(false);
  const [cardDensity, setCardDensity] = useState<'detailed' | 'compact'>('detailed');
  const [collapsedVlans, setCollapsedVlans] = useState<Record<number, boolean>>({});

  const containerRef = useRef<HTMLDivElement>(null);

  const toggleVlanCollapse = (vlanId: number) => {
    setCollapsedVlans(prev => ({
      ...prev,
      [vlanId]: !prev[vlanId]
    }));
  };

  const collapseAllVlans = () => {
    const next: Record<number, boolean> = {};
    vlans.forEach(v => { next[v.id] = true; });
    setCollapsedVlans(next);
  };

  const expandAllVlans = () => {
    setCollapsedVlans({});
  };

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

  // Compute layout coordinates for nodes with generous spacing and multi-row distribution
  const { nodePositions, clusterMeta } = useMemo(() => {
    const posMap = new Map<string, { x: number; y: number; vlanColor: string; isCollapsed?: boolean }>();
    const clusters: Array<{ id: number; name: string; subnet: string; color: string; cx: number; cy: number; count: number; isCollapsed: boolean }> = [];
    
    // Core gateway & switch at the top center with ample breathing room
    const gateway = devices.find(d => d.deviceType === 'firewall' || d.deviceType === 'gateway');
    const coreSwitch = devices.find(d => d.deviceType === 'switch' && d.id.includes('core'));

    const canvasCenterX = 650;
    if (gateway) {
      posMap.set(gateway.id, { x: canvasCenterX, y: 70, vlanColor: '#6366f1' });
    }
    if (coreSwitch) {
      posMap.set(coreSwitch.id, { x: canvasCenterX, y: 175, vlanColor: '#6366f1' });
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

      // Distribute clusters across 1 or 2 rows for spacious padding
      activeVlans.forEach((vlan, vIndex) => {
        let clusterCenterX: number;
        let clusterCenterY: number;

        if (activeVlans.length <= 3) {
          const spacingX = 1000 / (activeVlans.length + 1);
          clusterCenterX = 150 + (vIndex + 1) * spacingX;
          clusterCenterY = 420;
        } else {
          // Multi-row staggered layout to prevent clustering collisions
          if (vIndex < 3) {
            // Row 1 (3 clusters)
            clusterCenterX = 230 + vIndex * 420;
            clusterCenterY = 380;
          } else {
            // Row 2 (remaining clusters)
            const row2Index = vIndex - 3;
            clusterCenterX = 440 + row2Index * 420;
            clusterCenterY = 660;
          }
        }

        const vDevices = vlanGroups.get(vlan.id) || [];
        const isClusterCollapsed = !!collapsedVlans[vlan.id];

        clusters.push({
          id: vlan.id,
          name: vlan.name,
          subnet: vlan.subnet,
          color: vlan.color,
          cx: clusterCenterX,
          cy: clusterCenterY,
          count: vDevices.length,
          isCollapsed: isClusterCollapsed
        });

        if (isClusterCollapsed) {
          // Put devices hidden or at the center
          vDevices.forEach(dev => {
            posMap.set(dev.id, { x: clusterCenterX, y: clusterCenterY, vlanColor: vlan.color, isCollapsed: true });
          });
        } else {
          vDevices.forEach((dev, dIndex) => {
            if (vDevices.length === 1) {
              posMap.set(dev.id, { x: clusterCenterX, y: clusterCenterY, vlanColor: vlan.color, isCollapsed: false });
            } else if (vDevices.length === 2) {
              const x = clusterCenterX + (dIndex === 0 ? -70 : 70);
              posMap.set(dev.id, { x, y: clusterCenterY, vlanColor: vlan.color, isCollapsed: false });
            } else {
              // Circle layout with generous radius
              const angle = (dIndex / vDevices.length) * 2 * Math.PI - Math.PI / 2;
              const radius = 120;
              const x = clusterCenterX + Math.cos(angle) * radius;
              const y = clusterCenterY + Math.sin(angle) * radius;
              posMap.set(dev.id, { x, y, vlanColor: vlan.color, isCollapsed: false });
            }
          });
        }
      });
    } else {
      // Hierarchical layout with clean vertical separation
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
        const step = 1000 / (devs.length + 1);
        devs.forEach((d, i) => {
          const vColor = vlans.find(v => v.id === d.vlanId)?.color || '#64748b';
          posMap.set(d.id, { x: 150 + (i + 1) * step, y, vlanColor: vColor, isCollapsed: false });
        });
      };

      assignRow(layers.switches, 290);
      assignRow(layers.servers, 430);
      assignRow(layers.clients, 570);
      assignRow(layers.iot, 710);
    }

    return { nodePositions: posMap, clusterMeta: clusters };
  }, [devices, filteredDevices, vlans, layoutMode, collapsedVlans]);

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

  const getDeviceIcon = (type: NetworkDevice['deviceType'], isCompact: boolean) => {
    const size = isCompact ? 'w-3.5 h-3.5' : 'w-4 h-4';
    switch (type) {
      case 'firewall':
      case 'gateway': return <Shield className={size} />;
      case 'switch': return <Layers className={size} />;
      case 'access_point': return <Wifi className={size} />;
      case 'server': return <Server className={size} />;
      case 'workstation': return <Laptop className={size} />;
      case 'mobile': return <Smartphone className={size} />;
      case 'printer': return <Printer className={size} />;
      case 'iot': return <Radio className={size} />;
      default: return <HardDrive className={size} />;
    }
  };

  return (
    <div className="space-y-3">
      {/* Unified Search, Filter & Layout View Card (Collapsible) */}
      <div className="bg-[#161b22] border border-[#30363d] rounded-lg shadow-sm overflow-hidden transition-all duration-200">
        {/* Top Control Bar Header */}
        <div className="p-3 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2 flex-1 min-w-[260px]">
            <div className="relative flex-1 max-w-md">
              <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-[#8b949e]" />
              <input
                type="text"
                placeholder="Quick search IP, hostname, MAC address, vendor, OS..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-9 pr-8 py-1.5 bg-[#010409] border border-[#30363d] rounded text-xs text-[#c9d1d9] placeholder-[#8b949e] focus:outline-none focus:border-[#58a6ff]"
              />
              {searchQuery && (
                <button
                  onClick={() => setSearchQuery('')}
                  className="absolute right-2.5 top-2 text-[#8b949e] hover:text-[#c9d1d9]"
                  title="Clear search"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            {/* VLAN Filter Dropdown */}
            <div className="flex items-center gap-1.5">
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

          {/* Results Counter & Collapse Toggle */}
          <div className="flex items-center gap-2 text-xs">
            <span className="font-mono text-[11px] px-2.5 py-1 rounded bg-[#010409] border border-[#30363d] text-[#8b949e]">
              <span className="text-[#58a6ff] font-semibold">{filteredDevices.length}</span> / {devices.length} endpoints
            </span>
            {(searchQuery !== '' || filterVlan !== 'all') && (
              <button
                onClick={() => {
                  setSearchQuery('');
                  onFilterVlanChange('all');
                }}
                className="px-2 py-1 text-[11px] text-[#58a6ff] hover:underline"
              >
                Reset Filters
              </button>
            )}

            {/* Minimize / Expand Top Card */}
            <button
              onClick={() => setIsControlsCollapsed(!isControlsCollapsed)}
              className="p-1.5 text-[#8b949e] hover:text-[#c9d1d9] rounded border border-[#30363d] bg-[#010409] hover:bg-[#21262d] transition"
              title={isControlsCollapsed ? "Expand Toolbar" : "Collapse Toolbar"}
            >
              {isControlsCollapsed ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronUp className="w-3.5 h-3.5" />}
            </button>
          </div>
        </div>

        {/* Expandable Lower Toolbar: Layout Selector & Graph Density Options */}
        {!isControlsCollapsed && (
          <div className="px-3 pb-3 pt-2.5 border-t border-[#21262d] flex flex-wrap items-center justify-between gap-3 bg-[#13171e]">
            <div className="flex items-center gap-2">
              <span className="text-xs text-[#8b949e] font-medium">Layout View:</span>
              <div className="flex bg-[#010409] p-0.5 rounded border border-[#30363d] text-xs">
                <button
                  onClick={() => setViewMode('cards')}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded transition font-medium ${
                    viewMode === 'cards'
                      ? 'bg-[#21262d] text-[#58a6ff] border border-[#30363d] shadow-sm'
                      : 'text-[#8b949e] hover:text-[#c9d1d9]'
                  }`}
                >
                  <LayoutGrid className="w-3.5 h-3.5" />
                  <span>Card View</span>
                </button>

                <button
                  onClick={() => setViewMode('tree')}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded transition font-medium ${
                    viewMode === 'tree'
                      ? 'bg-[#21262d] text-[#58a6ff] border border-[#30363d] shadow-sm'
                      : 'text-[#8b949e] hover:text-[#c9d1d9]'
                  }`}
                >
                  <FolderTree className="w-3.5 h-3.5" />
                  <span>Tree View</span>
                </button>

                <button
                  onClick={() => setViewMode('graph')}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded transition font-medium ${
                    viewMode === 'graph'
                      ? 'bg-[#21262d] text-[#58a6ff] border border-[#30363d] shadow-sm'
                      : 'text-[#8b949e] hover:text-[#c9d1d9]'
                  }`}
                >
                  <Network className="w-3.5 h-3.5" />
                  <span>2D Graph View</span>
                </button>
              </div>
            </div>

            {/* View-specific controls */}
            {viewMode === 'graph' && (
              <div className="flex flex-wrap items-center gap-2">
                {/* Node Density Mode */}
                <div className="flex items-center bg-[#010409] p-0.5 rounded border border-[#30363d] text-xs">
                  <span className="text-[11px] text-[#8b949e] px-2 py-0.5">Cards:</span>
                  <button
                    onClick={() => setCardDensity('detailed')}
                    className={`px-2 py-0.5 rounded transition ${cardDensity === 'detailed' ? 'bg-[#21262d] text-[#58a6ff] font-medium border border-[#30363d]' : 'text-[#8b949e] hover:text-[#c9d1d9]'}`}
                    title="Detailed cards with hostname, IP, OS and tags"
                  >
                    Detailed
                  </button>
                  <button
                    onClick={() => setCardDensity('compact')}
                    className={`px-2 py-0.5 rounded transition ${cardDensity === 'compact' ? 'bg-[#21262d] text-[#58a6ff] font-medium border border-[#30363d]' : 'text-[#8b949e] hover:text-[#c9d1d9]'}`}
                    title="Compact un-cluttered circular node icons"
                  >
                    Compact
                  </button>
                </div>

                {/* Graph Layout Mode */}
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

                {/* Cluster Expand/Collapse All */}
                {layoutMode === 'vlan-clusters' && (
                  <div className="flex items-center gap-1 bg-[#010409] p-0.5 rounded border border-[#30363d] text-xs">
                    <button
                      onClick={collapseAllVlans}
                      className="px-2 py-0.5 text-[11px] text-[#8b949e] hover:text-[#c9d1d9] rounded hover:bg-[#21262d]"
                      title="Collapse all clusters into summary hubs"
                    >
                      Collapse All
                    </button>
                    <span className="text-[#30363d]">|</span>
                    <button
                      onClick={expandAllVlans}
                      className="px-2 py-0.5 text-[11px] text-[#8b949e] hover:text-[#c9d1d9] rounded hover:bg-[#21262d]"
                      title="Expand all clusters"
                    >
                      Expand All
                    </button>
                  </div>
                )}

                {/* Zoom & Pan Controls */}
                <div className="flex items-center bg-[#010409] rounded border border-[#30363d] p-0.5">
                  <button
                    onClick={() => setZoom(z => Math.min(1.8, z + 0.15))}
                    className="p-1.5 text-[#8b949e] hover:text-[#c9d1d9] rounded"
                    title="Zoom In"
                  >
                    <ZoomIn className="w-3.5 h-3.5" />
                  </button>
                  <button
                    onClick={() => setZoom(z => Math.max(0.4, z - 0.15))}
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
            )}
          </div>
        )}
      </div>

      {/* VIEW 1: Card View */}
      {viewMode === 'cards' && (
        <MobileVlanClusters
          vlans={vlans}
          devices={devices}
          selectedDevice={selectedDevice}
          onSelectDevice={onSelectDevice}
          filterVlan={filterVlan}
          onFilterVlanChange={onFilterVlanChange}
          searchQuery={searchQuery}
          hideEmbeddedSearch={true}
        />
      )}

      {/* VIEW 2: Tree View */}
      {viewMode === 'tree' && (
        <NetworkTreeView
          devices={devices}
          vlans={vlans}
          selectedDevice={selectedDevice}
          onSelectDevice={onSelectDevice}
          filterVlan={filterVlan}
          onFilterVlanChange={onFilterVlanChange}
          searchQuery={searchQuery}
          hideEmbeddedSearch={true}
        />
      )}

      {/* VIEW 3: 2D Canvas Graph View */}
      {viewMode === 'graph' && (
        <div className="flex relative w-full h-[700px] bg-[#0d1117] border border-[#30363d] rounded-md overflow-hidden flex-col select-none">
          {/* Main Canvas / SVG Interactive Area */}
          <div 
            ref={containerRef}
            onMouseDown={handleMouseDown}
            onMouseMove={handleMouseMove}
            onMouseUp={handleMouseUp}
            className="flex-1 w-full h-full relative cursor-grab active:cursor-grabbing overflow-hidden bg-[#0d1117] bg-[radial-gradient(#21262d_1px,transparent_1px)] [background-size:24px_24px]"
          >
            {/* Unified 2D World Board (1:1 lockstep between SVG and HTML coordinates) */}
            <div
              className="absolute pointer-events-none"
              style={{
                width: '1300px',
                height: '820px',
                left: '50%',
                top: '50%',
                transform: `translate(calc(-50% + ${pan.x}px), calc(-50% + ${pan.y}px)) scale(${zoom})`,
                transformOrigin: '650px 410px',
                transition: isDragging ? 'none' : 'transform 0.1s ease-out'
              }}
            >
              {/* SVG Wireframe Layer */}
              <svg 
                width="1300"
                height="820"
                className="w-full h-full absolute inset-0 pointer-events-none"
                viewBox="0 0 1300 820"
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
                    <text x={(p1.x + p2.x) / 2 + 12} y={(p1.y + p2.y) / 2} fill="#58a6ff" fontSize="10" fontFamily="monospace">
                      802.1Q 10G Trunk
                    </text>
                  </g>
                );
              })()}

              {/* Links: Core Switch -> Devices / Clusters */}
              {(() => {
                const sw = devices.find(d => d.deviceType === 'switch' && d.id.includes('core'));
                if (!sw) return null;
                const pSw = nodePositions.get(sw.id);
                if (!pSw) return null;

                if (layoutMode === 'vlan-clusters') {
                  // For collapsed clusters, draw one link to cluster center
                  return clusterMeta.map(cluster => {
                    if (cluster.isCollapsed) {
                      return (
                        <g key={`cluster-link-${cluster.id}`}>
                          <line
                            x1={pSw.x}
                            y1={pSw.y}
                            x2={cluster.cx}
                            y2={cluster.cy}
                            stroke={cluster.color}
                            strokeWidth="2"
                            strokeDasharray="3 3"
                            strokeOpacity={0.6}
                          />
                        </g>
                      );
                    }

                    // Otherwise draw links to active expanded devices
                    const clusterDevices = filteredDevices.filter(d => d.vlanId === cluster.id);
                    return clusterDevices.map(dev => {
                      if (dev.id === sw.id || dev.deviceType === 'firewall' || dev.deviceType === 'gateway') return null;
                      const pDev = nodePositions.get(dev.id);
                      if (!pDev || pDev.isCollapsed) return null;

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
                            strokeOpacity={isSelected ? 0.9 : 0.35}
                          />
                        </g>
                      );
                    });
                  });
                } else {
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
                          strokeOpacity={isSelected ? 0.9 : 0.35}
                        />
                      </g>
                    );
                  });
                }
              })()}

              {/* VLAN Cluster Background Rings with Clickable SVG area */}
              {layoutMode === 'vlan-clusters' && filterVlan === 'all' && clusterMeta.map(cluster => {
                const { cx, cy, color, id, name, subnet, isCollapsed, count } = cluster;

                if (isCollapsed) {
                  return (
                    <g key={`vlan-bg-${id}`} opacity="0.85">
                      <circle
                        cx={cx}
                        cy={cy}
                        r="45"
                        fill={`${color}12`}
                        stroke={color}
                        strokeWidth="1.5"
                        strokeDasharray="4 2"
                      />
                    </g>
                  );
                }

                return (
                  <g key={`vlan-bg-${id}`} opacity="0.85">
                    <circle
                      cx={cx}
                      cy={cy}
                      r="145"
                      fill={`${color}08`}
                      stroke={color}
                      strokeWidth="1.5"
                      strokeDasharray="6 4"
                      strokeOpacity="0.4"
                    />
                    <text
                      x={cx}
                      y={cy - 155}
                      textAnchor="middle"
                      fill={color}
                      fontSize="12"
                      fontWeight="600"
                      fontFamily="sans-serif"
                    >
                      VLAN {id}: {name} ({subnet})
                    </text>
                  </g>
                );
              })}
            </svg>

            {/* HTML Rendered Device Nodes & Interactive Collapsible Cluster Hubs */}
            <div className="w-full h-full absolute inset-0 pointer-events-none">
              {/* Collapsed Cluster Hub Nodes (When a VLAN is collapsed) */}
              {layoutMode === 'vlan-clusters' && clusterMeta.map(cluster => {
                if (!cluster.isCollapsed) {
                  // Render a small collapse toggle pill at top of cluster circle
                  return (
                    <div
                      key={`toggle-${cluster.id}`}
                      className="absolute pointer-events-auto transform -translate-x-1/2 -translate-y-1/2 z-20"
                      style={{ left: `${cluster.cx}px`, top: `${cluster.cy + 155}px` }}
                    >
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          toggleVlanCollapse(cluster.id);
                        }}
                        className="px-2 py-0.5 rounded-full text-[10px] font-medium bg-[#161b22] border border-[#30363d] hover:border-[#58a6ff] text-[#8b949e] hover:text-[#58a6ff] shadow-sm flex items-center gap-1 transition"
                        title="Collapse this VLAN cluster"
                      >
                        <Minimize2 className="w-2.5 h-2.5" />
                        <span>Collapse VLAN {cluster.id}</span>
                      </button>
                    </div>
                  );
                }

                // Render Collapsed Summary Capsule
                return (
                  <div
                    key={`collapsed-hub-${cluster.id}`}
                    onClick={() => toggleVlanCollapse(cluster.id)}
                    className="absolute pointer-events-auto transform -translate-x-1/2 -translate-y-1/2 cursor-pointer z-30 group"
                    style={{ left: `${cluster.cx}px`, top: `${cluster.cy}px` }}
                  >
                    <div 
                      className="flex flex-col items-center justify-center p-2 rounded-lg bg-[#161b22] border hover:border-[#58a6ff] transition shadow-md w-36 text-center"
                      style={{ borderColor: cluster.color, borderTopWidth: '3px' }}
                    >
                      <div 
                        className="w-7 h-7 rounded-full flex items-center justify-center mb-1"
                        style={{ backgroundColor: `${cluster.color}25`, color: cluster.color }}
                      >
                        <Layers className="w-3.5 h-3.5" />
                      </div>
                      <span className="text-[11px] font-semibold text-[#f0f6fc]">
                        VLAN {cluster.id}
                      </span>
                      <span className="text-[10px] text-[#8b949e]">
                        {cluster.count} {cluster.count === 1 ? 'Device' : 'Devices'}
                      </span>
                      <span className="text-[9px] text-[#58a6ff] mt-0.5 group-hover:underline flex items-center gap-0.5">
                        <Maximize2 className="w-2.5 h-2.5" /> Click to Expand
                      </span>
                    </div>
                  </div>
                );
              })}

              {/* Standard Device Nodes */}
              {filteredDevices.map(device => {
                const pos = nodePositions.get(device.id);
                if (!pos || pos.isCollapsed) return null;

                const isSelected = selectedDevice?.id === device.id;
                const hasRisks = device.riskScore === 'High' || device.riskScore === 'Critical';
                const isGatewayOrSwitch = device.deviceType === 'firewall' || device.deviceType === 'gateway' || (device.deviceType === 'switch' && device.id.includes('core'));

                if (cardDensity === 'compact' && !isGatewayOrSwitch) {
                  // COMPACT NODE VIEW (Sleek circular icon with mini tag)
                  return (
                    <div
                      key={device.id}
                      onClick={(e) => {
                        e.stopPropagation();
                        onSelectDevice(device);
                      }}
                      className={`absolute pointer-events-auto transform -translate-x-1/2 -translate-y-1/2 cursor-pointer transition-all duration-200 ${
                        isSelected ? 'scale-125 z-40' : 'hover:scale-110 z-20'
                      }`}
                      style={{
                        left: `${pos.x}px`,
                        top: `${pos.y}px`,
                      }}
                    >
                      <div className="flex flex-col items-center group">
                        <div 
                          className={`w-10 h-10 rounded-full flex items-center justify-center border-2 transition-all relative ${
                            isSelected 
                              ? 'bg-[#161b22] border-[#58a6ff] ring-2 ring-[#58a6ff]/40 shadow-lg' 
                              : 'bg-[#161b22] border-[#30363d] hover:border-[#8b949e]'
                          }`}
                          style={{
                            borderColor: isSelected ? '#58a6ff' : pos.vlanColor,
                            color: pos.vlanColor
                          }}
                        >
                          {getDeviceIcon(device.deviceType, true)}

                          {hasRisks ? (
                            <span className="absolute -top-1 -right-1 w-3 h-3 bg-[#da3633] rounded-full flex items-center justify-center text-white text-[8px] font-bold ring-2 ring-[#161b22]">
                              !
                            </span>
                          ) : (
                            <span className="absolute -bottom-0.5 -right-0.5 w-2 h-2 bg-[#238636] rounded-full ring-2 ring-[#161b22]" />
                          )}
                        </div>

                        {/* Compact Label */}
                        <div className="mt-1 px-1.5 py-0.5 rounded bg-[#010409]/90 border border-[#30363d] text-[10px] font-mono text-[#c9d1d9] group-hover:text-[#58a6ff] whitespace-nowrap shadow-sm">
                          {device.ip.split('.').slice(-2).join('.')} • {device.hostname.split('.')[0] || device.ip}
                        </div>
                      </div>
                    </div>
                  );
                }

                // DETAILED NODE CARD VIEW
                return (
                  <div
                    key={device.id}
                    onClick={(e) => {
                      e.stopPropagation();
                      onSelectDevice(device);
                    }}
                    className={`absolute pointer-events-auto transform -translate-x-1/2 -translate-y-1/2 cursor-pointer transition-all duration-200 ${
                      isSelected ? 'scale-110 z-30' : 'hover:scale-105 z-20'
                    }`}
                    style={{
                      left: `${pos.x}px`,
                      top: `${pos.y}px`,
                    }}
                  >
                    <div 
                      className={`flex flex-col items-center p-2.5 rounded-lg border transition-colors shadow-sm min-w-[110px] max-w-[125px] ${
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
                          className="w-8 h-8 rounded-md flex items-center justify-center"
                          style={{ backgroundColor: `${pos.vlanColor}20`, color: pos.vlanColor }}
                        >
                          {getDeviceIcon(device.deviceType, false)}
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
                      <span className="text-[11px] font-semibold text-[#f0f6fc] mt-1 max-w-[110px] truncate text-center" title={device.hostname}>
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
            {/* End Unified 2D World Board */}
            </div>
          </div>

          {/* Legend Footer */}
          <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-2 bg-[#161b22] border-t border-[#30363d] text-[11px] text-[#8b949e]">
            <div className="flex items-center gap-4 flex-wrap">
              <span className="font-semibold text-[#c9d1d9]">VLAN Map:</span>
              {vlans.map(v => {
                const isCollapsed = !!collapsedVlans[v.id];
                return (
                  <button
                    key={v.id}
                    onClick={() => toggleVlanCollapse(v.id)}
                    className="flex items-center gap-1.5 hover:text-[#58a6ff] transition"
                    title={isCollapsed ? `Click to expand VLAN ${v.id}` : `Click to collapse VLAN ${v.id}`}
                  >
                    <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: v.color }} />
                    <span className={`text-[#c9d1d9] ${isCollapsed ? 'line-through opacity-60' : ''}`}>
                      VLAN {v.id} ({v.name.split('/')[0].trim()})
                    </span>
                  </button>
                );
              })}
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
      )}
    </div>
  );
};

