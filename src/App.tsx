import React, { useState } from 'react';
import { NetworkDevice, VlanInfo } from './types';
import { INITIAL_DEVICES, INITIAL_VLANS } from './data/sampleNetwork';
import { TopologyGraph } from './components/TopologyGraph';
import { DeviceDrawer } from './components/DeviceDrawer';
import { ScannerModal } from './components/ScannerModal';
import { ProtocolAuditor } from './components/ProtocolAuditor';
import { VlanInspector } from './components/VlanInspector';
import { CodeLabView } from './components/CodeLabView';
import { AuditKnowledgeView } from './components/AuditKnowledgeView';
import { AiAdvisor } from './components/AiAdvisor';
import { NetflowAnalyzer } from './components/NetflowAnalyzer';
import { StormDetector } from './components/StormDetector';
import { AlertsManager } from './components/AlertsManager';
import { OctoMascot } from './components/OctoMascot';
import { 
  Network, Server, Layers, Activity, FileCode, 
  BookOpen, Sparkles, Radio, Shield, Search, 
  Filter, Plus, RefreshCw, Smartphone, Laptop, Download, Info,
  Zap, Bell, Eye
} from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState<
    'topology' | 'devices' | 'vlans' | 'netflow' | 'storms' | 'alerts' | 'protocols' | 'code-lab' | 'knowledge' | 'advisor'
  >('topology');
  const [devices, setDevices] = useState<NetworkDevice[]>(INITIAL_DEVICES);
  const [vlans, setVlans] = useState<VlanInfo[]>(INITIAL_VLANS);
  const [selectedDevice, setSelectedDevice] = useState<NetworkDevice | null>(null);
  const [filterVlan, setFilterVlan] = useState<number | 'all'>('all');
  const [isScannerOpen, setIsScannerOpen] = useState(false);
  const [deviceSearch, setDeviceSearch] = useState('');

  const handleScanComplete = (scannedDevices: NetworkDevice[]) => {
    setDevices(scannedDevices);
  };

  const filteredDevices = devices.filter(d => {
    const matchesVlan = filterVlan === 'all' || d.vlanId === filterVlan;
    const matchesSearch = deviceSearch === '' ||
      d.ip.toLowerCase().includes(deviceSearch.toLowerCase()) ||
      d.hostname.toLowerCase().includes(deviceSearch.toLowerCase()) ||
      d.mac.toLowerCase().includes(deviceSearch.toLowerCase()) ||
      d.vendor.toLowerCase().includes(deviceSearch.toLowerCase()) ||
      d.osFingerprint.name.toLowerCase().includes(deviceSearch.toLowerCase());
    return matchesVlan && matchesSearch;
  });

  const getVlanForDevice = (device: NetworkDevice | null) => {
    if (!device) return undefined;
    return vlans.find(v => v.id === device.vlanId);
  };

  return (
    <div className="min-h-screen bg-[#0d1117] text-[#c9d1d9] flex flex-col font-sans selection:bg-[#58a6ff]/30 selection:text-white">
      {/* Top Navigation Bar */}
      <header className="bg-[#161b22] border-b border-[#30363d] sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-14 flex items-center justify-between gap-3">
          {/* Brand Logo & Title (Home Navigation) */}
          <button
            type="button"
            onClick={() => {
              setActiveTab('topology');
              setSelectedDevice(null);
              setFilterVlan('all');
              setDeviceSearch('');
            }}
            className="flex items-center gap-3 text-left group focus:outline-none cursor-pointer"
            title="OctoLAN Home - Return to Topology Dashboard"
          >
            <OctoMascot 
              size={34} 
              variant="badge" 
              onClick={() => {
                setActiveTab('topology');
                setSelectedDevice(null);
                setFilterVlan('all');
                setDeviceSearch('');
              }}
            />
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-sm font-bold tracking-tight text-[#f0f6fc] sm:text-base group-hover:text-[#58a6ff] transition">
                  OctoLAN
                </h1>
                <span className="text-xs text-[#8b949e] font-mono">
                  v2.0-telemetry
                </span>
                <span className="hidden sm:inline-block px-1.5 py-0.5 rounded text-[10px] font-mono font-medium bg-[#010409] text-[#7ee787] border border-[#30363d] group-hover:border-[#58a6ff]/50 transition">
                  POSIX / NetFlow / Storm Guard
                </span>
              </div>
            </div>
          </button>

          {/* Quick Actions & Status Badges */}
          <div className="flex items-center gap-2.5">
            <div className="hidden md:flex items-center gap-2 text-xs text-[#8b949e] bg-[#010409] px-2.5 py-1 rounded border border-[#30363d]">
              <span>Sensor:</span>
              <span className="text-[#58a6ff] font-mono font-semibold">eth0 (Promisc)</span>
            </div>

            <div className="hidden lg:flex items-center gap-2 text-xs text-[#8b949e] bg-[#010409] px-2.5 py-1 rounded border border-[#30363d]">
              <span>Flow Port:</span>
              <span className="text-[#7ee787] font-mono font-semibold">UDP:2055</span>
            </div>

            <button
              onClick={() => setIsScannerOpen(true)}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded bg-[#238636] hover:bg-[#2ea043] text-white text-xs font-semibold shadow-sm transition active:scale-95"
            >
              <Radio className="w-3.5 h-3.5" />
              <span>Execute Scan</span>
            </button>
          </div>
        </div>

        {/* Desktop Tab Bar */}
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex space-x-1 overflow-x-auto no-scrollbar border-t border-[#21262d]">
          <button
            onClick={() => setActiveTab('topology')}
            className={`flex items-center gap-2 px-3.5 py-2.5 text-xs font-medium transition whitespace-nowrap border-b-2 ${
              activeTab === 'topology'
                ? 'border-[#58a6ff] text-[#58a6ff] bg-[#161b22]'
                : 'border-transparent text-[#8b949e] hover:text-[#c9d1d9] hover:bg-[#161b22]/50'
            }`}
          >
            <Network className="w-3.5 h-3.5" /> Topology Map
          </button>

          <button
            onClick={() => setActiveTab('devices')}
            className={`flex items-center gap-2 px-3.5 py-2.5 text-xs font-medium transition whitespace-nowrap border-b-2 ${
              activeTab === 'devices'
                ? 'border-[#58a6ff] text-[#58a6ff] bg-[#161b22]'
                : 'border-transparent text-[#8b949e] hover:text-[#c9d1d9] hover:bg-[#161b22]/50'
            }`}
          >
            <Server className="w-3.5 h-3.5" /> Active Discovery ({devices.length})
          </button>

          <button
            onClick={() => setActiveTab('vlans')}
            className={`flex items-center gap-2 px-3.5 py-2.5 text-xs font-medium transition whitespace-nowrap border-b-2 ${
              activeTab === 'vlans'
                ? 'border-[#58a6ff] text-[#58a6ff] bg-[#161b22]'
                : 'border-transparent text-[#8b949e] hover:text-[#c9d1d9] hover:bg-[#161b22]/50'
            }`}
          >
            <Layers className="w-3.5 h-3.5" /> VLAN Map ({vlans.length})
          </button>

          <button
            onClick={() => setActiveTab('netflow')}
            className={`flex items-center gap-2 px-3.5 py-2.5 text-xs font-medium transition whitespace-nowrap border-b-2 ${
              activeTab === 'netflow'
                ? 'border-[#58a6ff] text-[#58a6ff] bg-[#161b22]'
                : 'border-transparent text-[#8b949e] hover:text-[#c9d1d9] hover:bg-[#161b22]/50'
            }`}
          >
            <Activity className="w-3.5 h-3.5 text-[#58a6ff]" /> NetFlow Telemetry
          </button>

          <button
            onClick={() => setActiveTab('storms')}
            className={`flex items-center gap-2 px-3.5 py-2.5 text-xs font-medium transition whitespace-nowrap border-b-2 ${
              activeTab === 'storms'
                ? 'border-[#58a6ff] text-[#58a6ff] bg-[#161b22]'
                : 'border-transparent text-[#8b949e] hover:text-[#c9d1d9] hover:bg-[#161b22]/50'
            }`}
          >
            <Zap className="w-3.5 h-3.5 text-[#da3633]" /> Storm Watchdog
          </button>

          <button
            onClick={() => setActiveTab('alerts')}
            className={`flex items-center gap-2 px-3.5 py-2.5 text-xs font-medium transition whitespace-nowrap border-b-2 ${
              activeTab === 'alerts'
                ? 'border-[#58a6ff] text-[#58a6ff] bg-[#161b22]'
                : 'border-transparent text-[#8b949e] hover:text-[#c9d1d9] hover:bg-[#161b22]/50'
            }`}
          >
            <Bell className="w-3.5 h-3.5 text-[#7ee787]" /> Alerts Engine
          </button>

          <button
            onClick={() => setActiveTab('protocols')}
            className={`flex items-center gap-2 px-3.5 py-2.5 text-xs font-medium transition whitespace-nowrap border-b-2 ${
              activeTab === 'protocols'
                ? 'border-[#58a6ff] text-[#58a6ff] bg-[#161b22]'
                : 'border-transparent text-[#8b949e] hover:text-[#c9d1d9] hover:bg-[#161b22]/50'
            }`}
          >
            <Radio className="w-3.5 h-3.5" /> Traffic Monitor
          </button>

          <button
            onClick={() => setActiveTab('code-lab')}
            className={`flex items-center gap-2 px-3.5 py-2.5 text-xs font-medium transition whitespace-nowrap border-b-2 ${
              activeTab === 'code-lab'
                ? 'border-[#58a6ff] text-[#58a6ff] bg-[#161b22]'
                : 'border-transparent text-[#8b949e] hover:text-[#c9d1d9] hover:bg-[#161b22]/50'
            }`}
          >
            <FileCode className="w-3.5 h-3.5 text-[#7ee787]" /> C Source Suite
          </button>

          <button
            onClick={() => setActiveTab('advisor')}
            className={`flex items-center gap-2 px-3.5 py-2.5 text-xs font-medium transition whitespace-nowrap border-b-2 ${
              activeTab === 'advisor'
                ? 'border-[#58a6ff] text-[#58a6ff] bg-[#161b22]'
                : 'border-transparent text-[#8b949e] hover:text-[#c9d1d9] hover:bg-[#161b22]/50'
            }`}
          >
            <Sparkles className="w-3.5 h-3.5 text-[#d29922]" /> Hygiene Advisor
          </button>

          <button
            onClick={() => setActiveTab('knowledge')}
            className={`flex items-center gap-2 px-3.5 py-2.5 text-xs font-medium transition whitespace-nowrap border-b-2 ${
              activeTab === 'knowledge'
                ? 'border-[#58a6ff] text-[#58a6ff] bg-[#161b22]'
                : 'border-transparent text-[#8b949e] hover:text-[#c9d1d9] hover:bg-[#161b22]/50'
            }`}
          >
            <BookOpen className="w-3.5 h-3.5" /> Handbook
          </button>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-5 lg:p-6 space-y-4 pb-20 sm:pb-6">
        {/* VIEW 1: TOPOLOGY MAP */}
        {activeTab === 'topology' && (
          <div className="space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#161b22] p-3.5 rounded border border-[#30363d]">
              <div>
                <h2 className="text-sm font-semibold text-[#f0f6fc] flex items-center gap-2">
                  <Network className="w-4 h-4 text-[#58a6ff]" />
                  Interactive Layer 2/3 LAN Topology Map
                </h2>
                <p className="text-xs text-[#8b949e] mt-0.5">
                  Visual layout of Core Gateway, Switches, VLAN Clusters, and endpoints. Click any node to inspect fingerprints, open ports, and risk metrics.
                </p>
              </div>

              <div className="flex items-center gap-2 text-xs font-mono">
                <span className="px-2 py-1 rounded bg-[#010409] text-[#7ee787] border border-[#30363d]">
                  {devices.length} hosts up
                </span>
                <span className="px-2 py-1 rounded bg-[#010409] text-[#58a6ff] border border-[#30363d]">
                  {vlans.length} VLANs
                </span>
              </div>
            </div>

            <TopologyGraph
              devices={devices}
              vlans={vlans}
              selectedDevice={selectedDevice}
              onSelectDevice={(dev) => setSelectedDevice(dev)}
              filterVlan={filterVlan}
              onFilterVlanChange={(v) => setFilterVlan(v)}
            />
          </div>
        )}

        {/* VIEW 2: DEVICE INVENTORY */}
        {activeTab === 'devices' && (
          <div className="space-y-3">
            {/* Search & Filter Bar */}
            <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-[#161b22] p-3 rounded border border-[#30363d]">
              <div className="relative flex-1 w-full max-w-md">
                <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-[#8b949e]" />
                <input
                  type="text"
                  placeholder="Filter by IP, Hostname, MAC, Vendor, or OS..."
                  value={deviceSearch}
                  onChange={(e) => setDeviceSearch(e.target.value)}
                  className="w-full pl-9 pr-3 py-1.5 bg-[#010409] border border-[#30363d] rounded text-xs text-[#c9d1d9] placeholder-[#8b949e] focus:outline-none focus:border-[#58a6ff]"
                />
              </div>

              <div className="flex items-center gap-2 w-full sm:w-auto">
                <span className="text-xs text-[#8b949e]">VLAN:</span>
                <select
                  value={filterVlan}
                  onChange={(e) => setFilterVlan(e.target.value === 'all' ? 'all' : Number(e.target.value))}
                  className="bg-[#010409] border border-[#30363d] text-xs text-[#c9d1d9] rounded px-3 py-1.5 focus:outline-none focus:border-[#58a6ff]"
                >
                  <option value="all">All VLANs ({devices.length} hosts)</option>
                  {vlans.map(v => (
                    <option key={v.id} value={v.id}>VLAN {v.id}: {v.name}</option>
                  ))}
                </select>
              </div>
            </div>

            {/* Devices Table */}
            <div className="bg-[#161b22] border border-[#30363d] rounded overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs text-[#c9d1d9]">
                  <thead className="bg-[#161b22] text-[#8b949e] uppercase tracking-wider text-[11px] font-semibold border-b border-[#30363d]">
                    <tr>
                      <th className="py-2.5 px-4">IP Address</th>
                      <th className="py-2.5 px-4">MAC Address</th>
                      <th className="py-2.5 px-4">OS / Manufacturer</th>
                      <th className="py-2.5 px-4">VLAN</th>
                      <th className="py-2.5 px-4">Ports</th>
                      <th className="py-2.5 px-4">Hygiene Risk</th>
                      <th className="py-2.5 px-4 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#21262d] font-mono">
                    {filteredDevices.map(dev => {
                      const vlan = vlans.find(v => v.id === dev.vlanId);
                      return (
                        <tr 
                          key={dev.id} 
                          onClick={() => setSelectedDevice(dev)}
                          className="hover:bg-[#1f242c] transition cursor-pointer"
                        >
                          <td className="py-2.5 px-4">
                            <div className="font-semibold text-[#58a6ff]">{dev.ip}</div>
                            <div className="text-[10px] text-[#8b949e] font-sans">{dev.hostname}</div>
                          </td>

                          <td className="py-2.5 px-4">
                            <div className="text-[#c9d1d9]">{dev.mac}</div>
                          </td>

                          <td className="py-2.5 px-4 font-sans">
                            <div className="font-semibold text-[#f0f6fc]">{dev.vendor}</div>
                            <div className="text-[10px] text-[#8b949e]">{dev.osFingerprint.name}</div>
                          </td>

                          <td className="py-2.5 px-4 font-sans">
                            <span 
                              className="px-2 py-0.5 rounded-full text-[10px] font-semibold text-white inline-block"
                              style={{ backgroundColor: vlan?.color || '#1f6feb' }}
                            >
                              VLAN {dev.vlanId}
                            </span>
                          </td>

                          <td className="py-2.5 px-4">
                            <div className="flex flex-wrap gap-1 max-w-xs">
                              {dev.ports.slice(0, 3).map((p, i) => (
                                <span key={i} className={`px-1.5 py-0.2 rounded text-[10px] ${p.isRisky ? 'bg-[#da3633]/20 text-[#f85149] border border-[#da3633]/40' : 'bg-[#010409] text-[#7ee787] border border-[#30363d]'}`}>
                                  {p.port}
                                </span>
                              ))}
                              {dev.ports.length > 3 && (
                                <span className="text-[10px] text-[#8b949e] self-center">
                                  +{dev.ports.length - 3}
                                </span>
                              )}
                              {dev.ports.length === 0 && (
                                <span className="text-[10px] text-[#8b949e] italic font-sans">-</span>
                              )}
                            </div>
                          </td>

                          <td className="py-2.5 px-4 font-sans">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                              dev.riskScore === 'High' || dev.riskScore === 'Critical'
                                ? 'bg-[#da3633]/20 text-[#f85149] border border-[#da3633]/40'
                                : dev.riskScore === 'Medium'
                                ? 'bg-[#d29922]/20 text-[#d29922] border border-[#d29922]/40'
                                : 'bg-[#238636]/20 text-[#7ee787] border border-[#238636]/40'
                            }`}>
                              {dev.riskScore}
                            </span>
                          </td>

                          <td className="py-2.5 px-4 text-right font-sans">
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                setSelectedDevice(dev);
                              }}
                              className="px-2.5 py-1 rounded bg-[#21262d] hover:bg-[#30363d] text-[#58a6ff] text-xs font-medium border border-[#30363d] transition"
                            >
                              Inspect
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* VIEW 3: VLAN SEGMENTATION */}
        {activeTab === 'vlans' && (
          <VlanInspector
            vlans={vlans}
            devices={devices}
            onSelectVlan={(vId) => {
              setFilterVlan(vId);
              setActiveTab('topology');
            }}
          />
        )}

        {/* VIEW 4: NETFLOW & IPFIX TELEMETRY (NEW) */}
        {activeTab === 'netflow' && (
          <NetflowAnalyzer />
        )}

        {/* VIEW 5: BROADCAST STORM & STP LOOP WATCHDOG (NEW) */}
        {activeTab === 'storms' && (
          <StormDetector />
        )}

        {/* VIEW 6: EMAIL & WEBHOOK ALERTS ENGINE (NEW) */}
        {activeTab === 'alerts' && (
          <AlertsManager />
        )}

        {/* VIEW 7: PROTOCOL ANALYZER */}
        {activeTab === 'protocols' && (
          <ProtocolAuditor />
        )}

        {/* VIEW 8: C & BASH SOURCE CODE LAB */}
        {activeTab === 'code-lab' && (
          <CodeLabView />
        )}

        {/* VIEW 9: AI HYGIENE ADVISOR */}
        {activeTab === 'advisor' && (
          <AiAdvisor devices={devices} vlans={vlans} />
        )}

        {/* VIEW 10: EDUCATIONAL PRIMER & HANDBOOK */}
        {activeTab === 'knowledge' && (
          <AuditKnowledgeView />
        )}
      </main>

      {/* Slide-out Device Drawer */}
      <DeviceDrawer
        device={selectedDevice}
        vlan={getVlanForDevice(selectedDevice)}
        onClose={() => setSelectedDevice(null)}
      />

      {/* Scanner & Nmap Importer Modal */}
      <ScannerModal
        isOpen={isScannerOpen}
        onClose={() => setIsScannerOpen(false)}
        onScanComplete={handleScanComplete}
      />

      {/* Mobile Bottom Navigation Bar */}
      <nav className="sm:hidden fixed bottom-0 inset-x-0 bg-[#161b22] border-t border-[#30363d] z-30 flex items-center justify-around py-2 px-1 text-[10px]">
        <button
          onClick={() => setActiveTab('topology')}
          className={`flex flex-col items-center gap-1 py-1 px-2 rounded ${activeTab === 'topology' ? 'text-[#58a6ff] font-bold' : 'text-[#8b949e]'}`}
        >
          <Network className="w-4 h-4" />
          <span>Map</span>
        </button>

        <button
          onClick={() => setActiveTab('netflow')}
          className={`flex flex-col items-center gap-1 py-1 px-2 rounded ${activeTab === 'netflow' ? 'text-[#58a6ff] font-bold' : 'text-[#8b949e]'}`}
        >
          <Activity className="w-4 h-4" />
          <span>NetFlow</span>
        </button>

        <button
          onClick={() => setActiveTab('storms')}
          className={`flex flex-col items-center gap-1 py-1 px-2 rounded ${activeTab === 'storms' ? 'text-[#da3633] font-bold' : 'text-[#8b949e]'}`}
        >
          <Zap className="w-4 h-4" />
          <span>Storms</span>
        </button>

        <button
          onClick={() => setActiveTab('alerts')}
          className={`flex flex-col items-center gap-1 py-1 px-2 rounded ${activeTab === 'alerts' ? 'text-[#7ee787] font-bold' : 'text-[#8b949e]'}`}
        >
          <Bell className="w-4 h-4" />
          <span>Alerts</span>
        </button>

        <button
          onClick={() => setActiveTab('code-lab')}
          className={`flex flex-col items-center gap-1 py-1 px-2 rounded ${activeTab === 'code-lab' ? 'text-[#7ee787] font-bold' : 'text-[#8b949e]'}`}
        >
          <FileCode className="w-4 h-4" />
          <span>C Code</span>
        </button>
      </nav>
    </div>
  );
}
