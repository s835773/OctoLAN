import React, { useState } from 'react';
import { SAMPLE_NETFLOW_RECORDS, SAMPLE_TOP_TALKERS } from '../data/telemetryData';
import { NetflowRecord } from '../types';
import { PpsSpikeVisualizer } from './PpsSpikeVisualizer';
import { 
  Activity, ArrowDownLeft, ArrowUpRight, ArrowLeftRight, 
  Search, ShieldAlert, Cpu, HardDrive, Download, RefreshCw,
  Layers, Radio, SlidersHorizontal, BarChart3, Database, Globe
} from 'lucide-react';

export const NetflowAnalyzer: React.FC = () => {
  const [records, setRecords] = useState<NetflowRecord[]>(SAMPLE_NETFLOW_RECORDS);
  const [filterDirection, setFilterDirection] = useState<'all' | 'Ingress' | 'Egress' | 'Internal'>('all');
  const [filterProtocol, setFilterProtocol] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [isCollecting, setIsCollecting] = useState(false);

  const filteredRecords = records.filter(r => {
    const matchesDirection = filterDirection === 'all' || r.flowDirection === filterDirection;
    const matchesProtocol = filterProtocol === 'all' || r.protocol === filterProtocol;
    const matchesSearch = searchQuery === '' ||
      r.srcIp.includes(searchQuery) ||
      r.dstIp.includes(searchQuery) ||
      (r.srcHostname && r.srcHostname.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (r.dstHostname && r.dstHostname.toLowerCase().includes(searchQuery.toLowerCase())) ||
      r.application.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesDirection && matchesProtocol && matchesSearch;
  });

  const totalBytes = records.reduce((acc, r) => acc + r.bytes, 0);
  const totalPackets = records.reduce((acc, r) => acc + r.packets, 0);
  const totalBandwidthMbps = records.reduce((acc, r) => acc + r.rateMbps, 0).toFixed(2);
  const anomalousCount = records.filter(r => r.isAnomalous).length;

  const handleSimulateNewFlow = () => {
    setIsCollecting(true);
    setTimeout(() => {
      const newFlow: NetflowRecord = {
        id: `flow-${Date.now()}`,
        timestamp: new Date().toLocaleTimeString(),
        srcIp: '192.168.10.102',
        srcPort: Math.floor(Math.random() * 20000) + 30000,
        srcHostname: 'dev-macbook-pro',
        dstIp: '192.168.1.2',
        dstPort: 22,
        dstHostname: 'core-sw01 (SSH)',
        protocol: 'TCP',
        application: 'SSH Admin Session',
        bytes: 1450000,
        packets: 1200,
        durationMs: 4200,
        tcpFlags: 'ACK, PSH',
        vlanId: 10,
        flowDirection: 'Internal',
        rateMbps: 2.76
      };
      setRecords(prev => [newFlow, ...prev]);
      setIsCollecting(false);
    }, 600);
  };

  const handleExportCsv = () => {
    let csv = 'FlowID,Timestamp,SrcIP,SrcPort,DstIP,DstPort,Protocol,Application,Bytes,Packets,RateMbps,Direction,VLAN\n';
    records.forEach(r => {
      csv += `"${r.id}","${r.timestamp}","${r.srcIp}",${r.srcPort},"${r.dstIp}",${r.dstPort},"${r.protocol}","${r.application}",${r.bytes},${r.packets},${r.rateMbps},"${r.flowDirection}",${r.vlanId}\n`;
    });
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `OctoLAN_NetFlow_Telemetry_${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-4">
      {/* Header Banner */}
      <div className="bg-[#161b22] border border-[#30363d] p-4 rounded flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded bg-[#238636] text-white flex items-center justify-center font-bold text-xs shadow-sm">
              <Activity className="w-3.5 h-3.5" />
            </div>
            <h2 className="text-sm font-bold text-[#f0f6fc]">
              NetFlow v5/v9 & IPFIX Flow Telemetry Analyzer
            </h2>
          </div>
          <p className="text-xs text-[#8b949e] mt-1 max-w-3xl leading-relaxed">
            Real-time traffic flow inspection and bandwidth utilization analysis. Captures IP 5-tuples, duration, packet rates, TCP flag signatures, and cross-VLAN flow anomalies.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleSimulateNewFlow}
            disabled={isCollecting}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#21262d] hover:bg-[#30363d] text-[#c9d1d9] text-xs font-semibold border border-[#30363d] transition disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-[#58a6ff] ${isCollecting ? 'animate-spin' : ''}`} />
            <span>Poll Flow Collector</span>
          </button>

          <button
            onClick={handleExportCsv}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#238636] hover:bg-[#2ea043] text-white text-xs font-semibold shadow-sm transition"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export CSV</span>
          </button>
        </div>
      </div>

      {/* Metric Cards Grid */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <div className="bg-[#161b22] border border-[#30363d] p-3 rounded">
          <span className="text-[10px] uppercase font-semibold text-[#8b949e] block">Aggregated Bandwidth</span>
          <div className="flex items-baseline gap-1 mt-1">
            <span className="text-lg font-bold text-[#58a6ff] font-mono">{totalBandwidthMbps}</span>
            <span className="text-xs text-[#8b949e]">Mbps</span>
          </div>
          <span className="text-[10px] text-[#7ee787] mt-1 block">{(totalBytes / (1024 * 1024)).toFixed(1)} MB captured</span>
        </div>

        <div className="bg-[#161b22] border border-[#30363d] p-3 rounded">
          <span className="text-[10px] uppercase font-semibold text-[#8b949e] block">Active Flow Records</span>
          <div className="flex items-baseline gap-1 mt-1">
            <span className="text-lg font-bold text-[#f0f6fc] font-mono">{records.length}</span>
            <span className="text-xs text-[#8b949e]">flows</span>
          </div>
          <span className="text-[10px] text-[#8b949e] mt-1 block">{totalPackets.toLocaleString()} total pkts</span>
        </div>

        <div className="bg-[#161b22] border border-[#30363d] p-3 rounded">
          <span className="text-[10px] uppercase font-semibold text-[#8b949e] block">Collector Port / Sampling</span>
          <div className="flex items-baseline gap-1 mt-1">
            <span className="text-sm font-bold text-[#7ee787] font-mono">UDP :2055</span>
          </div>
          <span className="text-[10px] text-[#8b949e] mt-1 block">1:1 Full Packet Sampling</span>
        </div>

        <div className="bg-[#161b22] border border-[#30363d] p-3 rounded">
          <span className="text-[10px] uppercase font-semibold text-[#8b949e] block">Anomalous Flow Alerts</span>
          <div className="flex items-baseline gap-1 mt-1">
            <span className={`text-lg font-bold font-mono ${anomalousCount > 0 ? 'text-[#f85149]' : 'text-[#7ee787]'}`}>
              {anomalousCount}
            </span>
            <span className="text-xs text-[#8b949e]">flagged</span>
          </div>
          <span className="text-[10px] text-[#d29922] mt-1 block">VLAN Leak / Scan Probes</span>
        </div>
      </div>

      {/* Real-time PPS Counter & Traffic Spike Visualizer */}
      <PpsSpikeVisualizer />

      {/* Top Talkers & Application Breakdown Section */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Top Talkers Card */}
        <div className="lg:col-span-7 bg-[#161b22] border border-[#30363d] rounded p-3.5 space-y-3">
          <div className="flex items-center justify-between border-b border-[#30363d] pb-2">
            <h3 className="text-xs font-bold text-[#f0f6fc] flex items-center gap-1.5 uppercase tracking-wider">
              <BarChart3 className="w-3.5 h-3.5 text-[#58a6ff]" />
              Top Talkers (Auvik Flow Telemetry)
            </h3>
            <span className="text-[10px] text-[#8b949e] font-mono">Ranked by Total Octets</span>
          </div>

          <div className="space-y-2.5">
            {SAMPLE_TOP_TALKERS.map((talker, idx) => (
              <div key={idx} className="space-y-1 bg-[#010409] p-2 rounded border border-[#30363d]">
                <div className="flex items-center justify-between text-xs font-mono">
                  <div className="flex items-center gap-1.5">
                    <span className="text-[#58a6ff] font-bold">{talker.ip}</span>
                    <span className="text-[#8b949e] font-sans text-[11px]">({talker.hostname})</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-[#7ee787] font-semibold">{talker.bandwidthMbps} Mbps</span>
                    <span className="text-[10px] text-[#8b949e]">({talker.percentage}%)</span>
                  </div>
                </div>

                {/* Progress bar */}
                <div className="w-full h-1.5 bg-[#21262d] rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-gradient-to-r from-[#238636] to-[#58a6ff] rounded-full"
                    style={{ width: `${talker.percentage}%` }}
                  />
                </div>

                <div className="flex justify-between text-[10px] text-[#8b949e]">
                  <span>{talker.deviceType} • VLAN {talker.vlanId}</span>
                  <span>{(talker.totalBytes / (1024 * 1024)).toFixed(1)} MB • {talker.flowCount} flows</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Application & Protocol Distribution */}
        <div className="lg:col-span-5 bg-[#161b22] border border-[#30363d] rounded p-3.5 space-y-3">
          <div className="flex items-center justify-between border-b border-[#30363d] pb-2">
            <h3 className="text-xs font-bold text-[#f0f6fc] flex items-center gap-1.5 uppercase tracking-wider">
              <Database className="w-3.5 h-3.5 text-[#7ee787]" />
              Application Traffic Breakdown
            </h3>
            <span className="text-[10px] text-[#8b949e]">Layer 7 Classification</span>
          </div>

          <div className="space-y-2 text-xs">
            <div className="p-2 rounded bg-[#010409] border border-[#30363d] flex items-center justify-between">
              <div>
                <span className="font-semibold text-[#f0f6fc]">SMBv3 / Storage Area Network</span>
                <span className="block text-[10px] text-[#8b949e]">TCP 445 • Active Directory & File Share</span>
              </div>
              <span className="font-mono text-[#58a6ff] font-bold">38.4%</span>
            </div>

            <div className="p-2 rounded bg-[#010409] border border-[#30363d] flex items-center justify-between">
              <div>
                <span className="font-semibold text-[#f0f6fc]">RTSP / Video Surveillance</span>
                <span className="block text-[10px] text-[#8b949e]">TCP 554 • H.264 IP Camera Feed</span>
              </div>
              <span className="font-mono text-[#58a6ff] font-bold">24.6%</span>
            </div>

            <div className="p-2 rounded bg-[#010409] border border-[#30363d] flex items-center justify-between">
              <div>
                <span className="font-semibold text-[#f0f6fc]">Cloud Backup Egress (HTTPS)</span>
                <span className="block text-[10px] text-[#8b949e]">TCP 443 • Offsite GCS Replica</span>
              </div>
              <span className="font-mono text-[#58a6ff] font-bold">18.2%</span>
            </div>

            <div className="p-2 rounded bg-[#010409] border border-[#30363d] flex items-center justify-between">
              <div>
                <span className="font-semibold text-[#f0f6fc]">PostgreSQL Database Query</span>
                <span className="block text-[10px] text-[#8b949e]">TCP 5432 • Node Replication</span>
              </div>
              <span className="font-mono text-[#58a6ff] font-bold">11.5%</span>
            </div>

            <div className="p-2 rounded bg-[#010409] border border-[#30363d] flex items-center justify-between">
              <div>
                <span className="font-semibold text-[#f0f6fc]">RTP VoIP Audio Streams</span>
                <span className="block text-[10px] text-[#8b949e]">UDP 10240-16400 • G.711 SIP Call</span>
              </div>
              <span className="font-mono text-[#58a6ff] font-bold">7.3%</span>
            </div>
          </div>
        </div>
      </div>

      {/* Filter & Search Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-[#161b22] p-3 rounded border border-[#30363d]">
        <div className="relative flex-1 w-full max-w-md">
          <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-[#8b949e]" />
          <input
            type="text"
            placeholder="Filter by Source, Destination, Hostname, or Application..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 bg-[#010409] border border-[#30363d] rounded text-xs text-[#c9d1d9] placeholder-[#8b949e] focus:outline-none focus:border-[#58a6ff]"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <span className="text-xs text-[#8b949e]">Direction:</span>
          <select
            value={filterDirection}
            onChange={(e) => setFilterDirection(e.target.value as any)}
            className="bg-[#010409] border border-[#30363d] text-xs text-[#c9d1d9] rounded px-2.5 py-1 focus:outline-none focus:border-[#58a6ff]"
          >
            <option value="all">All Directions</option>
            <option value="Internal">Internal (East-West)</option>
            <option value="Ingress">Ingress (North-South)</option>
            <option value="Egress">Egress (North-South)</option>
          </select>

          <span className="text-xs text-[#8b949e] ml-2">Protocol:</span>
          <select
            value={filterProtocol}
            onChange={(e) => setFilterProtocol(e.target.value)}
            className="bg-[#010409] border border-[#30363d] text-xs text-[#c9d1d9] rounded px-2.5 py-1 focus:outline-none focus:border-[#58a6ff]"
          >
            <option value="all">All Protocols</option>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
            <option value="ICMP">ICMP</option>
          </select>
        </div>
      </div>

      {/* NetFlow Records Table */}
      <div className="bg-[#161b22] border border-[#30363d] rounded overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-[#c9d1d9]">
            <thead className="bg-[#161b22] text-[#8b949e] uppercase tracking-wider text-[11px] font-semibold border-b border-[#30363d]">
              <tr>
                <th className="py-2.5 px-3">Time</th>
                <th className="py-2.5 px-3">Source Endpoint</th>
                <th className="py-2.5 px-3">Destination Endpoint</th>
                <th className="py-2.5 px-3">Proto / App</th>
                <th className="py-2.5 px-3">Volume</th>
                <th className="py-2.5 px-3">Bandwidth</th>
                <th className="py-2.5 px-3">TCP Flags</th>
                <th className="py-2.5 px-3">Direction</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#21262d] font-mono">
              {filteredRecords.map(rec => (
                <tr 
                  key={rec.id} 
                  className={`hover:bg-[#1f242c] transition ${rec.isAnomalous ? 'bg-[#da3633]/10' : ''}`}
                >
                  <td className="py-2.5 px-3 text-[#8b949e] text-[11px]">
                    {rec.timestamp}
                  </td>

                  <td className="py-2.5 px-3">
                    <div className="font-semibold text-[#58a6ff]">{rec.srcIp}:{rec.srcPort}</div>
                    {rec.srcHostname && (
                      <div className="text-[10px] text-[#8b949e] font-sans truncate max-w-[140px]">{rec.srcHostname}</div>
                    )}
                  </td>

                  <td className="py-2.5 px-3">
                    <div className="font-semibold text-[#c9d1d9]">{rec.dstIp}:{rec.dstPort}</div>
                    {rec.dstHostname && (
                      <div className="text-[10px] text-[#8b949e] font-sans truncate max-w-[140px]">{rec.dstHostname}</div>
                    )}
                  </td>

                  <td className="py-2.5 px-3 font-sans">
                    <div className="font-semibold text-[#f0f6fc]">{rec.application}</div>
                    <div className="text-[10px] text-[#8b949e] font-mono">{rec.protocol} • VLAN {rec.vlanId}</div>
                  </td>

                  <td className="py-2.5 px-3">
                    <div>{(rec.bytes / (1024 * 1024)).toFixed(2)} MB</div>
                    <div className="text-[10px] text-[#8b949e]">{rec.packets.toLocaleString()} pkts</div>
                  </td>

                  <td className="py-2.5 px-3">
                    <span className="text-[#7ee787] font-semibold">{rec.rateMbps} Mbps</span>
                    <div className="text-[10px] text-[#8b949e]">{rec.durationMs}ms</div>
                  </td>

                  <td className="py-2.5 px-3 text-[11px] text-[#8b949e]">
                    {rec.tcpFlags}
                  </td>

                  <td className="py-2.5 px-3 font-sans">
                    {rec.isAnomalous ? (
                      <span className="flex items-center gap-1 text-[10px] font-bold text-[#f85149] bg-[#da3633]/20 px-2 py-0.5 rounded border border-[#da3633]/40" title={rec.anomalyReason}>
                        <ShieldAlert className="w-3 h-3" /> Anomaly
                      </span>
                    ) : rec.flowDirection === 'Internal' ? (
                      <span className="flex items-center gap-1 text-[10px] text-[#58a6ff] bg-[#58a6ff]/10 px-2 py-0.5 rounded border border-[#58a6ff]/30">
                        <ArrowLeftRight className="w-3 h-3" /> East-West
                      </span>
                    ) : rec.flowDirection === 'Egress' ? (
                      <span className="flex items-center gap-1 text-[10px] text-[#d29922] bg-[#d29922]/10 px-2 py-0.5 rounded border border-[#d29922]/30">
                        <ArrowUpRight className="w-3 h-3" /> Egress
                      </span>
                    ) : (
                      <span className="flex items-center gap-1 text-[10px] text-[#7ee787] bg-[#238636]/15 px-2 py-0.5 rounded border border-[#238636]/30">
                        <ArrowDownLeft className="w-3 h-3" /> Ingress
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
