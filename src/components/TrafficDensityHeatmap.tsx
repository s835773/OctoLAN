import React, { useState, useMemo } from 'react';
import {
  ResponsiveContainer,
  ComposedChart,
  BarChart,
  Bar,
  Area,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  ReferenceLine,
  Cell,
  Legend
} from 'recharts';
import { 
  Flame, 
  Clock, 
  Calendar, 
  TrendingUp, 
  AlertCircle, 
  Zap, 
  Filter, 
  Layers, 
  Activity,
  Info,
  Maximize2,
  Sparkles
} from 'lucide-react';

export interface HourlyTrafficData {
  hour: number;
  hourLabel: string;
  bandwidthGb: number;
  avgMbps: number;
  peakMbps: number;
  packetCountM: number;
  activeFlows: number;
  topProtocol: string;
  vlanVolume: {
    corp: number;      // VLAN 10
    servers: number;   // VLAN 30
    storage: number;   // VLAN 100
    guest: number;     // VLAN 50
    voip: number;      // VLAN 20
  };
  intensity: number;   // 0 to 100 density score
  isPeak: boolean;
  peakLabel?: string;
}

export interface DayHourDensity {
  day: string;
  dayShort: string;
  hours: number[]; // 24 values, 0-100 density
}

// 24-hour sample dataset representing realistic enterprise LAN/WAN flow patterns
const GENERATE_24H_DATA = (vlanFilter: string): HourlyTrafficData[] => {
  const vlanMultipliers: Record<string, { corp: number; servers: number; storage: number; guest: number; voip: number }> = {
    all: { corp: 1, servers: 1, storage: 1, guest: 1, voip: 1 },
    vlan10: { corp: 2.2, servers: 0.2, storage: 0.1, guest: 0, voip: 0.1 },
    vlan30: { corp: 0.1, servers: 2.5, storage: 0.4, guest: 0, voip: 0.1 },
    vlan50: { corp: 0, servers: 0.1, storage: 0, guest: 3.0, voip: 0 },
    vlan100: { corp: 0.1, servers: 0.8, storage: 3.2, guest: 0, voip: 0 },
  };

  const mult = vlanMultipliers[vlanFilter] || vlanMultipliers.all;

  return [
    { hour: 0, hourLabel: '00:00', bandwidthGb: 14.2, avgMbps: 31.5, peakMbps: 78.2, packetCountM: 1.8, activeFlows: 340, topProtocol: 'TCP/SAN', vlanVolume: { corp: 0.8, servers: 4.2, storage: 8.5, guest: 0.1, voip: 0.6 }, intensity: 22, isPeak: false },
    { hour: 1, hourLabel: '01:00', bandwidthGb: 28.6, avgMbps: 63.5, peakMbps: 145.0, packetCountM: 3.4, activeFlows: 410, topProtocol: 'TCP/445', vlanVolume: { corp: 0.4, servers: 8.2, storage: 19.5, guest: 0.1, voip: 0.4 }, intensity: 45, isPeak: false },
    { hour: 2, hourLabel: '02:00', bandwidthGb: 78.4, avgMbps: 174.2, peakMbps: 485.0, packetCountM: 9.8, activeFlows: 620, topProtocol: 'TCP/SAN Sync', vlanVolume: { corp: 0.3, servers: 21.0, storage: 56.5, guest: 0.1, voip: 0.5 }, intensity: 88, isPeak: true, peakLabel: 'Nightly Database Replication' },
    { hour: 3, hourLabel: '03:00', bandwidthGb: 84.1, avgMbps: 186.8, peakMbps: 512.0, packetCountM: 10.5, activeFlows: 680, topProtocol: 'GCS Backup (HTTPS)', vlanVolume: { corp: 0.2, servers: 24.1, storage: 59.2, guest: 0.1, voip: 0.5 }, intensity: 94, isPeak: true, peakLabel: 'Cloud SAN Offsite Snapshot' },
    { hour: 4, hourLabel: '04:00', bandwidthGb: 42.0, avgMbps: 93.3, peakMbps: 210.0, packetCountM: 5.2, activeFlows: 390, topProtocol: 'TCP/Backup', vlanVolume: { corp: 0.5, servers: 12.0, storage: 28.8, guest: 0.2, voip: 0.5 }, intensity: 52, isPeak: false },
    { hour: 5, hourLabel: '05:00', bandwidthGb: 12.5, avgMbps: 27.7, peakMbps: 65.0, packetCountM: 1.6, activeFlows: 280, topProtocol: 'NTP/DNS Sync', vlanVolume: { corp: 1.1, servers: 5.4, storage: 4.8, guest: 0.4, voip: 0.8 }, intensity: 18, isPeak: false },
    { hour: 6, hourLabel: '06:00', bandwidthGb: 19.8, avgMbps: 44.0, peakMbps: 98.0, packetCountM: 2.6, activeFlows: 460, topProtocol: 'TLS/HTTPS', vlanVolume: { corp: 4.5, servers: 7.2, storage: 5.1, guest: 1.2, voip: 1.8 }, intensity: 28, isPeak: false },
    { hour: 7, hourLabel: '07:00', bandwidthGb: 38.2, avgMbps: 84.8, peakMbps: 192.0, packetCountM: 5.1, activeFlows: 890, topProtocol: 'Kerberos / Auth', vlanVolume: { corp: 16.2, servers: 11.0, storage: 4.5, guest: 3.5, voip: 3.0 }, intensity: 50, isPeak: false },
    { hour: 8, hourLabel: '08:00', bandwidthGb: 68.5, avgMbps: 152.2, peakMbps: 380.0, packetCountM: 8.9, activeFlows: 1420, topProtocol: 'SMB / OAuth / Mail', vlanVolume: { corp: 34.0, servers: 18.5, storage: 6.0, guest: 4.5, voip: 5.5 }, intensity: 78, isPeak: false },
    { hour: 9, hourLabel: '09:00', bandwidthGb: 92.4, avgMbps: 205.3, peakMbps: 540.0, packetCountM: 12.4, activeFlows: 1980, topProtocol: 'Teams / Zoom / SMB', vlanVolume: { corp: 46.2, servers: 23.0, storage: 8.2, guest: 6.5, voip: 8.5 }, intensity: 98, isPeak: true, peakLabel: 'Morning Staff Rush & VoIP Start' },
    { hour: 10, hourLabel: '10:00', bandwidthGb: 98.6, avgMbps: 219.1, peakMbps: 590.0, packetCountM: 13.8, activeFlows: 2150, topProtocol: 'HTTPS / SIP VoIP', vlanVolume: { corp: 48.5, servers: 25.1, storage: 9.0, guest: 7.0, voip: 9.0 }, intensity: 100, isPeak: true, peakLabel: 'Peak Core Office Collaboration' },
    { hour: 11, hourLabel: '11:00', bandwidthGb: 88.0, avgMbps: 195.5, peakMbps: 490.0, packetCountM: 11.9, activeFlows: 1890, topProtocol: 'PostgreSQL / Web', vlanVolume: { corp: 42.0, servers: 26.0, storage: 7.5, guest: 5.5, voip: 7.0 }, intensity: 90, isPeak: false },
    { hour: 12, hourLabel: '12:00', bandwidthGb: 54.2, avgMbps: 120.4, peakMbps: 280.0, packetCountM: 7.1, activeFlows: 1320, topProtocol: 'YouTube / Media / Web', vlanVolume: { corp: 22.0, servers: 14.2, storage: 5.0, guest: 9.5, voip: 3.5 }, intensity: 60, isPeak: false },
    { hour: 13, hourLabel: '13:00', bandwidthGb: 72.8, avgMbps: 161.7, peakMbps: 395.0, packetCountM: 9.5, activeFlows: 1650, topProtocol: 'HTTPS / Git / Dev', vlanVolume: { corp: 36.0, servers: 20.0, storage: 6.8, guest: 4.8, voip: 5.2 }, intensity: 79, isPeak: false },
    { hour: 14, hourLabel: '14:00', bandwidthGb: 95.0, avgMbps: 211.1, peakMbps: 565.0, packetCountM: 13.0, activeFlows: 2080, topProtocol: 'SIP / RTSP / SMB', vlanVolume: { corp: 47.0, servers: 24.5, storage: 8.5, guest: 6.8, voip: 8.2 }, intensity: 97, isPeak: true, peakLabel: 'Afternoon Heavy Video Conf Peak' },
    { hour: 15, hourLabel: '15:00', bandwidthGb: 91.2, avgMbps: 202.6, peakMbps: 520.0, packetCountM: 12.1, activeFlows: 1940, topProtocol: 'PostgreSQL Sync', vlanVolume: { corp: 44.0, servers: 25.2, storage: 8.0, guest: 6.0, voip: 8.0 }, intensity: 92, isPeak: false },
    { hour: 16, hourLabel: '16:00', bandwidthGb: 79.5, avgMbps: 176.6, peakMbps: 430.0, packetCountM: 10.4, activeFlows: 1720, topProtocol: 'Git LFS / Build Artifacts', vlanVolume: { corp: 38.5, servers: 23.0, storage: 8.0, guest: 4.5, voip: 5.5 }, intensity: 84, isPeak: false },
    { hour: 17, hourLabel: '17:00', bandwidthGb: 58.4, avgMbps: 129.7, peakMbps: 310.0, packetCountM: 7.8, activeFlows: 1210, topProtocol: 'Cloud File Sync', vlanVolume: { corp: 26.4, servers: 18.0, storage: 7.0, guest: 3.5, voip: 3.5 }, intensity: 65, isPeak: false },
    { hour: 18, hourLabel: '18:00', bandwidthGb: 34.0, avgMbps: 75.5, peakMbps: 180.0, packetCountM: 4.6, activeFlows: 750, topProtocol: 'SSH / Security Scan', vlanVolume: { corp: 12.0, servers: 13.5, storage: 5.5, guest: 1.5, voip: 1.5 }, intensity: 42, isPeak: false },
    { hour: 19, hourLabel: '19:00', bandwidthGb: 22.1, avgMbps: 49.1, peakMbps: 120.0, packetCountM: 2.9, activeFlows: 510, topProtocol: 'RTSP Cameras / IoT', vlanVolume: { corp: 4.0, servers: 10.1, storage: 6.0, guest: 0.8, voip: 1.2 }, intensity: 30, isPeak: false },
    { hour: 20, hourLabel: '20:00', bandwidthGb: 19.5, avgMbps: 43.3, peakMbps: 105.0, packetCountM: 2.5, activeFlows: 440, topProtocol: 'RTSP / Telemetry', vlanVolume: { corp: 2.5, servers: 9.0, storage: 6.5, guest: 0.5, voip: 1.0 }, intensity: 27, isPeak: false },
    { hour: 21, hourLabel: '21:00', bandwidthGb: 24.8, avgMbps: 55.1, peakMbps: 135.0, packetCountM: 3.2, activeFlows: 480, topProtocol: 'Incremental NAS Backup', vlanVolume: { corp: 1.5, servers: 10.8, storage: 11.5, guest: 0.2, voip: 0.8 }, intensity: 35, isPeak: false },
    { hour: 22, hourLabel: '22:00', bandwidthGb: 31.0, avgMbps: 68.8, peakMbps: 160.0, packetCountM: 4.1, activeFlows: 530, topProtocol: 'DB Log Truncation', vlanVolume: { corp: 1.0, servers: 13.0, storage: 16.2, guest: 0.1, voip: 0.7 }, intensity: 44, isPeak: false },
    { hour: 23, hourLabel: '23:00', bandwidthGb: 21.4, avgMbps: 47.5, peakMbps: 115.0, packetCountM: 2.8, activeFlows: 390, topProtocol: 'Telemetry Rollup', vlanVolume: { corp: 0.9, servers: 8.5, storage: 11.2, guest: 0.1, voip: 0.7 }, intensity: 31, isPeak: false },
  ].map(item => {
    // scale by multiplier
    const corp = +(item.vlanVolume.corp * mult.corp).toFixed(1);
    const servers = +(item.vlanVolume.servers * mult.servers).toFixed(1);
    const storage = +(item.vlanVolume.storage * mult.storage).toFixed(1);
    const guest = +(item.vlanVolume.guest * mult.guest).toFixed(1);
    const voip = +(item.vlanVolume.voip * mult.voip).toFixed(1);
    const totalVlan = corp + servers + storage + guest + voip;

    const scale = vlanFilter === 'all' ? 1 : totalVlan / (item.vlanVolume.corp + item.vlanVolume.servers + item.vlanVolume.storage + item.vlanVolume.guest + item.vlanVolume.voip);
    const bandwidthGb = +(item.bandwidthGb * scale).toFixed(1);
    const avgMbps = +(item.avgMbps * scale).toFixed(1);
    const peakMbps = +(item.peakMbps * scale).toFixed(1);
    const intensity = Math.min(100, Math.round(item.intensity * scale));

    return {
      ...item,
      bandwidthGb,
      avgMbps,
      peakMbps,
      intensity,
      vlanVolume: { corp, servers, storage, guest, voip }
    };
  });
};

// 7-day heatmap matrix data (Monday to Sunday x 24 hours)
const DAYS_OF_WEEK: DayHourDensity[] = [
  { day: 'Monday', dayShort: 'Mon', hours: [18, 38, 85, 90, 48, 15, 25, 52, 82, 100, 96, 88, 58, 80, 96, 90, 82, 64, 40, 28, 25, 34, 42, 28] },
  { day: 'Tuesday', dayShort: 'Tue', hours: [20, 42, 88, 94, 52, 18, 28, 50, 78, 98, 100, 90, 60, 79, 97, 92, 84, 65, 42, 30, 27, 35, 44, 31] },
  { day: 'Wednesday', dayShort: 'Wed', hours: [22, 45, 86, 92, 50, 16, 26, 48, 76, 95, 98, 92, 62, 82, 98, 94, 85, 66, 43, 29, 26, 36, 45, 30] },
  { day: 'Thursday', dayShort: 'Thu', hours: [21, 40, 89, 95, 51, 17, 27, 49, 80, 99, 99, 89, 59, 81, 95, 91, 83, 63, 39, 28, 24, 33, 43, 29] },
  { day: 'Friday', dayShort: 'Fri', hours: [19, 36, 82, 88, 46, 14, 24, 46, 74, 94, 95, 84, 54, 72, 86, 80, 70, 50, 32, 24, 20, 28, 38, 25] },
  { day: 'Saturday', dayShort: 'Sat', hours: [12, 18, 55, 60, 30, 10, 12, 18, 25, 32, 36, 30, 28, 30, 34, 32, 28, 22, 18, 16, 15, 20, 26, 18] },
  { day: 'Sunday', dayShort: 'Sun', hours: [10, 15, 62, 70, 35, 8, 10, 14, 20, 26, 30, 26, 24, 26, 28, 26, 24, 18, 15, 14, 14, 22, 30, 20] },
];

export const TrafficDensityHeatmap: React.FC = () => {
  const [selectedVlan, setSelectedVlan] = useState<string>('all');
  const [chartViewMode, setChartViewMode] = useState<'density' | 'stacked' | 'peakCompare'>('density');
  const [activeHour, setActiveHour] = useState<HourlyTrafficData | null>(null);
  const [selectedDay, setSelectedDay] = useState<string>('Tuesday');
  const [hoveredCell, setHoveredCell] = useState<{ day: string; hour: number; val: number } | null>(null);

  const hourlyData = useMemo(() => GENERATE_24H_DATA(selectedVlan), [selectedVlan]);

  // Overall summary metrics
  const totalDayGb = useMemo(() => hourlyData.reduce((acc, d) => acc + d.bandwidthGb, 0).toFixed(1), [hourlyData]);
  const maxPeakMbps = useMemo(() => Math.max(...hourlyData.map(d => d.peakMbps)), [hourlyData]);
  const avgMbpsOverall = useMemo(() => (hourlyData.reduce((acc, d) => acc + d.avgMbps, 0) / 24).toFixed(1), [hourlyData]);
  const peakHours = useMemo(() => hourlyData.filter(d => d.isPeak), [hourlyData]);

  // Color helper for density heatmap
  const getDensityColor = (density: number) => {
    if (density >= 90) return { bg: '#da3633', text: '#ffffff', label: 'Critical Surge (90-100%)', badge: 'bg-[#da3633] text-white' };
    if (density >= 75) return { bg: '#d29922', text: '#000000', label: 'Heavy Usage (75-89%)', badge: 'bg-[#d29922] text-black' };
    if (density >= 50) return { bg: '#238636', text: '#ffffff', label: 'Moderate Load (50-74%)', badge: 'bg-[#238636] text-white' };
    if (density >= 25) return { bg: '#1f6feb', text: '#ffffff', label: 'Nominal Traffic (25-49%)', badge: 'bg-[#1f6feb] text-white' };
    return { bg: '#21262d', text: '#8b949e', label: 'Idle / Quiet (<25%)', badge: 'bg-[#21262d] text-[#8b949e]' };
  };

  // Custom Tooltip for Recharts
  const CustomChartTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      const data: HourlyTrafficData = payload[0].payload;
      const densityInfo = getDensityColor(data.intensity);

      return (
        <div className="bg-[#161b22] border border-[#30363d] p-3 rounded-lg shadow-xl text-xs font-mono max-w-xs z-50">
          <div className="flex items-center justify-between border-b border-[#30363d] pb-1.5 mb-2">
            <span className="font-bold text-[#f0f6fc] flex items-center gap-1">
              <Clock className="w-3 h-3 text-[#58a6ff]" /> Hour {data.hourLabel} (24H Slot)
            </span>
            <span className={`text-[10px] px-1.5 py-0.2 rounded font-bold ${densityInfo.badge}`}>
              {data.intensity}% Load
            </span>
          </div>

          <div className="space-y-1 text-[#c9d1d9]">
            <div className="flex justify-between">
              <span className="text-[#8b949e]">Transferred:</span>
              <span className="font-bold text-[#58a6ff]">{data.bandwidthGb} GB</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#8b949e]">Average Flow Rate:</span>
              <span className="text-[#7ee787]">{data.avgMbps} Mbps</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#8b949e]">Peak 5-Min Burst:</span>
              <span className="text-[#f85149] font-bold">{data.peakMbps} Mbps</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#8b949e]">Active Flows:</span>
              <span>{data.activeFlows.toLocaleString()} concurrent</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#8b949e]">Top L7 Protocol:</span>
              <span className="text-[#d29922] font-sans font-medium">{data.topProtocol}</span>
            </div>

            {data.isPeak && data.peakLabel && (
              <div className="mt-2 pt-1.5 border-t border-[#30363d] text-[11px] text-[#f85149] flex items-start gap-1 font-sans">
                <Flame className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                <span><strong>Peak Event:</strong> {data.peakLabel}</span>
              </div>
            )}
          </div>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="bg-[#161b22] border border-[#30363d] rounded-lg p-4 space-y-4">
      {/* Header Banner */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-[#30363d] pb-3.5">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-[#1f6feb]/20 border border-[#1f6feb] text-[#58a6ff]">
            <Flame className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold text-[#f0f6fc]">
                24-Hour Traffic Density & Peak Period Heatmap
              </h3>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#238636]/20 text-[#7ee787] border border-[#238636]/50">
                Recharts Flow Matrix
              </span>
            </div>
            <p className="text-xs text-[#8b949e] mt-0.5">
              Diurnal hourly traffic distribution, bandwidth peaks, and day-of-week network load density matrix.
            </p>
          </div>
        </div>

        {/* View Mode & VLAN Selectors */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Segment filter */}
          <div className="flex items-center gap-1.5 bg-[#010409] border border-[#30363d] rounded px-2 py-1 text-xs">
            <Filter className="w-3.5 h-3.5 text-[#8b949e]" />
            <span className="text-[#8b949e] hidden sm:inline">Segment:</span>
            <select
              value={selectedVlan}
              onChange={(e) => setSelectedVlan(e.target.value)}
              aria-label="Filter network segment"
              className="bg-transparent text-xs text-[#c9d1d9] font-medium focus:outline-none cursor-pointer"
            >
              <option value="all">All Network Fabrics</option>
              <option value="vlan10">VLAN 10 • Corp Workstations</option>
              <option value="vlan30">VLAN 30 • Application Servers</option>
              <option value="vlan100">VLAN 100 • SAN Storage Fabric</option>
              <option value="vlan50">VLAN 50 • Isolated Guest Wi-Fi</option>
            </select>
          </div>

          {/* Chart visual toggle */}
          <div className="flex items-center bg-[#010409] border border-[#30363d] rounded p-0.5">
            <button
              onClick={() => setChartViewMode('density')}
              className={`px-2.5 py-1 rounded text-xs font-semibold transition ${
                chartViewMode === 'density'
                  ? 'bg-[#21262d] text-[#58a6ff] shadow-sm'
                  : 'text-[#8b949e] hover:text-[#c9d1d9]'
              }`}
            >
              Density Heat
            </button>
            <button
              onClick={() => setChartViewMode('stacked')}
              className={`px-2.5 py-1 rounded text-xs font-semibold transition ${
                chartViewMode === 'stacked'
                  ? 'bg-[#21262d] text-[#58a6ff] shadow-sm'
                  : 'text-[#8b949e] hover:text-[#c9d1d9]'
              }`}
            >
              VLAN Breakdown
            </button>
            <button
              onClick={() => setChartViewMode('peakCompare')}
              className={`px-2.5 py-1 rounded text-xs font-semibold transition ${
                chartViewMode === 'peakCompare'
                  ? 'bg-[#21262d] text-[#58a6ff] shadow-sm'
                  : 'text-[#8b949e] hover:text-[#c9d1d9]'
              }`}
            >
              Avg vs Peak Rate
            </button>
          </div>
        </div>
      </div>

      {/* Top 4 Quick KPI Summary Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="bg-[#010409] p-3 rounded-lg border border-[#30363d]">
          <span className="text-[10px] uppercase font-semibold text-[#8b949e] block">24-Hour Total Ingress/Egress</span>
          <div className="flex items-baseline gap-1 mt-1">
            <span className="text-xl font-bold font-mono text-[#58a6ff]">{totalDayGb}</span>
            <span className="text-xs text-[#8b949e]">GB / day</span>
          </div>
          <span className="text-[10px] text-[#7ee787] mt-1 block">Full 24-Hour Cycle</span>
        </div>

        <div className="bg-[#010409] p-3 rounded-lg border border-[#30363d]">
          <span className="text-[10px] uppercase font-semibold text-[#8b949e] block">Diurnal Max Burst</span>
          <div className="flex items-baseline gap-1 mt-1">
            <span className="text-xl font-bold font-mono text-[#f85149]">{maxPeakMbps}</span>
            <span className="text-xs text-[#8b949e]">Mbps</span>
          </div>
          <span className="text-[10px] text-[#8b949e] mt-1 block">Occurred at 10:00 AM</span>
        </div>

        <div className="bg-[#010409] p-3 rounded-lg border border-[#30363d]">
          <span className="text-[10px] uppercase font-semibold text-[#8b949e] block">24H Average Rate</span>
          <div className="flex items-baseline gap-1 mt-1">
            <span className="text-xl font-bold font-mono text-[#7ee787]">{avgMbpsOverall}</span>
            <span className="text-xs text-[#8b949e]">Mbps</span>
          </div>
          <span className="text-[10px] text-[#8b949e] mt-1 block">Baseline network load</span>
        </div>

        <div className="bg-[#010409] p-3 rounded-lg border border-[#30363d]">
          <span className="text-[10px] uppercase font-semibold text-[#8b949e] block">Identified Peak Windows</span>
          <div className="flex items-baseline gap-1 mt-1">
            <span className="text-xl font-bold font-mono text-[#d29922]">{peakHours.length}</span>
            <span className="text-xs text-[#8b949e]">surge windows</span>
          </div>
          <span className="text-[10px] text-[#d29922] mt-1 block">02:00-04:00 & 09:00-15:00</span>
        </div>
      </div>

      {/* Primary 24-Hour Recharts Visualizer */}
      <div className="bg-[#010409] border border-[#30363d] rounded-lg p-3.5 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#21262d] pb-2">
          <div className="flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-[#58a6ff]" />
            <h4 className="text-xs font-bold text-[#f0f6fc]">
              {chartViewMode === 'density' && 'Hourly Traffic Volume (GB) & Intensity Density Bar Spectrum'}
              {chartViewMode === 'stacked' && 'VLAN Segment Composition Across 24-Hour Timeline'}
              {chartViewMode === 'peakCompare' && 'Average Bandwidth vs 5-Minute Peak Burst Rate (Mbps)'}
            </h4>
          </div>
          <div className="flex items-center gap-3 text-[11px] font-mono">
            <span className="text-[#8b949e] flex items-center gap-1">
              <span className="w-2 h-2 rounded bg-[#da3633]" /> Peak (&gt;90%)
            </span>
            <span className="text-[#8b949e] flex items-center gap-1">
              <span className="w-2 h-2 rounded bg-[#d29922]" /> Heavy
            </span>
            <span className="text-[#8b949e] flex items-center gap-1">
              <span className="w-2 h-2 rounded bg-[#238636]" /> Moderate
            </span>
            <span className="text-[#8b949e] flex items-center gap-1">
              <span className="w-2 h-2 rounded bg-[#1f6feb]" /> Nominal
            </span>
          </div>
        </div>

        {/* Recharts Main Container */}
        <div className="h-64 w-full">
          <ResponsiveContainer width="100%" height="100%">
            {chartViewMode === 'density' ? (
              <BarChart data={hourlyData} margin={{ top: 10, right: 10, left: -15, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#21262d" vertical={false} />
                <XAxis 
                  dataKey="hourLabel" 
                  stroke="#8b949e" 
                  fontSize={10} 
                  tickLine={false} 
                  axisLine={{ stroke: '#30363d' }} 
                />
                <YAxis 
                  stroke="#8b949e" 
                  fontSize={10} 
                  tickLine={false} 
                  axisLine={{ stroke: '#30363d' }}
                  unit=" GB" 
                />
                <Tooltip content={<CustomChartTooltip />} />
                <ReferenceLine y={80} stroke="#da3633" strokeDasharray="4 4" label={{ value: 'Peak Threshold (80 GB)', fill: '#f85149', fontSize: 10, position: 'top' }} />
                <Bar 
                  dataKey="bandwidthGb" 
                  radius={[4, 4, 0, 0]}
                  onClick={(entry) => setActiveHour(entry)}
                >
                  {hourlyData.map((entry, index) => {
                    const color = getDensityColor(entry.intensity).bg;
                    return <Cell key={`cell-${index}`} fill={color} className="cursor-pointer hover:opacity-80 transition" />;
                  })}
                </Bar>
              </BarChart>
            ) : chartViewMode === 'stacked' ? (
              <BarChart data={hourlyData} margin={{ top: 10, right: 10, left: -15, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#21262d" vertical={false} />
                <XAxis dataKey="hourLabel" stroke="#8b949e" fontSize={10} tickLine={false} axisLine={{ stroke: '#30363d' }} />
                <YAxis stroke="#8b949e" fontSize={10} tickLine={false} axisLine={{ stroke: '#30363d' }} unit=" GB" />
                <Tooltip content={<CustomChartTooltip />} />
                <Legend wrapperStyle={{ fontSize: '11px', paddingTop: '6px' }} />
                <Bar dataKey="vlanVolume.corp" name="VLAN 10 (Corp)" stackId="a" fill="#58a6ff" />
                <Bar dataKey="vlanVolume.servers" name="VLAN 30 (Servers)" stackId="a" fill="#7ee787" />
                <Bar dataKey="vlanVolume.storage" name="VLAN 100 (SAN)" stackId="a" fill="#d29922" />
                <Bar dataKey="vlanVolume.voip" name="VLAN 20 (VoIP)" stackId="a" fill="#bc8cff" />
                <Bar dataKey="vlanVolume.guest" name="VLAN 50 (Guest)" stackId="a" fill="#f85149" />
              </BarChart>
            ) : (
              <ComposedChart data={hourlyData} margin={{ top: 10, right: 10, left: -15, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#21262d" vertical={false} />
                <XAxis dataKey="hourLabel" stroke="#8b949e" fontSize={10} tickLine={false} axisLine={{ stroke: '#30363d' }} />
                <YAxis stroke="#8b949e" fontSize={10} tickLine={false} axisLine={{ stroke: '#30363d' }} unit=" Mbps" />
                <Tooltip content={<CustomChartTooltip />} />
                <Legend wrapperStyle={{ fontSize: '11px', paddingTop: '6px' }} />
                <Area type="monotone" dataKey="avgMbps" name="Average Rate (Mbps)" fill="#238636" fillOpacity={0.25} stroke="#7ee787" strokeWidth={2} />
                <Line type="monotone" dataKey="peakMbps" name="5-Min Peak Burst (Mbps)" stroke="#f85149" strokeWidth={2} dot={{ r: 3, fill: '#da3633' }} activeDot={{ r: 6 }} />
                <ReferenceLine y={500} stroke="#da3633" strokeDasharray="4 4" label={{ value: 'Line Rate Cap (500M)', fill: '#f85149', fontSize: 10 }} />
              </ComposedChart>
            )}
          </ResponsiveContainer>
        </div>
      </div>

      {/* 7-Day Day-by-Hour Heatmap Density Matrix */}
      <div className="bg-[#010409] border border-[#30363d] rounded-lg p-3.5 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#21262d] pb-2">
          <div className="flex items-center gap-2">
            <Calendar className="w-4 h-4 text-[#7ee787]" />
            <h4 className="text-xs font-bold text-[#f0f6fc]">
              7-Day x 24-Hour Diurnal Heatmap Matrix (Hover & Click Cells to Inspect)
            </h4>
          </div>
          <span className="text-[11px] text-[#8b949e] font-mono">
            {hoveredCell 
              ? `${hoveredCell.day} @ ${hoveredCell.hour.toString().padStart(2, '0')}:00 -> ${hoveredCell.val}% Traffic Density` 
              : 'Hover cells to inspect load percentage'}
          </span>
        </div>

        {/* Heatmap Grid */}
        <div className="overflow-x-auto">
          <div className="min-w-[650px] space-y-1 select-none">
            {/* Hour header row */}
            <div className="grid grid-cols-[60px_repeat(24,1fr)] gap-1 text-[9px] text-[#8b949e] font-mono text-center pb-1">
              <span className="text-left font-sans">Day \ Hr</span>
              {Array.from({ length: 24 }).map((_, h) => (
                <span key={h}>{h % 3 === 0 ? `${h}h` : ''}</span>
              ))}
            </div>

            {/* Day rows */}
            {DAYS_OF_WEEK.map((d) => {
              const isSelected = selectedDay === d.day;
              return (
                <div 
                  key={d.day} 
                  className={`grid grid-cols-[60px_repeat(24,1fr)] gap-1 items-center p-1 rounded transition ${
                    isSelected ? 'bg-[#161b22] border border-[#58a6ff]/40' : 'hover:bg-[#161b22]/50'
                  }`}
                >
                  <button
                    onClick={() => setSelectedDay(d.day)}
                    className="text-[11px] font-semibold text-left text-[#c9d1d9] hover:text-[#58a6ff] transition font-mono"
                  >
                    {d.dayShort}
                  </button>

                  {d.hours.map((val, h) => {
                    const color = getDensityColor(val);
                    return (
                      <div
                        key={h}
                        onMouseEnter={() => setHoveredCell({ day: d.day, hour: h, val })}
                        onMouseLeave={() => setHoveredCell(null)}
                        onClick={() => {
                          setSelectedDay(d.day);
                          const matching = hourlyData[h];
                          if (matching) setActiveHour(matching);
                        }}
                        className="h-6 rounded cursor-pointer transition-all duration-150 transform hover:scale-125 hover:z-20 hover:ring-2 hover:ring-white relative group"
                        style={{ backgroundColor: color.bg }}
                        title={`${d.day} ${h}:00 - ${val}% density`}
                      />
                    );
                  })}
                </div>
              );
            })}
          </div>
        </div>

        {/* Legend bar */}
        <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-[#21262d] text-[11px] text-[#8b949e]">
          <div className="flex items-center gap-2 font-mono text-[10px]">
            <span>Low Intensity</span>
            <div className="flex items-center gap-1">
              <span className="w-3.5 h-3.5 rounded bg-[#21262d]" title="<25%" />
              <span className="w-3.5 h-3.5 rounded bg-[#1f6feb]" title="25-50%" />
              <span className="w-3.5 h-3.5 rounded bg-[#238636]" title="50-75%" />
              <span className="w-3.5 h-3.5 rounded bg-[#d29922]" title="75-90%" />
              <span className="w-3.5 h-3.5 rounded bg-[#da3633]" title=">90%" />
            </div>
            <span>High Intensity Surge</span>
          </div>

          <div className="text-[11px] text-[#8b949e]">
            Peak periods recurring on weekdays between <strong>09:00 - 11:00</strong> and <strong>14:00 - 15:30</strong>
          </div>
        </div>
      </div>

      {/* Detail Drilldown Panel for Selected Hour */}
      {activeHour && (
        <div className="bg-[#010409] border border-[#58a6ff]/50 rounded-lg p-3.5 animate-in fade-in space-y-3">
          <div className="flex items-center justify-between border-b border-[#30363d] pb-2">
            <div className="flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-[#58a6ff]" />
              <h4 className="text-xs font-bold text-[#f0f6fc]">
                Hourly Deep Inspection: {activeHour.hourLabel} Window
              </h4>
              {activeHour.isPeak && (
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-[#da3633]/20 text-[#f85149] border border-[#da3633]/40 flex items-center gap-1">
                  <Flame className="w-3 h-3" /> Peak Period
                </span>
              )}
            </div>
            <button
              onClick={() => setActiveHour(null)}
              className="text-xs text-[#8b949e] hover:text-[#c9d1d9] font-mono px-2 py-0.5 rounded bg-[#21262d]"
            >
              Close Drilldown
            </button>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-5 gap-2.5 text-xs">
            <div className="bg-[#161b22] p-2.5 rounded border border-[#30363d]">
              <span className="text-[10px] text-[#8b949e] block">Transferred Bandwidth</span>
              <span className="text-sm font-bold font-mono text-[#58a6ff]">{activeHour.bandwidthGb} GB</span>
            </div>
            <div className="bg-[#161b22] p-2.5 rounded border border-[#30363d]">
              <span className="text-[10px] text-[#8b949e] block">Average Throughput</span>
              <span className="text-sm font-bold font-mono text-[#7ee787]">{activeHour.avgMbps} Mbps</span>
            </div>
            <div className="bg-[#161b22] p-2.5 rounded border border-[#30363d]">
              <span className="text-[10px] text-[#8b949e] block">Peak 5-Min Burst</span>
              <span className="text-sm font-bold font-mono text-[#f85149]">{activeHour.peakMbps} Mbps</span>
            </div>
            <div className="bg-[#161b22] p-2.5 rounded border border-[#30363d]">
              <span className="text-[10px] text-[#8b949e] block">Flow Concurrency</span>
              <span className="text-sm font-bold font-mono text-[#f0f6fc]">{activeHour.activeFlows.toLocaleString()}</span>
            </div>
            <div className="bg-[#161b22] p-2.5 rounded border border-[#30363d]">
              <span className="text-[10px] text-[#8b949e] block">Dominant Traffic</span>
              <span className="text-sm font-bold text-[#d29922] truncate block">{activeHour.topProtocol}</span>
            </div>
          </div>

          {activeHour.peakLabel && (
            <div className="bg-[#da3633]/10 border border-[#da3633]/30 rounded p-2.5 text-xs text-[#c9d1d9] flex items-center gap-2">
              <AlertCircle className="w-4 h-4 text-[#f85149] shrink-0" />
              <div>
                <strong className="text-[#f85149]">Operational Context:</strong> {activeHour.peakLabel}. Automated bandwidth throttling and QoS queuing active during this window.
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
