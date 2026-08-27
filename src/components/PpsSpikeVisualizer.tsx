import React, { useState, useEffect, useRef } from 'react';
import { 
  Zap, TrendingUp, AlertTriangle, Play, Pause, 
  RotateCcw, ShieldAlert, Sparkles, Gauge, ArrowUpRight,
  Flame, Radio, CheckCircle2, ChevronRight
} from 'lucide-react';

interface PpsDataPoint {
  id: number;
  timestamp: string;
  timeLabel: string;
  totalPps: number;
  tcpPps: number;
  udpPps: number;
  icmpPps: number;
  isSpike: boolean;
  spikeReason?: string;
}

interface SpikeEvent {
  id: string;
  timestamp: string;
  peakPps: number;
  durationSec: number;
  type: string;
  vlan: number;
  status: 'Mitigated' | 'Active' | 'Logged';
}

interface PpsSpikeVisualizerProps {
  onSpikeDetected?: (event: SpikeEvent) => void;
}

export const PpsSpikeVisualizer: React.FC<PpsSpikeVisualizerProps> = ({ onSpikeDetected }) => {
  const [isRunning, setIsRunning] = useState(true);
  const [threshold, setThreshold] = useState<number>(2200);
  const [history, setHistory] = useState<PpsDataPoint[]>(() => {
    // Generate initial 25 data points
    const now = Date.now();
    const initial: PpsDataPoint[] = [];
    for (let i = 24; i >= 0; i--) {
      const t = new Date(now - i * 1000);
      const base = 420 + Math.floor(Math.sin(i / 3) * 120) + Math.floor(Math.random() * 80);
      const tcp = Math.floor(base * 0.65);
      const udp = Math.floor(base * 0.30);
      const icmp = base - tcp - udp;
      initial.push({
        id: now - i * 1000,
        timestamp: t.toLocaleTimeString(),
        timeLabel: `${t.getMinutes()}:${t.getSeconds().toString().padStart(2, '0')}`,
        totalPps: base,
        tcpPps: tcp,
        udpPps: udp,
        icmpPps: icmp,
        isSpike: false
      });
    }
    return initial;
  });

  const [spikeLog, setSpikeLog] = useState<SpikeEvent[]>([
    {
      id: 'spk-01',
      timestamp: '08:14:22',
      peakPps: 4850,
      durationSec: 3.2,
      type: 'VLAN 50 ARP Discovery Flood',
      vlan: 50,
      status: 'Mitigated'
    },
    {
      id: 'spk-02',
      timestamp: '08:02:11',
      peakPps: 3420,
      durationSec: 1.8,
      type: 'TCP SYN Ingress Sweep (Port 22/80)',
      vlan: 10,
      status: 'Logged'
    }
  ]);

  const [hoveredPoint, setHoveredPoint] = useState<PpsDataPoint | null>(null);
  const nextSpikeTrigger = useRef<'flood' | 'burst' | null>(null);

  // Latest stats
  const currentPoint = history[history.length - 1] || { totalPps: 0, tcpPps: 0, udpPps: 0, icmpPps: 0 };
  const currentPps = currentPoint.totalPps;
  
  const peakPps = Math.max(...history.map(d => d.totalPps), 0);
  const avgPps = Math.round(history.reduce((sum, d) => sum + d.totalPps, 0) / (history.length || 1));
  
  // Delta vs previous point
  const prevPps = history.length > 1 ? history[history.length - 2].totalPps : currentPps;
  const ppsDelta = prevPps > 0 ? Math.round(((currentPps - prevPps) / prevPps) * 100) : 0;
  const isSpikeActive = currentPps >= threshold;

  // Real-time ticking effect
  useEffect(() => {
    if (!isRunning) return;

    const interval = setInterval(() => {
      setHistory(prev => {
        const now = new Date();
        const timeLabel = `${now.getMinutes()}:${now.getSeconds().toString().padStart(2, '0')}`;
        
        let newTotal = 0;
        let spike = false;
        let spikeReason = undefined;

        if (nextSpikeTrigger.current === 'flood') {
          // Injected malicious flood spike: 4200 - 5800 PPS
          newTotal = 4200 + Math.floor(Math.random() * 1600);
          spike = true;
          spikeReason = 'Simulated Layer-2 Broadcast Storm / SYN Flood';
          nextSpikeTrigger.current = null;

          const newSpikeEvent: SpikeEvent = {
            id: `spk-${Date.now()}`,
            timestamp: now.toLocaleTimeString(),
            peakPps: newTotal,
            durationSec: 2.5,
            type: 'Interactive Injected Broadcast Flood',
            vlan: 50,
            status: 'Active'
          };
          setSpikeLog(log => [newSpikeEvent, ...log.slice(0, 7)]);
          if (onSpikeDetected) onSpikeDetected(newSpikeEvent);

        } else if (nextSpikeTrigger.current === 'burst') {
          // High load burst: 1800 - 2400 PPS
          newTotal = 1800 + Math.floor(Math.random() * 600);
          spike = newTotal >= threshold;
          spikeReason = 'High-Volume File Sync / RTSP Camera Burst';
          nextSpikeTrigger.current = null;
        } else {
          // Normal stochastic network noise: 400 - 950 PPS
          const baseline = 520 + Math.floor(Math.sin(Date.now() / 4000) * 160);
          const jitter = Math.floor((Math.random() - 0.45) * 140);
          newTotal = Math.max(120, baseline + jitter);
          spike = newTotal >= threshold;
        }

        const tcp = Math.floor(newTotal * (0.60 + Math.random() * 0.15));
        const udp = Math.floor((newTotal - tcp) * (0.75 + Math.random() * 0.15));
        const icmp = Math.max(0, newTotal - tcp - udp);

        const newPoint: PpsDataPoint = {
          id: Date.now(),
          timestamp: now.toLocaleTimeString(),
          timeLabel,
          totalPps: newTotal,
          tcpPps: tcp,
          udpPps: udp,
          icmpPps: icmp,
          isSpike: spike,
          spikeReason
        };

        // Maintain rolling window of 30 seconds
        const updated = [...prev.slice(1), newPoint];
        return updated;
      });
    }, 1000);

    return () => clearInterval(interval);
  }, [isRunning, threshold, onSpikeDetected]);

  // SVG dimensions
  const svgWidth = 800;
  const svgHeight = 160;
  const paddingLeft = 45;
  const paddingRight = 15;
  const paddingTop = 15;
  const paddingBottom = 25;

  const chartWidth = svgWidth - paddingLeft - paddingRight;
  const chartHeight = svgHeight - paddingTop - paddingBottom;

  const maxVal = Math.max(peakPps * 1.15, threshold * 1.25, 3000);

  // Generate SVG path points
  const points = history.map((d, idx) => {
    const x = paddingLeft + (idx / Math.max(history.length - 1, 1)) * chartWidth;
    const y = paddingTop + chartHeight - (d.totalPps / maxVal) * chartHeight;
    return { x, y, data: d };
  });

  const pathD = points.length > 0
    ? points.reduce((acc, p, i) => `${acc} ${i === 0 ? 'M' : 'L'} ${p.x},${p.y}`, '')
    : '';

  const areaD = points.length > 0
    ? `${pathD} L ${points[points.length - 1].x},${paddingTop + chartHeight} L ${points[0].x},${paddingTop + chartHeight} Z`
    : '';

  const thresholdY = paddingTop + chartHeight - (threshold / maxVal) * chartHeight;

  const triggerSpike = (type: 'flood' | 'burst') => {
    nextSpikeTrigger.current = type;
    if (!isRunning) setIsRunning(true);
  };

  const handleReset = () => {
    setHistory(prev => prev.map(p => ({ ...p, totalPps: 450 + Math.floor(Math.random() * 100), isSpike: false })));
  };

  return (
    <div className="bg-[#161b22] border border-[#30363d] rounded-lg p-4 space-y-4">
      {/* Top Banner & Primary Stats */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-[#30363d] pb-3.5">
        <div className="flex items-center gap-3">
          <div className={`p-2.5 rounded-lg border transition-all ${
            isSpikeActive 
              ? 'bg-[#da3633]/20 border-[#da3633] text-[#f85149] animate-pulse' 
              : currentPps > 1500
              ? 'bg-[#d29922]/20 border-[#d29922] text-[#d29922]'
              : 'bg-[#238636]/20 border-[#238636] text-[#7ee787]'
          }`}>
            {isSpikeActive ? <Flame className="w-5 h-5" /> : <Zap className="w-5 h-5" />}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold text-[#f0f6fc]">
                Real-Time Packet Rate (PPS) & Traffic Spike Detector
              </h3>
              <span className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#010409] text-[#58a6ff] border border-[#30363d]">
                <Radio className={`w-3 h-3 ${isRunning ? 'text-[#7ee787] animate-pulse' : 'text-[#8b949e]'}`} />
                {isRunning ? '1.0s Live Ticker' : 'Stream Paused'}
              </span>
            </div>
            <p className="text-xs text-[#8b949e] mt-0.5">
              Continuous L2/L3 packet frequency counter with automated delta threshold triggering and spike telemetry.
            </p>
          </div>
        </div>

        {/* Live Controls */}
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => setIsRunning(!isRunning)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-semibold border transition active:scale-95 ${
              isRunning
                ? 'bg-[#010409] hover:bg-[#21262d] text-[#c9d1d9] border-[#30363d]'
                : 'bg-[#238636] hover:bg-[#2ea043] text-white border-[#238636]'
            }`}
          >
            {isRunning ? <Pause className="w-3.5 h-3.5 text-[#d29922]" /> : <Play className="w-3.5 h-3.5" />}
            <span>{isRunning ? 'Pause Feed' : 'Resume Live'}</span>
          </button>

          <button
            type="button"
            onClick={() => triggerSpike('flood')}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#da3633]/20 hover:bg-[#da3633]/30 text-[#f85149] text-xs font-semibold border border-[#da3633]/50 transition active:scale-95 shadow-sm"
            title="Inject a high-intensity flood spike (4,500+ PPS)"
          >
            <Flame className="w-3.5 h-3.5" />
            <span>Inject Flood Spike</span>
          </button>

          <button
            type="button"
            onClick={() => triggerSpike('burst')}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded bg-[#21262d] hover:bg-[#30363d] text-[#58a6ff] text-xs font-medium border border-[#30363d] transition active:scale-95"
            title="Simulate a media burst (2,000 PPS)"
          >
            <ArrowUpRight className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Traffic Burst</span>
          </button>

          <button
            type="button"
            onClick={handleReset}
            className="p-1.5 rounded bg-[#010409] hover:bg-[#21262d] text-[#8b949e] hover:text-[#c9d1d9] border border-[#30363d] transition"
            title="Reset telemetry trace"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* KPI Cards Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {/* Instant PPS */}
        <div className="bg-[#010409] p-3 rounded-lg border border-[#30363d] relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-[10px] uppercase font-semibold text-[#8b949e]">Instantaneous Rate</span>
            <span className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded ${
              ppsDelta > 40 ? 'bg-[#da3633]/20 text-[#f85149]' : ppsDelta > 0 ? 'bg-[#238636]/20 text-[#7ee787]' : 'bg-[#21262d] text-[#8b949e]'
            }`}>
              {ppsDelta > 0 ? `+${ppsDelta}%` : `${ppsDelta}%`}
            </span>
          </div>
          <div className="flex items-baseline gap-1.5 mt-1.5">
            <span className={`text-2xl font-black font-mono tracking-tight transition-colors ${
              isSpikeActive ? 'text-[#f85149]' : currentPps > 1500 ? 'text-[#d29922]' : 'text-[#7ee787]'
            }`}>
              {currentPps.toLocaleString()}
            </span>
            <span className="text-xs text-[#8b949e] font-sans">pkts / sec</span>
          </div>
          <div className="text-[10px] text-[#8b949e] mt-1 flex items-center justify-between">
            <span>TCP: {currentPoint.tcpPps}</span>
            <span>UDP: {currentPoint.udpPps}</span>
            <span>ICMP: {currentPoint.icmpPps}</span>
          </div>
        </div>

        {/* Peak PPS */}
        <div className="bg-[#010409] p-3 rounded-lg border border-[#30363d]">
          <span className="text-[10px] uppercase font-semibold text-[#8b949e] block">Session Peak PPS</span>
          <div className="flex items-baseline gap-1.5 mt-1.5">
            <span className="text-2xl font-black font-mono text-[#f0f6fc] tracking-tight">
              {peakPps.toLocaleString()}
            </span>
            <span className="text-xs text-[#8b949e]">pkts / sec</span>
          </div>
          <div className="text-[10px] text-[#8b949e] mt-1">
            {peakPps >= threshold ? (
              <span className="text-[#f85149] font-medium flex items-center gap-1">
                <AlertTriangle className="w-3 h-3" /> Exceeded {threshold} PPS
              </span>
            ) : (
              <span className="text-[#7ee787]">Within normal limits</span>
            )}
          </div>
        </div>

        {/* Moving Average */}
        <div className="bg-[#010409] p-3 rounded-lg border border-[#30363d]">
          <span className="text-[10px] uppercase font-semibold text-[#8b949e] block">30s Moving Average</span>
          <div className="flex items-baseline gap-1.5 mt-1.5">
            <span className="text-2xl font-black font-mono text-[#58a6ff] tracking-tight">
              {avgPps.toLocaleString()}
            </span>
            <span className="text-xs text-[#8b949e]">pkts / sec</span>
          </div>
          <div className="text-[10px] text-[#8b949e] mt-1">
            Baseline nominal traffic
          </div>
        </div>

        {/* Spike Threshold Configuration */}
        <div className="bg-[#010409] p-3 rounded-lg border border-[#30363d] flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-[10px] uppercase font-semibold text-[#8b949e]">Spike Alert Threshold</span>
            <span className="text-xs font-mono font-bold text-[#d29922]">{threshold} PPS</span>
          </div>
          <div className="mt-2">
            <input
              type="range"
              min="1000"
              max="4000"
              step="200"
              value={threshold}
              onChange={(e) => setThreshold(Number(e.target.value))}
              className="w-full h-1.5 bg-[#21262d] rounded-lg appearance-none cursor-pointer accent-[#58a6ff]"
            />
          </div>
          <div className="flex justify-between text-[9px] text-[#8b949e] font-mono mt-1">
            <span>1,000</span>
            <span>2,500</span>
            <span>4,000</span>
          </div>
        </div>
      </div>

      {/* Real-time Waveform Chart (SVG) */}
      <div className="bg-[#010409] border border-[#30363d] rounded-lg p-3.5 relative">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-2">
            <TrendingUp className="w-3.5 h-3.5 text-[#58a6ff]" />
            <span className="text-xs font-semibold text-[#f0f6fc]">Rolling 30-Second Packet Velocity Waveform</span>
          </div>
          <div className="flex items-center gap-3 text-[11px]">
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-[#7ee787]" />
              <span className="text-[#8b949e]">Live PPS Flow</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-3 h-0.5 border-t border-dashed border-[#da3633]" />
              <span className="text-[#8b949e]">Alert Threshold ({threshold})</span>
            </div>
          </div>
        </div>

        {/* Responsive SVG Chart */}
        <div className="w-full overflow-hidden">
          <svg 
            viewBox={`0 0 ${svgWidth} ${svgHeight}`} 
            className="w-full h-44 select-none"
          >
            <defs>
              <linearGradient id="ppsAreaGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={isSpikeActive ? '#da3633' : '#238636'} stopOpacity="0.45" />
                <stop offset="60%" stopColor="#58a6ff" stopOpacity="0.15" />
                <stop offset="100%" stopColor="#010409" stopOpacity="0.0" />
              </linearGradient>
            </defs>

            {/* Horizontal Grid lines */}
            {[0.25, 0.5, 0.75, 1].map((factor, i) => {
              const y = paddingTop + chartHeight - factor * chartHeight;
              const val = Math.round(maxVal * factor);
              return (
                <g key={i}>
                  <line 
                    x1={paddingLeft} 
                    y1={y} 
                    x2={svgWidth - paddingRight} 
                    y2={y} 
                    stroke="#21262d" 
                    strokeDasharray="3,3" 
                  />
                  <text 
                    x={paddingLeft - 6} 
                    y={y + 3} 
                    textAnchor="end" 
                    fill="#8b949e" 
                    fontSize="9" 
                    fontFamily="monospace"
                  >
                    {val}
                  </text>
                </g>
              );
            })}

            {/* Threshold line */}
            <line 
              x1={paddingLeft} 
              y1={thresholdY} 
              x2={svgWidth - paddingRight} 
              y2={thresholdY} 
              stroke="#da3633" 
              strokeWidth="1.5" 
              strokeDasharray="4,4" 
            />
            <text 
              x={svgWidth - paddingRight - 4} 
              y={thresholdY - 4} 
              textAnchor="end" 
              fill="#f85149" 
              fontSize="9" 
              fontFamily="monospace"
              fontWeight="bold"
            >
              TRIGGER {threshold} PPS
            </text>

            {/* Area Fill */}
            <path d={areaD} fill="url(#ppsAreaGrad)" />

            {/* Main Trace Line */}
            <path 
              d={pathD} 
              fill="none" 
              stroke={isSpikeActive ? '#f85149' : '#7ee787'} 
              strokeWidth="2.5" 
              strokeLinecap="round" 
              strokeLinejoin="round" 
            />

            {/* Data Point Circles */}
            {points.map((p, idx) => {
              const isOver = p.data.totalPps >= threshold;
              const isLatest = idx === points.length - 1;
              return (
                <g key={p.data.id}>
                  {/* Outer pulse ring for latest or spike */}
                  {(isLatest || isOver) && (
                    <circle 
                      cx={p.x} 
                      y={p.y} 
                      r={isOver ? 7 : 5} 
                      fill={isOver ? '#da3633' : '#7ee787'} 
                      opacity="0.3" 
                      className="animate-ping" 
                    />
                  )}
                  <circle
                    cx={p.x}
                    y={p.y}
                    r={isLatest ? 4.5 : isOver ? 4 : 2}
                    fill={isOver ? '#f85149' : isLatest ? '#7ee787' : '#58a6ff'}
                    stroke="#010409"
                    strokeWidth="1.5"
                    className="cursor-pointer transition-transform hover:scale-150"
                    onMouseEnter={() => setHoveredPoint(p.data)}
                    onMouseLeave={() => setHoveredPoint(null)}
                  />
                </g>
              );
            })}

            {/* Time labels on bottom axis */}
            {points.filter((_, i) => i % 5 === 0 || i === points.length - 1).map((p, idx) => (
              <text 
                key={idx} 
                x={p.x} 
                y={svgHeight - 6} 
                textAnchor="middle" 
                fill="#8b949e" 
                fontSize="9" 
                fontFamily="monospace"
              >
                {p.data.timeLabel}
              </text>
            ))}
          </svg>
        </div>

        {/* Hover Tooltip Overlay */}
        {hoveredPoint && (
          <div className="absolute top-4 left-14 bg-[#161b22] border border-[#30363d] shadow-lg rounded px-3 py-2 text-xs font-mono z-20 pointer-events-none animate-in fade-in">
            <div className="text-[#f0f6fc] font-bold flex items-center gap-1.5">
              <span>{hoveredPoint.timestamp}</span>
              <span className={`px-1.5 py-0.2 rounded text-[10px] ${hoveredPoint.totalPps >= threshold ? 'bg-[#da3633] text-white' : 'bg-[#238636] text-white'}`}>
                {hoveredPoint.totalPps} PPS
              </span>
            </div>
            <div className="text-[11px] text-[#8b949e] mt-1 space-y-0.5">
              <div>TCP Packets: <span className="text-[#58a6ff]">{hoveredPoint.tcpPps} pkts/s</span></div>
              <div>UDP Packets: <span className="text-[#7ee787]">{hoveredPoint.udpPps} pkts/s</span></div>
              <div>ICMP / Raw: <span className="text-[#d29922]">{hoveredPoint.icmpPps} pkts/s</span></div>
              {hoveredPoint.spikeReason && (
                <div className="text-[#f85149] font-sans font-medium text-[10px] mt-1 pt-1 border-t border-[#30363d]">
                  {hoveredPoint.spikeReason}
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Protocol Bandwidth Distribution & Spike Audit History */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-3.5">
        {/* Real-time Protocol Composition */}
        <div className="lg:col-span-5 bg-[#010409] p-3 rounded-lg border border-[#30363d] space-y-2.5">
          <div className="flex items-center justify-between text-xs font-semibold text-[#f0f6fc]">
            <span>Layer 4 Protocol Velocity Breakdown</span>
            <span className="text-[10px] text-[#8b949e] font-mono">{currentPps} Total PPS</span>
          </div>

          <div className="w-full h-2.5 bg-[#21262d] rounded-full overflow-hidden flex">
            <div 
              className="bg-[#58a6ff] h-full transition-all duration-300"
              style={{ width: `${currentPps > 0 ? (currentPoint.tcpPps / currentPps) * 100 : 0}%` }}
              title="TCP Traffic"
            />
            <div 
              className="bg-[#7ee787] h-full transition-all duration-300"
              style={{ width: `${currentPps > 0 ? (currentPoint.udpPps / currentPps) * 100 : 0}%` }}
              title="UDP Traffic"
            />
            <div 
              className="bg-[#d29922] h-full transition-all duration-300"
              style={{ width: `${currentPps > 0 ? (currentPoint.icmpPps / currentPps) * 100 : 0}%` }}
              title="ICMP / Other"
            />
          </div>

          <div className="grid grid-cols-3 gap-2 text-xs">
            <div className="bg-[#161b22] p-2 rounded border border-[#30363d]">
              <span className="text-[10px] text-[#58a6ff] font-semibold block">TCP Streams</span>
              <span className="text-sm font-bold font-mono text-[#f0f6fc]">{currentPoint.tcpPps}</span>
              <span className="text-[10px] text-[#8b949e] block font-mono">
                {currentPps > 0 ? Math.round((currentPoint.tcpPps / currentPps) * 100) : 0}%
              </span>
            </div>

            <div className="bg-[#161b22] p-2 rounded border border-[#30363d]">
              <span className="text-[10px] text-[#7ee787] font-semibold block">UDP Datagrams</span>
              <span className="text-sm font-bold font-mono text-[#f0f6fc]">{currentPoint.udpPps}</span>
              <span className="text-[10px] text-[#8b949e] block font-mono">
                {currentPps > 0 ? Math.round((currentPoint.udpPps / currentPps) * 100) : 0}%
              </span>
            </div>

            <div className="bg-[#161b22] p-2 rounded border border-[#30363d]">
              <span className="text-[10px] text-[#d29922] font-semibold block">ICMP / Probes</span>
              <span className="text-sm font-bold font-mono text-[#f0f6fc]">{currentPoint.icmpPps}</span>
              <span className="text-[10px] text-[#8b949e] block font-mono">
                {currentPps > 0 ? Math.round((currentPoint.icmpPps / currentPps) * 100) : 0}%
              </span>
            </div>
          </div>
        </div>

        {/* Spike Event Audit Ticker */}
        <div className="lg:col-span-7 bg-[#010409] p-3 rounded-lg border border-[#30363d] space-y-2">
          <div className="flex items-center justify-between text-xs font-semibold text-[#f0f6fc]">
            <span className="flex items-center gap-1.5">
              <ShieldAlert className="w-3.5 h-3.5 text-[#f85149]" />
              Recent Traffic Spikes & Storm Events
            </span>
            <span className="text-[10px] text-[#8b949e] font-mono">{spikeLog.length} Recorded</span>
          </div>

          <div className="space-y-1.5 max-h-32 overflow-y-auto pr-1">
            {spikeLog.map(spike => (
              <div 
                key={spike.id} 
                className="flex items-center justify-between bg-[#161b22] p-2 rounded border border-[#30363d] text-xs hover:border-[#58a6ff]/50 transition"
              >
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-mono text-[#8b949e]">{spike.timestamp}</span>
                  <span className="font-semibold text-[#f0f6fc] text-xs">{spike.type}</span>
                  <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-[#010409] text-[#58a6ff] border border-[#30363d]">
                    VLAN {spike.vlan}
                  </span>
                </div>

                <div className="flex items-center gap-2.5 font-mono">
                  <span className="text-[#f85149] font-bold text-xs">
                    {spike.peakPps.toLocaleString()} PPS
                  </span>
                  <span className={`text-[10px] px-1.5 py-0.5 rounded font-sans font-medium ${
                    spike.status === 'Active' 
                      ? 'bg-[#da3633]/20 text-[#f85149] border border-[#da3633]/40 animate-pulse'
                      : 'bg-[#238636]/20 text-[#7ee787] border border-[#238636]/40'
                  }`}>
                    {spike.status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
