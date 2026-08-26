import React, { useState, useEffect } from 'react';
import { SAMPLE_STORM_METRICS, SAMPLE_STORM_NODES } from '../data/telemetryData';
import { StormMetric, StormNodeActivity } from '../types';
import { 
  Zap, AlertTriangle, ShieldCheck, ShieldAlert, Radio,
  Activity, Play, Pause, RefreshCw, Layers, Server, Flame, Sparkles
} from 'lucide-react';

export const StormDetector: React.FC = () => {
  const [metrics, setMetrics] = useState<StormMetric[]>(SAMPLE_STORM_METRICS);
  const [nodes, setNodes] = useState<StormNodeActivity[]>(SAMPLE_STORM_NODES);
  const [isSimulatingStorm, setIsSimulatingStorm] = useState(false);
  const [stormType, setStormType] = useState<'none' | 'arp' | 'stp_loop'>('none');
  const [isMitigated, setIsMitigated] = useState(false);
  const [thresholdPps, setThresholdPps] = useState<number>(250);

  // Latest metric
  const currentMetric = metrics[metrics.length - 1];
  const isStormActive = currentMetric.broadcastPps + currentMetric.multicastPps > thresholdPps && !isMitigated;

  const handleTriggerArpStorm = () => {
    setIsSimulatingStorm(true);
    setStormType('arp');
    setIsMitigated(false);

    // Update nodes
    setNodes(prev => prev.map(n => {
      if (n.ip === '192.168.50.120') {
        return { ...n, broadcastPps: 840, multicastPps: 120, stormStatus: 'Flooding', packetRingSize: 95 };
      }
      if (n.ip === '192.168.10.10') {
        return { ...n, broadcastPps: 450, stormStatus: 'Flooding', packetRingSize: 70 };
      }
      return { ...n, packetRingSize: Math.min(60, n.packetRingSize + 15) };
    }));

    // Update metrics
    const newMetric: StormMetric = {
      timestamp: new Date().toLocaleTimeString(),
      broadcastPps: 890,
      multicastPps: 340,
      unicastPps: 3100,
      totalBandwidthKbps: 8400,
      status: 'Critical Storm',
      topEmitterIp: '192.168.50.120',
      protocolType: 'ARP Who-has Sweep Flood'
    };
    setMetrics(prev => [...prev.slice(1), newMetric]);
  };

  const handleTriggerStpLoop = () => {
    setIsSimulatingStorm(true);
    setStormType('stp_loop');
    setIsMitigated(false);

    setNodes(prev => prev.map(n => {
      if (n.ip === '192.168.1.2') {
        return { ...n, broadcastPps: 620, dominantProtocol: 'STP BPDU', stormStatus: 'Loop Detected', packetRingSize: 90 };
      }
      return { ...n, broadcastPps: n.broadcastPps + 150, stormStatus: 'Flooding', packetRingSize: 75 };
    }));

    const newMetric: StormMetric = {
      timestamp: new Date().toLocaleTimeString(),
      broadcastPps: 1120,
      multicastPps: 580,
      unicastPps: 4200,
      totalBandwidthKbps: 12400,
      status: 'Critical Storm',
      topEmitterIp: '192.168.1.2',
      protocolType: 'STP Bridging Loop (Topology Change BPDU)'
    };
    setMetrics(prev => [...prev.slice(1), newMetric]);
  };

  const handleApplyMitigation = () => {
    setIsMitigated(true);
    setStormType('none');

    setNodes(prev => prev.map(n => ({
      ...n,
      broadcastPps: Math.min(25, n.broadcastPps),
      multicastPps: Math.min(40, n.multicastPps),
      stormStatus: 'Suppressed',
      packetRingSize: 28
    })));

    const calmedMetric: StormMetric = {
      timestamp: new Date().toLocaleTimeString(),
      broadcastPps: 18,
      multicastPps: 32,
      unicastPps: 1200,
      totalBandwidthKbps: 450,
      status: 'Normal'
    };
    setMetrics(prev => [...prev.slice(1), calmedMetric]);
  };

  return (
    <div className="space-y-4">
      {/* Intro Header referencing EtherApe & Auvik */}
      <div className="bg-[#161b22] border border-[#30363d] p-4 rounded flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded bg-[#da3633] text-white flex items-center justify-center font-bold text-xs shadow-sm">
              <Zap className="w-3.5 h-3.5" />
            </div>
            <h2 className="text-sm font-bold text-[#f0f6fc]">
              Broadcast Storm & Layer 2 Loop Watchdog
            </h2>
          </div>
          <p className="text-xs text-[#8b949e] mt-1 max-w-3xl leading-relaxed">
            Real-time broadcast/multicast PPS rate-limiting and Spanning Tree bridging loop detection inspired by <strong>EtherApe</strong> packet flow ring dynamics and <strong>Auvik</strong> storm mitigation telemetry.
          </p>
        </div>

        {/* Simulation Action Buttons */}
        <div className="flex flex-wrap items-center gap-2">
          {!isStormActive ? (
            <>
              <button
                onClick={handleTriggerArpStorm}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#da3633]/20 hover:bg-[#da3633]/30 text-[#f85149] text-xs font-semibold border border-[#da3633]/40 transition"
              >
                <Flame className="w-3.5 h-3.5" /> Trigger ARP Storm
              </button>
              <button
                onClick={handleTriggerStpLoop}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#d29922]/20 hover:bg-[#d29922]/30 text-[#d29922] text-xs font-semibold border border-[#d29922]/40 transition"
              >
                <AlertTriangle className="w-3.5 h-3.5" /> Simulate STP Loop
              </button>
            </>
          ) : (
            <button
              onClick={handleApplyMitigation}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded bg-[#238636] hover:bg-[#2ea043] text-white text-xs font-semibold shadow-sm transition animate-pulse"
            >
              <ShieldCheck className="w-3.5 h-3.5" /> Engage Storm Control (Mitigate)
            </button>
          )}
        </div>
      </div>

      {/* Storm Status Banner */}
      <div className={`p-3.5 rounded border flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${
        isStormActive 
          ? 'bg-[#da3633]/15 border-[#da3633]/50 text-[#f85149]' 
          : 'bg-[#161b22] border-[#30363d] text-[#7ee787]'
      }`}>
        <div className="flex items-center gap-2.5">
          {isStormActive ? (
            <ShieldAlert className="w-5 h-5 text-[#f85149] animate-bounce" />
          ) : (
            <ShieldCheck className="w-5 h-5 text-[#7ee787]" />
          )}
          <div>
            <h3 className="text-xs font-bold font-mono uppercase tracking-wider">
              {isStormActive ? `CRITICAL STORM ALERT: ${currentMetric.protocolType || 'Broadcast Flood'}` : 'LAYER 2 TRAFFIC NORMAL: No Loops or Storms Detected'}
            </h3>
            <span className="text-[11px] text-[#8b949e]">
              {isStormActive 
                ? `Egress rate from ${currentMetric.topEmitterIp} has overwhelmed threshold (${thresholdPps} PPS). Packet drops occurring on access ports.`
                : `Current Aggregate Broadcast & Multicast rate is ${(currentMetric.broadcastPps + currentMetric.multicastPps)} PPS (Threshold: ${thresholdPps} PPS).`}
            </span>
          </div>
        </div>

        <div className="flex items-center gap-3 font-mono text-xs">
          <div className="bg-[#010409] px-2.5 py-1 rounded border border-[#30363d]">
            <span className="text-[#8b949e] text-[10px] block">Broadcast PPS</span>
            <span className={`font-bold ${isStormActive ? 'text-[#f85149]' : 'text-[#58a6ff]'}`}>
              {currentMetric.broadcastPps} pps
            </span>
          </div>
          <div className="bg-[#010409] px-2.5 py-1 rounded border border-[#30363d]">
            <span className="text-[#8b949e] text-[10px] block">Multicast PPS</span>
            <span className="text-[#d29922] font-bold">
              {currentMetric.multicastPps} pps
            </span>
          </div>
        </div>
      </div>

      {/* EtherApe-style Visual Packet Flow Ring Grid */}
      <div className="bg-[#161b22] border border-[#30363d] rounded p-4 space-y-3">
        <div className="flex items-center justify-between border-b border-[#30363d] pb-2">
          <div>
            <h3 className="text-xs font-bold text-[#f0f6fc] flex items-center gap-2 uppercase tracking-wider">
              <Radio className="w-3.5 h-3.5 text-[#58a6ff]" />
              EtherApe Dynamic Node Flow & Chatter Rings
            </h3>
            <span className="text-[11px] text-[#8b949e]">
              Ring diameter and pulsation scale with broadcast/multicast frames dispatched per second.
            </span>
          </div>

          <div className="flex items-center gap-2 text-[10px] font-mono">
            <span className="flex items-center gap-1 text-[#58a6ff]">
              <span className="w-2 h-2 rounded-full bg-[#58a6ff]" /> ARP
            </span>
            <span className="flex items-center gap-1 text-[#d29922]">
              <span className="w-2 h-2 rounded-full bg-[#d29922]" /> LLMNR
            </span>
            <span className="flex items-center gap-1 text-[#7ee787]">
              <span className="w-2 h-2 rounded-full bg-[#7ee787]" /> mDNS
            </span>
            <span className="flex items-center gap-1 text-[#f85149]">
              <span className="w-2 h-2 rounded-full bg-[#f85149]" /> STP BPDU
            </span>
          </div>
        </div>

        {/* Nodes Grid with Animated EtherApe style Rings */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 pt-2">
          {nodes.map(node => {
            const isEmitter = node.broadcastPps > 100;
            const ringColor = 
              node.dominantProtocol === 'ARP' ? '#58a6ff' :
              node.dominantProtocol === 'LLMNR' ? '#d29922' :
              node.dominantProtocol === 'STP BPDU' ? '#da3633' :
              node.dominantProtocol === 'mDNS' ? '#7ee787' : '#bc8cff';

            return (
              <div 
                key={node.id} 
                className={`p-3 rounded border transition flex flex-col justify-between ${
                  isEmitter 
                    ? 'bg-[#da3633]/10 border-[#da3633]/50 ring-1 ring-[#da3633]/30' 
                    : 'bg-[#010409] border-[#30363d]'
                }`}
              >
                <div className="flex items-start justify-between">
                  <div>
                    <span className="text-[10px] text-[#8b949e] font-mono block">VLAN {node.vlanId}</span>
                    <span className="text-xs font-bold text-[#f0f6fc] font-mono">{node.ip}</span>
                    <span className="text-[11px] text-[#8b949e] block font-sans truncate max-w-[170px]">{node.hostname}</span>
                  </div>

                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono uppercase ${
                    node.stormStatus === 'Flooding' || node.stormStatus === 'Loop Detected'
                      ? 'bg-[#da3633]/20 text-[#f85149] border border-[#da3633]/40 animate-pulse'
                      : node.stormStatus === 'Suppressed'
                      ? 'bg-[#238636]/20 text-[#7ee787] border border-[#238636]/40'
                      : 'bg-[#21262d] text-[#8b949e] border border-[#30363d]'
                  }`}>
                    {node.stormStatus}
                  </span>
                </div>

                {/* Simulated EtherApe Ring Graphic */}
                <div className="py-3 flex items-center justify-center">
                  <div className="relative flex items-center justify-center">
                    {/* Outer Pulsing Ring */}
                    <div 
                      className={`rounded-full transition-all duration-500 ${isEmitter ? 'animate-ping opacity-60' : 'opacity-20'}`}
                      style={{ 
                        width: `${node.packetRingSize + 16}px`, 
                        height: `${node.packetRingSize + 16}px`,
                        backgroundColor: ringColor
                      }}
                    />
                    {/* Inner Dynamic Disc */}
                    <div 
                      className="absolute rounded-full flex items-center justify-center text-white font-mono text-[10px] font-bold shadow-md"
                      style={{ 
                        width: `${node.packetRingSize}px`, 
                        height: `${node.packetRingSize}px`,
                        backgroundColor: ringColor
                      }}
                    >
                      {node.broadcastPps}
                    </div>
                  </div>
                </div>

                {/* Footer Metrics */}
                <div className="pt-2 border-t border-[#21262d] flex items-center justify-between text-[10px] font-mono text-[#8b949e]">
                  <span>Dominant: <strong style={{ color: ringColor }}>{node.dominantProtocol}</strong></span>
                  <span>{node.broadcastPps + node.multicastPps} PPS total</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Layer 2 Hardening Guidelines & Port Storm Control Reference */}
      <div className="bg-[#161b22] border border-[#30363d] p-4 rounded text-xs space-y-2">
        <h4 className="font-bold text-[#58a6ff] flex items-center gap-2 uppercase tracking-wider">
          <ShieldCheck className="w-4 h-4 text-[#58a6ff]" />
          Defensive Switch Configuration & Loop Prevention Runbook
        </h4>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
          <div className="bg-[#010409] p-2.5 rounded border border-[#30363d] space-y-1 font-mono text-[11px]">
            <span className="text-[#7ee787] font-semibold font-sans text-xs block">1. Cisco IOS Switch Storm Control:</span>
            <div className="text-[#8b949e]">interface range Gi1/0/1-48</div>
            <div className="text-[#c9d1d9]"> storm-control broadcast level 2.00</div>
            <div className="text-[#c9d1d9]"> storm-control multicast level 3.00</div>
            <div className="text-[#c9d1d9]"> storm-control action trap</div>
          </div>

          <div className="bg-[#010409] p-2.5 rounded border border-[#30363d] space-y-1 font-mono text-[11px]">
            <span className="text-[#7ee787] font-semibold font-sans text-xs block">2. Spanning Tree BPDU Guard & PortFast:</span>
            <div className="text-[#8b949e]">spanning-tree mode rapid-pvst</div>
            <div className="text-[#c9d1d9]">spanning-tree portfast default</div>
            <div className="text-[#c9d1d9]">spanning-tree portfast bpduguard default</div>
            <div className="text-[#8b949e]">// Shuts down rogue switch access ports instantly</div>
          </div>
        </div>
      </div>
    </div>
  );
};
