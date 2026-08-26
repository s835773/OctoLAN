import React, { useState } from 'react';
import { ProtocolStat } from '../types';
import { PROTOCOL_STATS } from '../data/sampleNetwork';
import { 
  Activity, ShieldAlert, AlertTriangle, CheckCircle2, 
  Lock, Unlock, Radio, Server, Eye, Filter
} from 'lucide-react';

export const ProtocolAuditor: React.FC = () => {
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [showPlaintextOnly, setShowPlaintextOnly] = useState(false);

  const categories = ['all', 'Infrastructure', 'Discovery', 'Web/App', 'File Sharing', 'Management', 'Legacy/Insecure'];

  const filteredStats = PROTOCOL_STATS.filter(p => {
    const matchesCat = selectedCategory === 'all' || p.category === selectedCategory;
    const matchesPlaintext = !showPlaintextOnly || p.isPlaintext;
    return matchesCat && matchesPlaintext;
  });

  const totalPackets = PROTOCOL_STATS.reduce((acc, p) => acc + p.packetCount, 0);
  const plaintextCount = PROTOCOL_STATS.filter(p => p.isPlaintext).length;

  return (
    <div className="space-y-4">
      {/* Header Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <div className="bg-[#161b22] border border-[#30363d] p-3.5 rounded">
          <span className="text-xs text-[#8b949e] font-medium">Total Captured Packets</span>
          <div className="text-xl font-bold text-[#f0f6fc] mt-1 font-mono">{totalPackets.toLocaleString()}</div>
          <span className="text-[11px] text-[#7ee787] flex items-center gap-1 mt-0.5">
            <Activity className="w-3 h-3" /> Passive wire sniffer active
          </span>
        </div>

        <div className="bg-[#161b22] border border-[#30363d] p-3.5 rounded">
          <span className="text-xs text-[#8b949e] font-medium">Monitored LAN Protocols</span>
          <div className="text-xl font-bold text-[#f0f6fc] mt-1 font-mono">{PROTOCOL_STATS.length} Protocols</div>
          <span className="text-[11px] text-[#8b949e] mt-0.5 block">L2 Ethernet through L7 Application</span>
        </div>

        <div className="bg-[#161b22] border border-[#d29922]/40 p-3.5 rounded bg-[#d29922]/5">
          <span className="text-xs text-[#d29922] font-medium">Plaintext / Broadcast Chatters</span>
          <div className="text-xl font-bold text-[#d29922] mt-1 font-mono">{plaintextCount} Detected</div>
          <span className="text-[11px] text-[#d29922] flex items-center gap-1 mt-0.5">
            <AlertTriangle className="w-3 h-3" /> mDNS, LLMNR, HTTP, SNMPv2c
          </span>
        </div>
      </div>

      {/* Protocol Visual Distribution Bar */}
      <div className="bg-[#161b22] border border-[#30363d] p-3.5 rounded space-y-2.5">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-[#c9d1d9] flex items-center gap-2">
            <Activity className="w-4 h-4 text-[#58a6ff]" />
            Protocol Traffic Composition (% of LAN Packets)
          </h3>
          <span className="text-xs font-mono text-[#8b949e]">100% Normalized</span>
        </div>

        {/* Stacked Percentage Bar */}
        <div className="w-full h-4 rounded overflow-hidden flex bg-[#010409] p-0.5 gap-0.5 border border-[#30363d]">
          {PROTOCOL_STATS.map((p, idx) => {
            const colors = [
              'bg-[#58a6ff]', 'bg-[#7ee787]', 'bg-[#d29922]', 'bg-[#bc8cff]',
              'bg-[#f0883e]', 'bg-[#f85149]', 'bg-[#3fb950]', 'bg-[#1f6feb]'
            ];
            const color = colors[idx % colors.length];

            return (
              <div
                key={p.protocol}
                title={`${p.protocol}: ${p.percentage}%`}
                className={`${color} h-full hover:opacity-80 transition cursor-pointer`}
                style={{ width: `${p.percentage}%` }}
              />
            );
          })}
        </div>

        {/* Quick Legend Chips */}
        <div className="flex flex-wrap gap-2 pt-1 text-[11px]">
          {PROTOCOL_STATS.slice(0, 6).map((p, idx) => {
            const colors = [
              'bg-[#58a6ff]', 'bg-[#7ee787]', 'bg-[#d29922]', 'bg-[#bc8cff]',
              'bg-[#f0883e]', 'bg-[#f85149]'
            ];
            return (
              <div key={p.protocol} className="flex items-center gap-1.5 text-[#8b949e]">
                <span className={`w-2 h-2 rounded-full ${colors[idx % colors.length]}`} />
                <span className="font-mono text-[#c9d1d9]">{p.protocol}</span>
                <span>({p.percentage}%)</span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Filter Controls */}
      <div className="flex flex-wrap items-center justify-between gap-3 bg-[#161b22] p-2.5 rounded border border-[#30363d]">
        <div className="flex items-center gap-1.5 flex-wrap">
          <span className="text-xs font-semibold text-[#8b949e] mr-1 flex items-center gap-1">
            <Filter className="w-3 h-3" /> Category:
          </span>
          {categories.map(cat => (
            <button
              key={cat}
              onClick={() => setSelectedCategory(cat)}
              className={`text-xs px-2.5 py-1 rounded transition ${
                selectedCategory === cat
                  ? 'bg-[#238636] text-white font-medium shadow-sm'
                  : 'bg-[#21262d] text-[#8b949e] hover:text-[#c9d1d9] border border-[#30363d]'
              }`}
            >
              {cat.charAt(0).toUpperCase() + cat.slice(1)}
            </button>
          ))}
        </div>

        <label className="flex items-center gap-2 text-xs text-[#c9d1d9] cursor-pointer select-none">
          <input
            type="checkbox"
            checked={showPlaintextOnly}
            onChange={(e) => setShowPlaintextOnly(e.target.checked)}
            className="rounded border-[#30363d] text-[#238636] focus:ring-0 bg-[#010409]"
          />
          <span className="flex items-center gap-1 text-[#d29922]">
            <Unlock className="w-3.5 h-3.5" /> Plaintext / Unencrypted Only
          </span>
        </label>
      </div>

      {/* Protocol Table */}
      <div className="bg-[#161b22] border border-[#30363d] rounded overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-[#c9d1d9]">
            <thead className="bg-[#010409] text-[#8b949e] uppercase tracking-wider font-semibold border-b border-[#30363d]">
              <tr>
                <th className="py-2.5 px-3.5">Protocol & Port</th>
                <th className="py-2.5 px-3.5">Category</th>
                <th className="py-2.5 px-3.5">Packets Captured</th>
                <th className="py-2.5 px-3.5">Encryption Status</th>
                <th className="py-2.5 px-3.5">Security & Reconnaissance Implication</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#30363d] font-mono">
              {filteredStats.map((item, idx) => (
                <tr key={idx} className="hover:bg-[#21262d] transition">
                  <td className="py-2.5 px-3.5">
                    <div className="font-bold text-[#f0f6fc]">{item.protocol}</div>
                    <div className="text-[11px] text-[#8b949e] font-normal">Port: {item.port}</div>
                  </td>

                  <td className="py-2.5 px-3.5">
                    <span className="px-2 py-0.5 rounded text-[10px] font-sans font-medium bg-[#21262d] text-[#c9d1d9] border border-[#30363d]">
                      {item.category}
                    </span>
                  </td>

                  <td className="py-2.5 px-3.5">
                    <div className="text-[#f0f6fc] font-bold">{item.packetCount.toLocaleString()}</div>
                    <div className="text-[10px] text-[#8b949e] font-sans">{item.percentage}% of LAN traffic</div>
                  </td>

                  <td className="py-2.5 px-3.5 font-sans">
                    {item.isPlaintext ? (
                      <span className="inline-flex items-center gap-1 text-[11px] font-medium text-[#d29922] bg-[#d29922]/10 px-2 py-0.5 rounded border border-[#d29922]/30">
                        <Unlock className="w-3 h-3" /> Plaintext
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-[11px] font-medium text-[#7ee787] bg-[#238636]/15 px-2 py-0.5 rounded border border-[#238636]/30">
                        <Lock className="w-3 h-3" /> Encrypted
                      </span>
                    )}
                  </td>

                  <td className="py-2.5 px-3.5 font-sans text-xs text-[#8b949e] leading-relaxed max-w-md">
                    {item.securityImplication}
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
