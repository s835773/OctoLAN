import React, { useState } from 'react';
import { NetworkDevice, VlanInfo } from '../types';
import { exportToPdf, exportToCsv, exportToTxt, ExportOptions } from '../utils/exportUtils';
import { 
  Download, FileText, Table, FileSpreadsheet, 
  CheckCircle, X, ShieldAlert, Layers, Filter, Sparkles
} from 'lucide-react';

interface ExportModalProps {
  isOpen: boolean;
  onClose: () => void;
  devices: NetworkDevice[];
  vlans: VlanInfo[];
}

export const ExportModal: React.FC<ExportModalProps> = ({
  isOpen,
  onClose,
  devices,
  vlans
}) => {
  const [selectedVlan, setSelectedVlan] = useState<number | 'all'>('all');
  const [highRiskOnly, setHighRiskOnly] = useState(false);
  const [exportedFormat, setExportedFormat] = useState<string | null>(null);

  if (!isOpen) return null;

  const exportOptions: ExportOptions = {
    vlanFilter: selectedVlan,
    highRiskOnly: highRiskOnly
  };

  const filteredCount = devices.filter(d => {
    const matchesVlan = selectedVlan === 'all' || d.vlanId === selectedVlan;
    const matchesRisk = !highRiskOnly || (d.riskScore === 'High' || d.riskScore === 'Critical');
    return matchesVlan && matchesRisk;
  }).length;

  const handleDownload = (format: 'pdf' | 'csv' | 'txt') => {
    if (format === 'pdf') {
      exportToPdf(devices, vlans, exportOptions);
    } else if (format === 'csv') {
      exportToCsv(devices, vlans, exportOptions);
    } else if (format === 'txt') {
      exportToTxt(devices, vlans, exportOptions);
    }
    setExportedFormat(format.toUpperCase());
    setTimeout(() => setExportedFormat(null), 3000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-in fade-in">
      <div className="bg-[#161b22] border border-[#30363d] rounded-xl w-full max-w-xl shadow-2xl overflow-hidden flex flex-col">
        {/* Header */}
        <div className="p-4 border-b border-[#30363d] flex items-center justify-between bg-[#161b22]">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-[#238636]/20 border border-[#238636]/40 text-[#7ee787]">
              <Download className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-[#f0f6fc]">Export Network Telemetry & Audit Reports</h2>
              <p className="text-xs text-[#8b949e]">Generate executive security summaries and machine-readable data feeds</p>
            </div>
          </div>
          <button 
            onClick={onClose}
            className="p-1 rounded-lg text-[#8b949e] hover:text-[#c9d1d9] hover:bg-[#21262d] transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-5 space-y-5">
          {/* Scope Filters */}
          <div className="bg-[#010409] p-3.5 rounded-lg border border-[#30363d] space-y-3">
            <div className="text-xs font-semibold text-[#f0f6fc] flex items-center justify-between">
              <span className="flex items-center gap-1.5">
                <Filter className="w-3.5 h-3.5 text-[#58a6ff]" />
                Export Scope & Filtering
              </span>
              <span className="text-[11px] font-mono text-[#7ee787] bg-[#238636]/20 px-2 py-0.5 rounded border border-[#238636]/40">
                {filteredCount} of {devices.length} hosts selected
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {/* VLAN Filter */}
              <div>
                <label className="block text-[11px] text-[#8b949e] mb-1">Target VLAN Segment:</label>
                <select
                  value={selectedVlan}
                  onChange={(e) => setSelectedVlan(e.target.value === 'all' ? 'all' : Number(e.target.value))}
                  className="w-full bg-[#161b22] border border-[#30363d] rounded text-xs text-[#c9d1d9] px-2.5 py-1.5 focus:outline-none focus:border-[#58a6ff]"
                >
                  <option value="all">All VLAN Segments ({devices.length} hosts)</option>
                  {vlans.map(v => (
                    <option key={v.id} value={v.id}>VLAN {v.id}: {v.name}</option>
                  ))}
                </select>
              </div>

              {/* Risk Filter */}
              <div>
                <label className="block text-[11px] text-[#8b949e] mb-1">Hygiene Filter:</label>
                <button
                  type="button"
                  onClick={() => setHighRiskOnly(!highRiskOnly)}
                  className={`w-full flex items-center justify-between px-2.5 py-1.5 rounded text-xs border transition ${
                    highRiskOnly 
                      ? 'bg-[#da3633]/20 border-[#da3633] text-[#f85149] font-medium' 
                      : 'bg-[#161b22] border-[#30363d] text-[#8b949e] hover:text-[#c9d1d9]'
                  }`}
                >
                  <span className="flex items-center gap-1.5">
                    <ShieldAlert className="w-3.5 h-3.5" />
                    High/Critical Risk Only
                  </span>
                  <input 
                    type="checkbox" 
                    checked={highRiskOnly} 
                    onChange={() => {}} 
                    className="accent-[#da3633] cursor-pointer"
                  />
                </button>
              </div>
            </div>
          </div>

          {/* Export Options Grid */}
          <div className="space-y-2.5">
            <div className="text-xs font-semibold text-[#8b949e] uppercase tracking-wider">
              Select Export Format
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              {/* Option 1: PDF */}
              <div className="p-3.5 rounded-lg bg-[#010409] border border-[#30363d] hover:border-[#58a6ff] transition flex flex-col justify-between group">
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <div className="p-2 rounded bg-[#da3633]/20 text-[#f85149] border border-[#da3633]/40">
                      <FileText className="w-5 h-5" />
                    </div>
                    <span className="text-[10px] font-mono font-semibold bg-[#21262d] text-[#c9d1d9] px-1.5 py-0.5 rounded">
                      .PDF
                    </span>
                  </div>
                  <h3 className="text-sm font-semibold text-[#f0f6fc] group-hover:text-[#58a6ff] transition">
                    Executive PDF Report
                  </h3>
                  <p className="text-[11px] text-[#8b949e] mt-1 leading-relaxed">
                    Formatted multi-page document with executive summary, port tables, VLAN maps, and hygiene grades.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => handleDownload('pdf')}
                  className="mt-3 w-full py-1.5 rounded bg-[#21262d] hover:bg-[#30363d] text-[#58a6ff] text-xs font-medium border border-[#30363d] transition flex items-center justify-center gap-1.5"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download PDF</span>
                </button>
              </div>

              {/* Option 2: CSV */}
              <div className="p-3.5 rounded-lg bg-[#010409] border border-[#30363d] hover:border-[#238636] transition flex flex-col justify-between group">
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <div className="p-2 rounded bg-[#238636]/20 text-[#7ee787] border border-[#238636]/40">
                      <FileSpreadsheet className="w-5 h-5" />
                    </div>
                    <span className="text-[10px] font-mono font-semibold bg-[#21262d] text-[#c9d1d9] px-1.5 py-0.5 rounded">
                      .CSV
                    </span>
                  </div>
                  <h3 className="text-sm font-semibold text-[#f0f6fc] group-hover:text-[#7ee787] transition">
                    Inventory CSV Sheet
                  </h3>
                  <p className="text-[11px] text-[#8b949e] mt-1 leading-relaxed">
                    RFC-compliant spreadsheet with IP addresses, MACs, OUI vendors, TTL signatures, and port lists.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => handleDownload('csv')}
                  className="mt-3 w-full py-1.5 rounded bg-[#21262d] hover:bg-[#30363d] text-[#7ee787] text-xs font-medium border border-[#30363d] transition flex items-center justify-center gap-1.5"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download CSV</span>
                </button>
              </div>

              {/* Option 3: TXT */}
              <div className="p-3.5 rounded-lg bg-[#010409] border border-[#30363d] hover:border-[#d29922] transition flex flex-col justify-between group">
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <div className="p-2 rounded bg-[#d29922]/20 text-[#d29922] border border-[#d29922]/40">
                      <Table className="w-5 h-5" />
                    </div>
                    <span className="text-[10px] font-mono font-semibold bg-[#21262d] text-[#c9d1d9] px-1.5 py-0.5 rounded">
                      .TXT
                    </span>
                  </div>
                  <h3 className="text-sm font-semibold text-[#f0f6fc] group-hover:text-[#d29922] transition">
                    Syslog / Raw ASCII Log
                  </h3>
                  <p className="text-[11px] text-[#8b949e] mt-1 leading-relaxed">
                    Plain-text structured audit log ideal for command-line parsing, SIEM ingestion, or terminal viewing.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => handleDownload('txt')}
                  className="mt-3 w-full py-1.5 rounded bg-[#21262d] hover:bg-[#30363d] text-[#d29922] text-xs font-medium border border-[#30363d] transition flex items-center justify-center gap-1.5"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download TXT</span>
                </button>
              </div>
            </div>
          </div>

          {/* Success Banner */}
          {exportedFormat && (
            <div className="p-2.5 rounded-lg bg-[#238636]/20 border border-[#238636]/40 text-[#7ee787] text-xs flex items-center gap-2 animate-in fade-in">
              <CheckCircle className="w-4 h-4 flex-shrink-0" />
              <span>
                <strong>{exportedFormat}</strong> exported and downloaded successfully!
              </span>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-3 bg-[#161b22] border-t border-[#30363d] flex items-center justify-between">
          <span className="text-[11px] text-[#8b949e]">
            Powered by OctoLAN POSIX C99 Telemetry Engine
          </span>
          <button
            type="button"
            onClick={onClose}
            className="px-3.5 py-1.5 rounded bg-[#21262d] hover:bg-[#30363d] text-[#c9d1d9] text-xs font-medium transition"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
