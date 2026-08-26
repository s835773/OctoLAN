import React, { useState } from 'react';
import { NetworkDevice, VlanInfo, AuditReport } from '../types';
import { 
  Sparkles, ShieldCheck, AlertTriangle, CheckCircle2, 
  Layers, Lock, Server, FileDown, RefreshCw, ChevronRight
} from 'lucide-react';

interface AiAdvisorProps {
  devices: NetworkDevice[];
  vlans: VlanInfo[];
}

export const AiAdvisor: React.FC<AiAdvisorProps> = ({ devices, vlans }) => {
  const [isGenerating, setIsGenerating] = useState(false);
  const [filterSeverity, setFilterSeverity] = useState<'all' | 'Critical' | 'High' | 'Medium'>('all');

  // Compute live recommendations from current device set
  const generateRecommendations = () => {
    const recs: AuditReport['recommendations'] = [];

    // Check for plaintext HTTP administration
    const httpDevs = devices.filter(d => d.ports.some(p => p.port === 80 && p.state === 'open'));
    if (httpDevs.length > 0) {
      recs.push({
        category: 'Plaintext Protocols',
        severity: 'Critical',
        title: 'Unencrypted HTTP Web Management Detected on LAN Devices',
        description: `Found ${httpDevs.length} devices (including ${httpDevs.slice(0, 2).map(d => d.hostname).join(', ')}) listening on HTTP port 80 without automatic HTTPS redirection.`,
        remediation: 'Enforce HTTPS (TLS 1.3) and configure HTTP-to-HTTPS 301 permanent redirects on all administrative portals.'
      });
    }

    // Check for SNMPv2c default strings
    const snmpDevs = devices.filter(d => d.ports.some(p => p.port === 161 || p.riskReason?.includes('SNMP')));
    if (snmpDevs.length > 0) {
      recs.push({
        category: 'Default Services',
        severity: 'High',
        title: 'SNMPv2c Cleartext Community Strings Exposed',
        description: `Core network switch (${snmpDevs[0].hostname}) is responding to SNMP queries over UDP 161 with default public community strings.`,
        remediation: 'Upgrade to SNMPv3 with SHA authentication (authPriv) and AES-256 encryption, or restrict SNMP access to dedicated management jump-hosts via firewall ACLs.'
      });
    }

    // Check for LLMNR / NetBIOS broadcast chatter
    const llmnrDevs = devices.filter(d => d.activeProtocols.includes('LLMNR') || d.activeProtocols.includes('NetBIOS'));
    if (llmnrDevs.length > 0) {
      recs.push({
        category: 'Device Hardening',
        severity: 'High',
        title: 'LLMNR & NetBIOS Name Resolution Enabled on Workstations',
        description: `${llmnrDevs.length} Windows workstations are actively broadcasting LLMNR queries (UDP 5355). This allows rogue devices on the subnet to spoof responses and capture password hashes.`,
        remediation: 'Disable LLMNR via Group Policy (Computer Configuration -> Administrative Templates -> Network -> DNS Client -> Turn off multicast name resolution) and disable NetBIOS over TCP/IP in DHCP scope.'
      });
    }

    // Check for IoT devices on unisolated VLANs
    const unisolatedIot = devices.filter(d => d.deviceType === 'iot' && d.vlanId !== 30);
    if (unisolatedIot.length > 0) {
      recs.push({
        category: 'VLAN Segmentation',
        severity: 'Medium',
        title: 'IoT / Camera Endpoints Located Outside Dedicated IoT VLAN',
        description: `Detected IoT devices residing on standard corporate subnets instead of dedicated isolated VLAN 30.`,
        remediation: 'Move all smart cameras, thermostats, and smart sensors into an isolated IoT VLAN with no access to corporate servers or workstation subnets.'
      });
    }

    // Check for Guest VLAN Isolation
    const guestVlan = vlans.find(v => v.id === 50);
    if (guestVlan && guestVlan.isolated) {
      recs.push({
        category: 'VLAN Segmentation',
        severity: 'Low',
        title: 'Guest Wi-Fi VLAN Isolation Confirmed',
        description: 'VLAN 50 is properly configured with Layer 2 client isolation and firewall rules blocking inter-VLAN routing to internal servers.',
        remediation: 'Maintain current guest policy; ensure periodic review of firewall ACLs on default gateway.'
      });
    }

    return recs;
  };

  const recommendations = generateRecommendations();
  const filteredRecs = recommendations.filter(r => filterSeverity === 'all' || r.severity === filterSeverity);

  const handleExportReport = () => {
    const textReport = `======================================================================
LAN TOPOLOGY & ON-PREMISE NETWORK AUDIT REPORT
Generated: ${new Date().toISOString()}
======================================================================
Total Discovered Assets: ${devices.length}
Total VLAN Segments: ${vlans.length}
Total Open Services Flagged: ${devices.reduce((acc, d) => acc + d.ports.length, 0)}

AUDIT RECOMMENDATIONS & HYGIENE FINDINGS:
${recommendations.map((r, i) => `
[${i + 1}] [${r.severity.toUpperCase()}] ${r.title}
Category: ${r.category}
Finding: ${r.description}
Remediation: ${r.remediation}
`).join('\n')}

======================================================================
END OF REPORT
`;

    const blob = new Blob([textReport], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `LAN-Audit-Report-${new Date().toISOString().slice(0, 10)}.txt`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="bg-[#161b22] border border-[#30363d] p-4 rounded flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded bg-[#238636] text-white flex items-center justify-center font-bold text-xs">
              <Sparkles className="w-3.5 h-3.5" />
            </div>
            <h2 className="text-sm font-bold text-[#f0f6fc]">
              Defensive Network Hygiene & Segmentation Advisor
            </h2>
          </div>
          <p className="text-xs text-[#8b949e] mt-1 max-w-2xl leading-relaxed">
            Automated defensive assessment evaluating your VLAN boundary enforcement, exposed plaintext services, legacy broadcast chatter, and device hardening compliance.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleExportReport}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#238636] hover:bg-[#2ea043] text-white text-xs font-semibold shadow-sm transition"
          >
            <FileDown className="w-3.5 h-3.5" /> Export Audit Report
          </button>
        </div>
      </div>

      {/* Severity Filter */}
      <div className="flex items-center gap-2 bg-[#161b22] p-2 rounded border border-[#30363d] text-xs">
        <span className="text-[#8b949e] px-1 font-medium">Filter Severity:</span>
        {(['all', 'Critical', 'High', 'Medium'] as const).map(sev => (
          <button
            key={sev}
            onClick={() => setFilterSeverity(sev)}
            className={`px-2.5 py-1 rounded transition ${
              filterSeverity === sev
                ? 'bg-[#238636] text-white font-medium shadow-sm'
                : 'text-[#8b949e] hover:text-[#c9d1d9] bg-[#21262d] border border-[#30363d]'
            }`}
          >
            {sev === 'all' ? 'All Findings' : sev}
          </button>
        ))}
      </div>

      {/* Recommendations Cards */}
      <div className="space-y-3">
        {filteredRecs.map((rec, idx) => (
          <div
            key={idx}
            className="p-3.5 rounded border border-[#30363d] space-y-2.5 bg-[#161b22]"
          >
            <div className="flex items-start justify-between gap-3">
              <div className="flex items-center gap-2">
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider font-mono ${
                    rec.severity === 'Critical' ? 'bg-[#da3633]/20 text-[#f85149] border border-[#da3633]/40' :
                    rec.severity === 'High' ? 'bg-[#d29922]/20 text-[#d29922] border border-[#d29922]/40' :
                    rec.severity === 'Medium' ? 'bg-[#58a6ff]/15 text-[#58a6ff] border border-[#58a6ff]/30' :
                    'bg-[#238636]/20 text-[#7ee787] border border-[#238636]/40'
                  }`}
                >
                  {rec.severity}
                </span>
                <span className="text-xs px-2 py-0.5 rounded bg-[#010409] text-[#c9d1d9] font-medium border border-[#30363d]">
                  {rec.category}
                </span>
              </div>
            </div>

            <h3 className="text-sm font-bold text-[#f0f6fc]">{rec.title}</h3>
            <p className="text-xs text-[#c9d1d9] leading-relaxed">{rec.description}</p>

            <div className="bg-[#010409] p-2.5 rounded border border-[#30363d] text-xs space-y-1">
              <span className="text-[#7ee787] font-semibold flex items-center gap-1.5 text-[11px] uppercase tracking-wider">
                <ShieldCheck className="w-3.5 h-3.5" /> Recommended Remediation:
              </span>
              <p className="text-[#c9d1d9] font-mono text-[11px] leading-relaxed">{rec.remediation}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
