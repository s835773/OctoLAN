import React, { useState } from 'react';
import { 
  BookOpen, Terminal, Shield, Cpu, Layers, 
  HelpCircle, CheckCircle2, ChevronDown, ChevronRight,
  Activity, Bell, Zap, Radio, Globe, BarChart3
} from 'lucide-react';

export const AuditKnowledgeView: React.FC = () => {
  const [openSection, setOpenSection] = useState<number | null>(0);

  const guides = [
    {
      title: '1. Comparative Network Auditing Architectures: OcuLAN, Auvik, NetAlertX & EtherApe',
      icon: <Layers className="w-4 h-4 text-[#58a6ff]" />,
      content: (
        <div className="space-y-3 text-xs text-[#c9d1d9] leading-relaxed">
          <p>
            Understanding how modern on-premise network intelligence engines monitor and secure local infrastructure:
          </p>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-1">
            <div className="bg-[#010409] p-3 rounded border border-[#30363d] space-y-1.5">
              <span className="font-bold text-[#58a6ff] text-xs flex items-center gap-1.5">
                <Globe className="w-3.5 h-3.5" /> Auvik Topology & Flows
              </span>
              <p className="text-[11px] text-[#8b949e]">
                Enterprise network management system that combines <strong>SNMP, LLDP, CDP, WMI, and NetFlow/IPFIX</strong> to generate automated Layer 2/3 topology graphs, track switchport mapping, and inspect real-time bandwidth talkers.
              </p>
            </div>

            <div className="bg-[#010409] p-3 rounded border border-[#30363d] space-y-1.5">
              <span className="font-bold text-[#7ee787] text-xs flex items-center gap-1.5">
                <Bell className="w-3.5 h-3.5" /> NetAlertX Continuous Alerts
              </span>
              <p className="text-[11px] text-[#8b949e]">
                Dedicated WiFi / LAN intruder detector and device presence tracker. Continuously sweeps ARP/DHCP leases to alert instantly via <strong>Email, Webhook, and Push</strong> when unknown MAC vendors, rogue APs, or port changes appear.
              </p>
            </div>

            <div className="bg-[#010409] p-3 rounded border border-[#30363d] space-y-1.5">
              <span className="font-bold text-[#d29922] text-xs flex items-center gap-1.5">
                <Radio className="w-3.5 h-3.5" /> EtherApe Packet Rings
              </span>
              <p className="text-[11px] text-[#8b949e]">
                Classic Unix graphical packet monitor. Visualizes network activity as <strong>dynamic nodes with expanding color-coded protocol rings</strong>, exposing broadcast chatter spikes, ARP floods, and storm emitters in real time.
              </p>
            </div>
          </div>
        </div>
      )
    },
    {
      title: '2. NetFlow v5/v9 & IPFIX Flow Telemetry Mechanics',
      icon: <Activity className="w-4 h-4 text-[#7ee787]" />,
      content: (
        <div className="space-y-3 text-xs text-[#c9d1d9] leading-relaxed">
          <p>
            <strong>NetFlow</strong> (Cisco RFC 3954) and <strong>IPFIX</strong> (RFC 7011) decouple packet forwarding from telemetry analysis. Instead of recording full payload captures, routers and switches aggregate packets into unidirectional <strong>5-tuples</strong>:
          </p>
          <div className="bg-[#010409] p-3 rounded border border-[#30363d] font-mono text-[11px] text-[#c9d1d9] space-y-1">
            <div className="text-[#8b949e]">// NetFlow v5 5-Tuple Definition:</div>
            <div>[Source IP] : [Source Port] &lt;---&gt; [Destination IP] : [Destination Port]</div>
            <div>[IP Protocol: TCP (6), UDP (17), ICMP (1)] | [Type of Service (TOS)] | [Input/Output IfIndex]</div>
            <div>[Metrics: Cumulative Octets, Cumulative Packets, First Uptime, Last Uptime, TCP Flags]</div>
          </div>
          <p>
            Flow records expire and export over UDP port 2055 when an <em>Inactive Timeout</em> (e.g. 15s of silence) or <em>Active Timeout</em> (e.g. 60s long-lived connection) occurs.
          </p>
        </div>
      )
    },
    {
      title: '3. Broadcast Storm Dynamics & Spanning Tree (STP) Loops',
      icon: <Zap className="w-4 h-4 text-[#f85149]" />,
      content: (
        <div className="space-y-3 text-xs text-[#c9d1d9] leading-relaxed">
          <p>
            Ethernet frames lack a Time-To-Live (TTL) field at Layer 2. If redundant switch cabling creates a physical loop without <strong>Spanning Tree Protocol (IEEE 802.1D / 802.1w Rapid-PVST)</strong>, a single broadcast frame (such as an ARP request) is forwarded indefinitely out of every port:
          </p>
          <div className="bg-[#010409] p-3 rounded border border-[#30363d] font-mono text-[11px] text-[#c9d1d9] space-y-1">
            <div className="text-[#8b949e]">// Layer 2 Loop Catastrophe Progression:</div>
            <div>1. Host sends 1 ARP Request (FF:FF:FF:FF:FF:FF)</div>
            <div>2. Switch A forwards to Switch B; Switch B forwards back to Switch A</div>
            <div>3. Frame multiplies exponentially --&gt; 50,000+ PPS in &lt; 2 seconds</div>
            <div>4. Switch CPU saturates at 100%, MAC address table oscillates, packet drop occurs</div>
          </div>
          <div className="p-2.5 rounded bg-[#238636]/10 border border-[#238636]/30 text-[#7ee787]">
            <strong>Remediation:</strong> Enable <code className="font-mono">storm-control broadcast level 2.00</code> and <code className="font-mono">spanning-tree portfast bpduguard default</code> on all access switchports.
          </div>
        </div>
      )
    },
    {
      title: '4. Layer 2 ARP Sweeps & Promiscuous Raw Sockets in C',
      icon: <Terminal className="w-4 h-4 text-[#58a6ff]" />,
      content: (
        <div className="space-y-3 text-xs text-[#c9d1d9] leading-relaxed">
          <p>
            When auditing a local Ethernet broadcast domain (LAN), standard TCP/IP connect scans are bypassed in favor of raw <strong>ARP requests (<code className="text-[#58a6ff] font-mono">AF_PACKET</code> / <code className="text-[#58a6ff] font-mono">ETH_P_ARP</code>)</strong>. Because ARP operates below IP firewalls at Layer 2, hosts cannot hide or block ARP who-has queries without dropping their own network connectivity.
          </p>
          <div className="bg-[#010409] p-3 rounded border border-[#30363d] font-mono text-[11px] text-[#c9d1d9] space-y-1">
            <div className="text-[#8b949e]">// Standard ARP probe frame layout:</div>
            <div>[Ethernet Header (Dest: FF:FF:FF:FF:FF:FF) (Type: 0x0806)]</div>
            <div>[ARP Payload: HW Type 1, Proto 0x0800, Opcode 1 (REQUEST)]</div>
            <div>[Sender MAC: local_mac | Target IP: 192.168.1.X]</div>
          </div>
        </div>
      )
    },
    {
      title: '5. Operating System Fingerprinting Heuristics (TTL, Window Size, TCP Options)',
      icon: <Cpu className="w-4 h-4 text-[#58a6ff]" />,
      content: (
        <div className="space-y-3 text-xs text-[#c9d1d9] leading-relaxed">
          <p>
            Every major operating system network stack implements slightly different default values in its IP and TCP header implementations:
          </p>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-[11px] font-mono border border-[#30363d] rounded overflow-hidden">
              <thead className="bg-[#010409] text-[#8b949e] uppercase">
                <tr>
                  <th className="p-2">OS Platform</th>
                  <th className="p-2">Initial IP TTL</th>
                  <th className="p-2">TCP Window Size</th>
                  <th className="p-2">DF (Don't Fragment)</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#30363d] bg-[#161b22]">
                <tr>
                  <td className="p-2 text-[#58a6ff] font-sans font-bold">Linux Kernel 3.x - 6.x</td>
                  <td className="p-2">64</td>
                  <td className="p-2">29200 / 64240</td>
                  <td className="p-2 text-[#7ee787]">Yes (1)</td>
                </tr>
                <tr>
                  <td className="p-2 text-[#58a6ff] font-sans font-bold">Windows 10 / 11 / Server 2022</td>
                  <td className="p-2">128</td>
                  <td className="p-2">64512 / 65535</td>
                  <td className="p-2 text-[#7ee787]">Yes (1)</td>
                </tr>
                <tr>
                  <td className="p-2 text-[#58a6ff] font-sans font-bold">Cisco IOS / IOS-XE</td>
                  <td className="p-2">255</td>
                  <td className="p-2">4128 / 8192</td>
                  <td className="p-2 text-[#8b949e]">No (0)</td>
                </tr>
                <tr>
                  <td className="p-2 text-[#58a6ff] font-sans font-bold">FreeBSD / pfSense / macOS</td>
                  <td className="p-2">64</td>
                  <td className="p-2">65535</td>
                  <td className="p-2 text-[#7ee787]">Yes (1)</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      )
    }
  ];

  return (
    <div className="space-y-4">
      {/* Header Banner */}
      <div className="bg-[#161b22] border border-[#30363d] p-4 rounded flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded bg-[#238636] text-white flex items-center justify-center font-bold text-xs shadow-sm">
              <BookOpen className="w-3.5 h-3.5" />
            </div>
            <h2 className="text-sm font-bold text-[#f0f6fc]">
              OcuLAN On-Premise Network Engineering & Security Handbook
            </h2>
          </div>
          <p className="text-xs text-[#8b949e] mt-1 max-w-2xl">
            In-depth architectural explanations comparing <strong>Auvik</strong>, <strong>NetAlertX</strong>, and <strong>EtherApe</strong> paradigms with raw socket C packet construction.
          </p>
        </div>
      </div>

      {/* Accordion List */}
      <div className="space-y-2.5">
        {guides.map((guide, idx) => {
          const isOpen = openSection === idx;
          return (
            <div
              key={idx}
              className="bg-[#161b22] border border-[#30363d] rounded overflow-hidden transition"
            >
              <button
                onClick={() => setOpenSection(isOpen ? null : idx)}
                className="w-full p-3.5 flex items-center justify-between text-left hover:bg-[#1f242c] transition"
              >
                <div className="flex items-center gap-3">
                  {guide.icon}
                  <span className="text-xs font-semibold text-[#f0f6fc]">
                    {guide.title}
                  </span>
                </div>
                {isOpen ? (
                  <ChevronDown className="w-4 h-4 text-[#58a6ff]" />
                ) : (
                  <ChevronRight className="w-4 h-4 text-[#8b949e]" />
                )}
              </button>

              {isOpen && (
                <div className="p-4 pt-2 border-t border-[#21262d] bg-[#161b22]/70">
                  {guide.content}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
