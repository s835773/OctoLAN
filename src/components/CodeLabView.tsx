import React, { useState, useEffect } from 'react';
import { C_SOURCE_FILES, CSourceFile } from '../data/cSourceCode';
import { RUST_SOURCE_FILES, RustSourceFile } from '../data/rustSourceCode';
import { 
  FileCode, Terminal, Copy, Check, Download, 
  Cpu, Layers, Shield, BookOpen, ExternalLink, Play, Sparkles, RefreshCw, FolderArchive,
  Zap, Box
} from 'lucide-react';

export const CodeLabView: React.FC = () => {
  const [suiteLanguage, setSuiteLanguage] = useState<'rust' | 'c'>('rust');
  const [selectedRustFile, setSelectedRustFile] = useState<RustSourceFile>(RUST_SOURCE_FILES[1]); // main.rs
  const [selectedCFile, setSelectedCFile] = useState<CSourceFile>(C_SOURCE_FILES[0]);
  const [copied, setCopied] = useState(false);
  const [activeTab, setActiveTab] = useState<'source' | 'terminal'>('source');
  const [isExecuting, setIsExecuting] = useState(false);
  const [terminalOutput, setTerminalOutput] = useState<string[]>([]);
  const [customArgs, setCustomArgs] = useState<string>('');

  const activeFile = suiteLanguage === 'rust' 
    ? {
        filename: selectedRustFile.filename,
        title: selectedRustFile.title,
        description: selectedRustFile.description,
        category: selectedRustFile.category,
        code: selectedRustFile.code,
        compilationCmd: selectedRustFile.compilationCmd,
        requirements: selectedRustFile.requirements,
        capabilities: selectedRustFile.capabilities,
      }
    : {
        filename: selectedCFile.filename,
        title: selectedCFile.title,
        description: selectedCFile.description,
        category: selectedCFile.category,
        code: selectedCFile.code,
        compilationCmd: selectedCFile.compilationCmd,
        requirements: selectedCFile.requirements,
        capabilities: selectedCFile.capabilities,
      };

  useEffect(() => {
    if (suiteLanguage === 'rust') {
      if (selectedRustFile.filename === 'main.rs') {
        setCustomArgs('--interface eth0 --port 3000');
      } else if (selectedRustFile.filename === 'arp.rs') {
        setCustomArgs('scan --subnet 192.168.1.0/24');
      } else if (selectedRustFile.filename === 'storm.rs') {
        setCustomArgs('storm-watch --threshold-pps 2200');
      } else {
        setCustomArgs('');
      }
    } else {
      if (selectedCFile.filename === 'arp_scan.c') {
        setCustomArgs('eth0 192.168.1.1 192.168.1.254');
      } else if (selectedCFile.filename === 'icmp_sweep.c') {
        setCustomArgs('192.168.1.0/24');
      } else if (selectedCFile.filename === 'os_fingerprint.c') {
        setCustomArgs('192.168.1.100');
      } else if (selectedCFile.filename === 'lldp_vlan_sniff.c') {
        setCustomArgs('eth0 15');
      } else if (selectedCFile.filename === 'netflow_collector.c') {
        setCustomArgs('2055');
      } else if (selectedCFile.filename === 'storm_detector.c') {
        setCustomArgs('eth0 250');
      } else {
        setCustomArgs('');
      }
    }
    setTerminalOutput([]);
    setIsExecuting(false);
  }, [suiteLanguage, selectedRustFile, selectedCFile]);

  const handleCopy = () => {
    navigator.clipboard.writeText(activeFile.code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([activeFile.code], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = activeFile.filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const handleDownloadBundle = () => {
    if (suiteLanguage === 'rust') {
      let bundleScript = `#!/usr/bin/env bash
# ==============================================================================
# OctoLAN Rust Crate Setup & Automated Builder (octolan-rs)
# ==============================================================================
set -e

echo "[+] Generating complete octolan-rs project structure..."
mkdir -p octolan-rs/src/api octolan-rs/src/scanners

cat << 'EOF' > octolan-rs/Cargo.toml
${RUST_SOURCE_FILES.find(f => f.filename === 'Cargo.toml')?.code || ''}
EOF

cat << 'EOF' > octolan-rs/src/main.rs
${RUST_SOURCE_FILES.find(f => f.filename === 'main.rs')?.code || ''}
EOF

cat << 'EOF' > octolan-rs/src/scanners/mod.rs
pub mod arp;
pub mod netflow;
pub mod storm;
pub mod fingerprint;
pub mod lldp;
EOF

cat << 'EOF' > octolan-rs/src/scanners/arp.rs
${RUST_SOURCE_FILES.find(f => f.filename === 'arp.rs')?.code || ''}
EOF

cat << 'EOF' > octolan-rs/src/scanners/netflow.rs
${RUST_SOURCE_FILES.find(f => f.filename === 'netflow.rs')?.code || ''}
EOF

cat << 'EOF' > octolan-rs/src/scanners/storm.rs
${RUST_SOURCE_FILES.find(f => f.filename === 'storm.rs')?.code || ''}
EOF

cat << 'EOF' > octolan-rs/src/api/mod.rs
pub mod ws;
use axum::{routing::get, Router, Json};
use tower_http::cors::CorsLayer;
use std::sync::Arc;
use tokio::sync::broadcast;
use serde_json::json;

pub fn create_router(interface: String, tx_telemetry: Arc<broadcast::Sender<String>>) -> Router {
    let state = ws::AppState { interface, tx_telemetry };
    Router::new()
        .route("/api/health", get(|| async { Json(json!({"status": "healthy", "runtime": "Rust/Axum"})) }))
        .route("/ws/telemetry", get(ws::ws_handler))
        .layer(CorsLayer::permissive())
        .with_state(state)
}
EOF

cat << 'EOF' > octolan-rs/src/api/ws.rs
${RUST_SOURCE_FILES.find(f => f.filename === 'ws.rs')?.code || ''}
EOF

echo "[✓] Successfully created complete octolan-rs Cargo workspace in ./octolan-rs"
echo "[+] To compile: cd octolan-rs && cargo build --release"
echo "[+] To run: sudo ./target/release/octolan-rs --interface eth0 --port 3000"
`;
      const blob = new Blob([bundleScript], { type: 'text/x-sh;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = 'bundle_setup_rust.sh';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    } else {
      let bundleScript = `#!/usr/bin/env bash\n# LAN Reconnaissance C & Bash Suite\n# Generated by On-Premise LAN Auditor\n\nmkdir -p lan_recon_suite && cd lan_recon_suite\n\n`;
      C_SOURCE_FILES.forEach(f => {
        bundleScript += `cat << 'EOF' > ${f.filename}\n${f.code}\nEOF\n\n`;
      });
      bundleScript += `echo "[+] Extracted all C source files and Makefile into ./lan_recon_suite"\necho "[+] Run 'make' to compile all native binaries or 'bash lan_recon.sh' to audit."\n`;

      const blob = new Blob([bundleScript], { type: 'text/x-sh;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = 'bundle_setup_c.sh';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    }
  };

  const runSimulation = () => {
    setIsExecuting(true);
    
    if (suiteLanguage === 'rust') {
      setTerminalOutput([
        `$ cargo build --release`,
        `   Compiling tokio v1.38.0`,
        `   Compiling axum v0.7.5`,
        `   Compiling pnet v0.34.0`,
        `   Compiling octolan-rs v2.1.0 (/usr/src/octolan-rs)`,
        `    Finished release [optimized + lto] target(s) in 3.42s`,
        `$ sudo ./target/release/octolan-rs ${customArgs}`
      ]);

      setTimeout(() => {
        if (selectedRustFile.filename === 'main.rs') {
          setTerminalOutput(prev => [
            ...prev,
            `2026-08-28T18:45:00Z INFO [octolan_rs] 🚀 Initializing octolan-rs v2.1.0 (Tokio Multi-Core Runtime)`,
            `2026-08-28T18:45:00Z INFO [pnet::datalink] AF_PACKET raw socket bound to eth0 (Promiscuous Mode)`,
            `2026-08-28T18:45:00Z INFO [scanners::netflow] 📡 NetFlow UDP Ingestion daemon listening on 0.0.0.0:2055`,
            `2026-08-28T18:45:00Z INFO [scanners::storm] 🛡️ Storm Watchdog initialized (Active Threshold: 2200 PPS)`,
            `2026-08-28T18:45:00Z INFO [octolan_rs] 🌐 Starting Axum REST & WebSocket Server at http://0.0.0.0:3000`,
            `2026-08-28T18:45:00Z INFO [octolan_rs] 📡 Streaming real-time telemetry on ws://0.0.0.0:3000/ws/telemetry`,
            `2026-08-28T18:45:02Z INFO [api::ws] 📡 Client connected: Browser React WebApp established WebSocket link`,
            `2026-08-28T18:45:03Z INFO [telemetry] Ingested 1,420 PPS from Cisco Core Switch (UDP 2055)`
          ]);
        } else if (selectedRustFile.filename === 'arp.rs') {
          setTerminalOutput(prev => [
            ...prev,
            `2026-08-28T18:45:00Z INFO [scanners::arp] Using interface: eth0 (MAC: 02:42:c0:a8:01:05)`,
            `2026-08-28T18:45:00Z INFO [scanners::arp] Transmitting async raw ARP requests across 192.168.1.0/24...`,
            `[+] Host Discovered: 192.168.1.1      at bc:a9:d4:11:22:33 (Cisco Systems Enterprise) - RTT: 0.84ms`,
            `[+] Host Discovered: 192.168.1.2      at 00:1b:21:44:55:66 (Cisco Systems Enterprise) - RTT: 0.91ms`,
            `[+] Host Discovered: 192.168.1.10     at 00:0c:29:ab:cd:ef (VMware ESXi Virtualization) - RTT: 1.12ms`,
            `[+] Host Discovered: 192.168.1.20     at b8:27:eb:12:34:56 (Raspberry Pi Foundation) - RTT: 2.30ms`,
            `[+] Host Discovered: 192.168.1.100    at d8:5ed3:98:76:54 (Dell Inc. Enterprise Servers) - RTT: 1.45ms`,
            `[+] Host Discovered: 192.168.1.101    at 3c:22:fb:11:22:33 (Apple Inc.) - RTT: 3.10ms`,
            `2026-08-28T18:45:01Z INFO [scanners::arp] Sweep complete: 6 active hosts discovered in 142ms.`
          ]);
        } else if (selectedRustFile.filename === 'storm.rs') {
          setTerminalOutput(prev => [
            ...prev,
            `2026-08-28T18:45:00Z INFO [scanners::storm] Monitoring interface 'eth0' for broadcast storms...`,
            `[18:45:01] Normal Load: 24 Bcast PPS, 48 Mcast PPS, 1,320 Unicast PPS`,
            `[18:45:02] Normal Load: 31 Bcast PPS, 52 Mcast PPS, 1,410 Unicast PPS`,
            `2026-08-28T18:45:03Z WARN [scanners::storm] ⚠️ STORM THRESHOLD BREACHED: 2,480 PPS on interface`,
            `{"type":"storm_alert","timestamp":"2026-08-28T18:45:03Z","peak_pps":2480,"threshold":2200,"severity":"HIGH_CRITICAL","action_taken":"Tripped 802.1Q Port Rate-Limiter"}`
          ]);
        } else {
          setTerminalOutput(prev => [
            ...prev,
            `2026-08-28T18:45:00Z INFO Module active. Ready for background task invocation.`
          ]);
        }
        setIsExecuting(false);
      }, 700);
    } else {
      setTerminalOutput([`$ gcc -O2 ${selectedCFile.filename} -o ${selectedCFile.filename.replace('.c', '')}`, `[✓] Compilation succeeded: 0 warnings, 0 errors.`, `$ sudo ./${selectedCFile.filename.replace('.c', '')} ${customArgs}`]);

      setTimeout(() => {
        if (selectedCFile.filename === 'arp_scan.c') {
          setTerminalOutput(prev => [
            ...prev,
            `[*] Probing interface eth0 (HW: 02:42:c0:a8:01:05, IP: 192.168.1.5)...`,
            `[*] Sending raw ARP WHO-HAS frames to 192.168.1.1 - 192.168.1.254...`,
            `[+] 192.168.1.1      at bc:a9:d4:11:22:33 (Cisco Systems) - Latency: 0.84ms`,
            `[+] 192.168.1.10     at 00:0c:29:ab:cd:ef (VMware ESXi Host) - Latency: 1.12ms`,
            `[*] ARP Sweep complete: Discovered active endpoints in 1.42s.`
          ]);
        } else {
          setTerminalOutput(prev => [
            ...prev,
            `[✓] Execution completed successfully with exit code 0.`
          ]);
        }
        setIsExecuting(false);
      }, 700);
    }
  };

  return (
    <div className="space-y-4">
      {/* Intro Header */}
      <div className="bg-[#161b22] border border-[#30363d] p-4 rounded-lg flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded border ${
              suiteLanguage === 'rust'
                ? 'bg-[#f0883e]/20 text-[#f0883e] border-[#f0883e]/40'
                : 'bg-[#238636]/20 text-[#7ee787] border-[#238636]/40'
            }`}>
              {suiteLanguage === 'rust' ? '🦀 Rust 1.80+ (Axum + Tokio + pnet)' : 'POSIX C99 & Shell'}
            </span>
            <h2 className="text-sm font-bold text-[#f0f6fc]">
              {suiteLanguage === 'rust' 
                ? 'Full-Stack Rust Asynchronous Telemetry Engine (octolan-rs)'
                : 'Portable On-Premise Reconnaissance C Suite & Toolchain'}
            </h2>
          </div>
          <p className="text-xs text-[#8b949e] mt-1 max-w-2xl leading-relaxed">
            {suiteLanguage === 'rust'
              ? 'Complete high-performance Rust daemon featuring Axum v0.7 HTTP/WS server, Tokio multi-threaded async workers, zero-copy pnet raw Ethernet packets, and NetFlow UDP ingestion.'
              : 'Zero-dependency native C programs utilizing POSIX raw packet sockets (AF_PACKET, IPPROTO_ICMP, ETH_P_LLDP) for bare-metal Linux and embedded OpenWrt/Termux execution.'}
          </p>
        </div>

        {/* Action buttons */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Language Suite Switcher */}
          <div className="flex items-center bg-[#010409] border border-[#30363d] rounded p-0.5">
            <button
              onClick={() => setSuiteLanguage('rust')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-semibold transition ${
                suiteLanguage === 'rust'
                  ? 'bg-[#f0883e] text-white shadow-sm'
                  : 'text-[#8b949e] hover:text-[#c9d1d9]'
              }`}
            >
              <span>🦀 Rust Suite</span>
            </button>
            <button
              onClick={() => setSuiteLanguage('c')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-semibold transition ${
                suiteLanguage === 'c'
                  ? 'bg-[#238636] text-white shadow-sm'
                  : 'text-[#8b949e] hover:text-[#c9d1d9]'
              }`}
            >
              <span>POSIX C Suite</span>
            </button>
          </div>

          <button
            onClick={handleDownloadBundle}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#21262d] hover:bg-[#30363d] text-[#c9d1d9] text-xs font-medium border border-[#30363d] transition"
            title="Download full project setup installer"
          >
            <FolderArchive className="w-3.5 h-3.5 text-[#58a6ff]" />
            <span>Download {suiteLanguage === 'rust' ? 'octolan-rs Crate' : 'C Suite'}</span>
          </button>

          <button
            onClick={handleDownload}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#238636] hover:bg-[#2ea043] text-white text-xs font-semibold shadow-sm transition"
          >
            <Download className="w-3.5 h-3.5" /> Download {activeFile.filename}
          </button>
        </div>
      </div>

      {/* Main Layout: Sidebar File List + Code/Terminal Viewer */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left Sidebar: Source Files */}
        <div className="lg:col-span-4 space-y-2">
          <div className="flex items-center justify-between px-1">
            <span className="text-xs font-semibold text-[#8b949e] uppercase tracking-wider block">
              {suiteLanguage === 'rust' ? 'Rust Crate Modules' : 'C Source Modules & Scripts'}
            </span>
            <span className="text-[10px] text-[#58a6ff] font-mono">
              {suiteLanguage === 'rust' ? `${RUST_SOURCE_FILES.length} Files` : `${C_SOURCE_FILES.length} Files`}
            </span>
          </div>

          <div className="space-y-1.5">
            {suiteLanguage === 'rust' ? (
              RUST_SOURCE_FILES.map(file => (
                <button
                  key={file.filename}
                  onClick={() => setSelectedRustFile(file)}
                  className={`w-full text-left p-3 rounded-lg border transition flex flex-col gap-1 ${
                    selectedRustFile.filename === file.filename
                      ? 'bg-[#21262d] border-[#f0883e] ring-1 ring-[#f0883e]/30 text-[#f0f6fc]'
                      : 'bg-[#161b22] border-[#30363d] hover:bg-[#21262d] hover:border-[#8b949e] text-[#c9d1d9]'
                  }`}
                >
                  <div className="flex items-center justify-between w-full">
                    <div className="flex items-center gap-2 font-mono text-xs font-bold">
                      <FileCode className="w-3.5 h-3.5 text-[#f0883e] flex-shrink-0" />
                      {file.filename}
                    </div>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#010409] text-[#8b949e] font-sans border border-[#30363d]">
                      {file.category}
                    </span>
                  </div>
                  <span className="text-[11px] text-[#8b949e] leading-snug line-clamp-2">
                    {file.title}
                  </span>
                </button>
              ))
            ) : (
              C_SOURCE_FILES.map(file => (
                <button
                  key={file.filename}
                  onClick={() => setSelectedCFile(file)}
                  className={`w-full text-left p-3 rounded-lg border transition flex flex-col gap-1 ${
                    selectedCFile.filename === file.filename
                      ? 'bg-[#21262d] border-[#58a6ff] ring-1 ring-[#58a6ff]/30 text-[#f0f6fc]'
                      : 'bg-[#161b22] border-[#30363d] hover:bg-[#21262d] hover:border-[#8b949e] text-[#c9d1d9]'
                  }`}
                >
                  <div className="flex items-center justify-between w-full">
                    <div className="flex items-center gap-2 font-mono text-xs font-bold">
                      <FileCode className="w-3.5 h-3.5 text-[#58a6ff] flex-shrink-0" />
                      {file.filename}
                    </div>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#010409] text-[#8b949e] font-sans border border-[#30363d]">
                      {file.category}
                    </span>
                  </div>
                  <span className="text-[11px] text-[#8b949e] leading-snug line-clamp-2">
                    {file.title}
                  </span>
                </button>
              ))
            )}
          </div>

          {/* Deployment Card */}
          <div className="bg-[#161b22] border border-[#30363d] p-3 rounded-lg space-y-1.5 mt-3 text-xs text-[#8b949e]">
            <span className="font-semibold text-[#f0f6fc] flex items-center gap-1.5">
              <Cpu className="w-3.5 h-3.5 text-[#58a6ff]" />
              {suiteLanguage === 'rust' ? 'Rust Build & Container Deployment' : 'POSIX C Cross-Compilation'}
            </span>
            {suiteLanguage === 'rust' ? (
              <div className="space-y-1 text-[11px] leading-relaxed">
                <p>
                  To compile on your Linux host: <code className="text-[#f0883e] font-mono">cargo build --release</code>
                </p>
                <p>
                  To run with Podman: <code className="text-[#58a6ff] font-mono">podman build -t octolan-rs -f Dockerfile.rust .</code>
                </p>
              </div>
            ) : (
              <p className="text-[11px] leading-relaxed">
                Compile with <code className="text-[#f0f6fc] font-mono">make</code> or <code className="text-[#f0f6fc] font-mono">gcc -O2</code> for direct execution on standard Linux, OpenWrt, or Termux.
              </p>
            )}
          </div>
        </div>

        {/* Right Area: Code Display & Compiler Instructions & Interactive Execution */}
        <div className="lg:col-span-8 space-y-3">
          {/* File Meta Bar */}
          <div className="bg-[#161b22] border border-[#30363d] p-3.5 rounded-lg space-y-2.5">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <h3 className="text-sm font-bold text-[#f0f6fc]">{activeFile.title}</h3>
                <span className="text-xs text-[#8b949e] mt-0.5 block">{activeFile.description}</span>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={handleCopy}
                  className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#21262d] hover:bg-[#30363d] text-[#c9d1d9] text-xs font-semibold border border-[#30363d] transition"
                >
                  {copied ? <Check className="w-3 h-3 text-[#7ee787]" /> : <Copy className="w-3 h-3" />}
                  {copied ? 'Copied' : 'Copy Code'}
                </button>
              </div>
            </div>

            {/* View Mode Toggle: Source vs Simulator */}
            <div className="flex items-center justify-between pt-1 border-t border-[#30363d]">
              <div className="flex items-center gap-1 bg-[#010409] p-1 rounded border border-[#30363d]">
                <button
                  onClick={() => setActiveTab('source')}
                  className={`flex items-center gap-1.5 px-3 py-1 rounded text-xs font-medium transition ${
                    activeTab === 'source'
                      ? suiteLanguage === 'rust' ? 'bg-[#f0883e] text-white' : 'bg-[#238636] text-white'
                      : 'text-[#8b949e] hover:text-[#c9d1d9]'
                  }`}
                >
                  <FileCode className="w-3 h-3" /> {suiteLanguage === 'rust' ? 'Rust Source View' : 'C99 Source View'}
                </button>
                <button
                  onClick={() => {
                    setActiveTab('terminal');
                    if (terminalOutput.length === 0) runSimulation();
                  }}
                  className={`flex items-center gap-1.5 px-3 py-1 rounded text-xs font-medium transition ${
                    activeTab === 'terminal'
                      ? suiteLanguage === 'rust' ? 'bg-[#f0883e] text-white' : 'bg-[#238636] text-white'
                      : 'text-[#8b949e] hover:text-[#c9d1d9]'
                  }`}
                >
                  <Terminal className="w-3 h-3" /> {suiteLanguage === 'rust' ? 'Cargo Runner Simulation' : 'POSIX Simulation Console'}
                </button>
              </div>

              <div className="hidden sm:flex items-center gap-1.5">
                {activeFile.capabilities.slice(0, 2).map((cap, i) => (
                  <span key={i} className="text-[10px] px-2 py-0.5 rounded bg-[#010409] border border-[#30363d] text-[#58a6ff] font-medium">
                    ✓ {cap}
                  </span>
                ))}
              </div>
            </div>
          </div>

          {/* Tab 1: Source Code Viewer */}
          {activeTab === 'source' && (
            <div className="bg-[#010409] border border-[#30363d] rounded-lg overflow-hidden space-y-0">
              {/* Compiler Header Bar */}
              <div className="bg-[#161b22] px-4 py-2 border-b border-[#30363d] flex items-center justify-between text-xs font-mono">
                <div className="text-[#8b949e] flex items-center gap-2">
                  <span className="text-[#58a6ff] font-bold">{activeFile.filename}</span>
                  <span className="hidden sm:inline text-[11px]">• {activeFile.requirements}</span>
                </div>
                <div className="text-[11px] text-[#8b949e]">
                  {activeFile.code.split('\n').length} lines
                </div>
              </div>

              {/* Code Pre Box */}
              <pre className="p-4 text-xs font-mono text-[#c9d1d9] overflow-x-auto max-h-[500px] leading-relaxed select-text">
                <code>{activeFile.code}</code>
              </pre>

              {/* Quick CLI Invocation footer */}
              <div className="bg-[#161b22] p-3 border-t border-[#30363d] flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono">
                <span className="text-[#8b949e] font-sans font-semibold">Build & Execution Command:</span>
                <div className="bg-[#010409] px-2.5 py-1 rounded border border-[#30363d] text-[#7ee787] font-mono text-[11px] overflow-x-auto">
                  {activeFile.compilationCmd.split('\n')[0]}
                </div>
              </div>
            </div>
          )}

          {/* Tab 2: Terminal Simulator */}
          {activeTab === 'terminal' && (
            <div className="bg-[#010409] border border-[#30363d] rounded-lg overflow-hidden">
              {/* Terminal Title Bar */}
              <div className="bg-[#161b22] px-4 py-2 border-b border-[#30363d] flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="flex gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-full bg-[#f85149]" />
                    <span className="w-2.5 h-2.5 rounded-full bg-[#d29922]" />
                    <span className="w-2.5 h-2.5 rounded-full bg-[#238636]" />
                  </div>
                  <span className="text-xs font-mono text-[#8b949e]">
                    {suiteLanguage === 'rust' ? 'octolan-rs (Tokio Runtime Simulator)' : 'tty1: bash-simulation'}
                  </span>
                </div>
                <button
                  onClick={runSimulation}
                  disabled={isExecuting}
                  className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#21262d] hover:bg-[#30363d] text-xs font-mono text-[#58a6ff] transition"
                >
                  <RefreshCw className={`w-3 h-3 ${isExecuting ? 'animate-spin' : ''}`} />
                  <span>Re-Run</span>
                </button>
              </div>

              {/* Console Output Area */}
              <div className="p-4 font-mono text-xs text-[#c9d1d9] space-y-1 min-h-[300px] max-h-[460px] overflow-y-auto">
                {terminalOutput.map((line, i) => (
                  <div 
                    key={i} 
                    className={`${
                      line.startsWith('$') ? 'text-[#58a6ff] font-bold mt-2' :
                      line.startsWith('[✓]') || line.includes('INFO') ? 'text-[#7ee787]' :
                      line.startsWith('[!]') || line.includes('WARN') ? 'text-[#f85149] font-bold' :
                      line.startsWith('[+]') ? 'text-[#f0f6fc]' : 'text-[#8b949e]'
                    }`}
                  >
                    {line}
                  </div>
                ))}

                {isExecuting && (
                  <div className="text-[#58a6ff] animate-pulse flex items-center gap-1.5 pt-2">
                    <RefreshCw className="w-3 h-3 animate-spin" /> Compiling and executing target binary...
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
