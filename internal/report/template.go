package report

const reportHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{if .S.Site}}{{.S.Site}} · {{end}}Network Assessment</title>
<style>
:root{--ink:#0f172a;--muted:#475569;--line:#e2e8f0;--bg:#fff;--soft:#f8fafc;--accent:#0f766e;
--critical:#b91c1c;--high:#dc2626;--medium:#d97706;--low:#2563eb;--info:#64748b}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.page{max-width:1080px;margin:0 auto;padding:40px 32px}
header.cover{display:flex;gap:32px;align-items:center;border-bottom:3px solid var(--accent);padding-bottom:28px;margin-bottom:28px}
.brand{font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:var(--accent);font-weight:700}
h1{font-size:30px;margin:6px 0 4px;line-height:1.2}
h2{font-size:20px;margin:36px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--line)}
h3{font-size:15px;margin:0 0 4px}
.muted{color:var(--muted)}
.gauge{flex:none;text-align:center}
.gauge .g{font-size:34px;font-weight:800}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:20px 0}
.kpi{background:var(--soft);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.kpi b{display:block;font-size:24px}
.kpi span{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em}
.sev{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:#fff}
.sev.critical{background:var(--critical)}.sev.high{background:var(--high)}.sev.medium{background:var(--medium)}.sev.low{background:var(--low)}.sev.info{background:var(--info)}
.finding{border:1px solid var(--line);border-left:5px solid var(--info);border-radius:8px;padding:14px 16px;margin:12px 0;break-inside:avoid}
.finding.critical{border-left-color:var(--critical)}.finding.high{border-left-color:var(--high)}.finding.medium{border-left-color:var(--medium)}.finding.low{border-left-color:var(--low)}
.finding .fix{background:#f0fdfa;border-radius:6px;padding:8px 10px;margin-top:8px}
.finding ul{margin:6px 0 0;padding-left:18px;columns:2;font-size:13px}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{background:var(--soft);font-weight:600;position:sticky;top:0}
td.mono,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:20px}
.card{border:1px solid var(--line);border-radius:10px;padding:14px 16px}
#map{height:620px;border:1px solid var(--line);border-radius:10px;background:var(--soft);overflow:hidden}
.bar{height:8px;background:var(--line);border-radius:4px;overflow:hidden}
.bar i{display:block;height:100%;background:var(--accent)}
.eol{color:var(--high);font-weight:600}
footer{margin-top:40px;color:var(--muted);font-size:12px;border-top:1px solid var(--line);padding-top:12px}
@media (max-width:760px){header.cover{flex-direction:column;align-items:flex-start}.grid2{grid-template-columns:1fr}.finding ul{columns:1}}
@media print{.page{padding:0}h2{break-after:avoid}#map{height:520px}.noprint{display:none}a{color:inherit;text-decoration:none}}
</style>
</head>
<body>
<div class="page">
<header class="cover">
  <div class="gauge">
    <svg width="132" height="132" viewBox="0 0 132 132" role="img" aria-label="Score {{.S.Score}}">
      <circle cx="66" cy="66" r="52" fill="none" stroke="#e2e8f0" stroke-width="14"/>
      <circle cx="66" cy="66" r="52" fill="none" stroke="{{.GaugeColor}}" stroke-width="14" stroke-linecap="round"
        stroke-dasharray="{{.GaugeDash}}" transform="rotate(-90 66 66)"/>
      <text x="66" y="72" text-anchor="middle" font-size="30" font-weight="800" fill="#0f172a">{{if ge .S.Score 0}}{{.S.Score}}{{else}}–{{end}}</text>
      <text x="66" y="94" text-anchor="middle" font-size="12" fill="#475569">out of 100</text>
    </svg>
    <div class="g" style="color:{{.GaugeColor}}">Grade {{if .S.Grade}}{{.S.Grade}}{{else}}–{{end}}</div>
  </div>
  <div>
    <div class="brand">OcuLAN network assessment</div>
    <h1>{{if .S.Site}}{{.S.Site}}{{else}}Network Assessment{{end}}</h1>
    <div class="muted">{{.Generated}}{{if .Duration}} · scan time {{.Duration}}{{end}} · collector {{.S.Collector}} ({{.S.Caps.OS}}/{{.S.Caps.Arch}})</div>
    <p style="margin:12px 0 0;max-width:640px">{{.Summary}}</p>
  </div>
</header>

<div class="kpis">
  <div class="kpi"><b>{{len .S.Devices}}</b><span>Devices</span></div>
  <div class="kpi"><b>{{.Infra}}</b><span>Infrastructure</span></div>
  <div class="kpi"><b>{{len .S.Subnets}}</b><span>Subnets</span></div>
  <div class="kpi"><b>{{len .S.VLANs}}</b><span>VLANs</span></div>
  <div class="kpi"><b style="color:var(--critical)">{{index .SevCount "critical"}}</b><span>Critical</span></div>
  <div class="kpi"><b style="color:var(--high)">{{index .SevCount "high"}}</b><span>High</span></div>
  <div class="kpi"><b style="color:var(--medium)">{{index .SevCount "medium"}}</b><span>Medium</span></div>
  <div class="kpi"><b class="{{if .EOL}}eol{{end}}">{{.EOL}}</b><span>End-of-life</span></div>
</div>

{{if .Top}}
<h2>Priority actions</h2>
<table>
<tr><th style="width:90px">Severity</th><th>Issue</th><th style="width:90px">Affected</th></tr>
{{range .Top}}<tr><td><span class="sev {{.Severity}}">{{.Severity}}</span></td><td><b>{{.Title}}</b><br><span class="muted">{{.Remediation}}</span></td><td>{{if .Devices}}{{len .Devices}} device(s){{else}}network{{end}}</td></tr>{{end}}
</table>
{{end}}

<h2>Network overview</h2>
<div class="grid2">
  <div class="card">
    <h3>Subnets</h3>
    <table>{{range .S.Subnets}}<tr><td class="mono">{{.CIDR}}</td><td>{{if .Local}}collector segment{{else}}scanned{{end}}{{if .Gateway}} · gateway {{.Gateway}}{{end}}</td></tr>{{else}}<tr><td class="muted">none recorded</td></tr>{{end}}</table>
    <h3 style="margin-top:14px">DHCP servers</h3>
    <table>{{range .S.DHCPServers}}<tr><td class="mono">{{.IP}}</td><td>router {{.Router}} · DNS {{join .DNS ", "}}{{if .Domain}} · {{.Domain}}{{end}}</td></tr>{{else}}<tr><td class="muted">none observed during the listening window</td></tr>{{end}}</table>
  </div>
  <div class="card">
    <h3>Device mix</h3>
    {{range .TypeCount}}<div style="display:flex;gap:10px;align-items:center;margin:5px 0"><span style="width:110px">{{title .K}}</span><div class="bar" style="flex:1"><i style="width:{{.Pct}}%;min-width:4px"></i></div><b style="width:32px;text-align:right">{{.V}}</b></div>{{end}}
    <h3 style="margin-top:14px">Layer 2</h3>
    <div>{{if .S.Storm.STP.Seen}}{{.S.Storm.STP.Protocol}} root bridge <span class="mono">{{.S.Storm.STP.RootBridge}}</span>, {{.S.Storm.STP.TopologyChanges}} topology change(s) observed.{{else}}No spanning-tree BPDUs heard on the collector port.{{end}}</div>
    <div>{{if .S.Storm.Series}}Peak broadcast+multicast: <b>{{.S.Storm.Peak.Broadcast}}</b> bcast / <b>{{.S.Storm.Peak.Multicast}}</b> mcast pps.{{else}}Storm Guard was not running (requires raw capture).{{end}}</div>
  </div>
</div>

<h2>Topology</h2>
<p class="muted">Solid lines are LLDP/CDP adjacencies, dashed lines come from switch MAC tables, dotted lines are inferred from subnet membership. Drag to pan, scroll to zoom.</p>
<div id="map"></div>

<h2>Findings</h2>
{{range .S.Findings}}
<div class="finding {{.Severity}}">
  <div style="display:flex;justify-content:space-between;gap:12px"><h3>{{.Title}}</h3><span><span class="muted" style="font-size:12px;margin-right:8px">{{.Category}}</span><span class="sev {{.Severity}}">{{.Severity}}</span></span></div>
  <div>{{.Detail}}</div>
  <div class="fix"><b>Recommendation:</b> {{.Remediation}}</div>
  {{if .Devices}}<ul>{{range .Devices}}<li>{{devname $.ByID .}}</li>{{end}}</ul>{{end}}
</div>
{{else}}<p>No findings.</p>{{end}}

<h2>Device inventory</h2>
<table>
<tr><th>Name</th><th>IP</th><th>MAC / vendor</th><th>Type</th><th>Operating system</th><th>Open TCP ports</th><th>Latency</th></tr>
{{range .S.Devices}}<tr>
<td><b>{{label .}}</b>{{if .Model}}<br><span class="muted">{{.Model}}</span>{{end}}{{if .Serial}}<br><span class="muted mono">S/N {{.Serial}}</span>{{end}}</td>
<td class="mono">{{range $i, $ip := .IPs}}{{if $i}}<br>{{end}}{{$ip}}{{end}}</td>
<td class="mono">{{.MAC}}<br><span class="muted" style="font-family:inherit">{{.Vendor}}</span></td>
<td>{{title (printf "%s" .Type)}}</td>
<td>{{if .OS.Name}}{{.OS.Name}}{{else}}{{.OS.Family}}{{end}}{{if .OS.EOL}} <span class="eol">EOL</span>{{end}}</td>
<td class="mono">{{ports .}}</td>
<td>{{rtt .RTTMicro}}</td>
</tr>{{end}}
</table>

{{if .Talkers}}
<h2>Traffic (NetFlow / IPFIX)</h2>
<div class="grid2">
<div class="card"><h3>Top talkers</h3><table>{{range .Talkers}}<tr><td class="mono">{{.Key}}</td><td style="text-align:right">{{bytes .Bytes}}</td></tr>{{end}}</table></div>
<div class="card"><h3>Top applications</h3><table>{{range .Apps}}<tr><td>{{.Key}}</td><td style="text-align:right">{{bytes .Bytes}}</td></tr>{{end}}</table></div>
</div>
{{end}}

<h2>Methodology</h2>
<p>The assessment combined active discovery (ARP and ICMP sweeps, TCP service checks, SNMP polling, SMB/NTLM and TLS inspection, reverse DNS, NetBIOS and mDNS) with passive listening (DHCP, LLDP/CDP, mDNS/SSDP, spanning tree and broadcast metering). No credentials were used other than the SNMP communities supplied, and no exploits or intrusive tests were run.</p>
<table>
<tr><th>Phase</th><th>Result</th><th>Detail</th></tr>
{{range .Phases}}<tr><td>{{.Name}}</td><td>{{.State}}</td><td>{{.Detail}}</td></tr>{{end}}
</table>
<p class="muted">Collector capabilities: raw capture {{if .S.Caps.RawCapture}}available{{else}}unavailable{{if .S.Caps.CaptureNote}} ({{.S.Caps.CaptureNote}}){{end}}{{end}}; ICMP mode {{.S.Caps.ICMPMode}}.</p>

<footer>Generated by OcuLAN {{.S.Version}} · {{.Generated}} · This report reflects the network as observed from the collector's position during the assessment window.</footer>
</div>
<script>{{.MapJS}}</script>
<script>
(function(){var data={{.MapJSON}};var el=document.getElementById('map');if(window.OcuMap&&el){OcuMap.render(el,data,{static:false,light:true});}})();
</script>
</body>
</html>`
