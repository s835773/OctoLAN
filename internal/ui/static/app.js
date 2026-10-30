/* OctoLAN dashboard. Vanilla JS, no build step, no CDN. */
(function () {
  'use strict';

  // ---------- helpers ----------
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function api(path, opts) {
    opts = opts || {};
    if (opts.body && typeof opts.body !== 'string') {
      opts.body = JSON.stringify(opts.body);
      opts.headers = { 'Content-Type': 'application/json' };
    }
    return fetch(path, opts).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) {
        if (!r.ok) throw new Error(j.error || r.statusText);
        return j;
      });
    });
  }
  function fmtBytes(b) {
    if (!b) return '0 B';
    var u = ['B', 'KB', 'MB', 'GB', 'TB'], i = Math.min(4, Math.floor(Math.log(b) / Math.log(1024)));
    return (b / Math.pow(1024, i)).toFixed(i ? 1 : 0) + ' ' + u[i];
  }
  function fmtBits(b) {
    if (!b) return '0 bps';
    var u = ['bps', 'Kbps', 'Mbps', 'Gbps'], i = Math.min(3, Math.floor(Math.log(b) / Math.log(1000)));
    return (b / Math.pow(1000, i)).toFixed(1) + ' ' + u[i];
  }
  function fmtNum(n) { return (n || 0).toLocaleString(); }
  function fmtRTT(us) { if (!us) return ''; return us < 1000 ? us + ' µs' : (us / 1000).toFixed(1) + ' ms'; }
  function ago(t) {
    if (!t) return '';
    var s = (Date.now() - new Date(t).getTime()) / 1000;
    if (s < 60) return Math.max(0, Math.floor(s)) + 's ago';
    if (s < 3600) return Math.floor(s / 60) + 'm ago';
    if (s < 86400) return Math.floor(s / 3600) + 'h ago';
    return new Date(t).toLocaleDateString();
  }
  // Go encodes "no date" as year 1; treat anything before 1971 as unknown.
  function realDate(t) { if (!t) return null; var d = new Date(t); return isNaN(d) || d.getFullYear() < 1971 ? null : d; }
  function hhmmss(t) { return new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }); }
  var CFG_ISSUES = { 'enable-password-plaintext': 'Weak enable password', 'no-service-password-encryption': 'No password encryption',
    'vty-telnet': 'Telnet on VTY', 'http-server': 'HTTP server on', 'snmp-rw-community': 'SNMP RW community', 'no-remote-syslog': 'No remote syslog',
    'no-ntp': 'No NTP', 'local-user-weak-hash': 'Weak local user hash', 'no-aaa': 'AAA off', 'smart-install': 'Smart Install on',
    'forti-http-admin': 'HTTP admin access', 'routeros-insecure-services': 'Insecure services' };
  var TYPE_LABELS = { 'voip-phone': 'VoIP phone', nas: 'NAS', ups: 'UPS', iot: 'IoT', 'access-point': 'Access point' };
  function title(s) { if (TYPE_LABELS[s]) return TYPE_LABELS[s]; s = String(s || '').replace(/-/g, ' '); return s.charAt(0).toUpperCase() + s.slice(1); }
  function md(s) { return esc(s).replace(/`([^`]+)`/g, '<code>$1</code>'); }
  function label(d) {
    if (d.hostname) { var h = d.hostname; var i = h.indexOf('.'); return (i > 0 && !/^\d+\.\d+\.\d+\.\d+$/.test(h)) ? h.slice(0, i) : h; }
    if (d.snmp && d.snmp.sysName) return d.snmp.sysName;
    return (d.ips && d.ips[0]) || d.mac || d.id;
  }
  function osName(d) { return (d.os && (d.os.name || d.os.family)) || ''; }
  var debounceT = {};
  function debounce(key, fn, ms) { clearTimeout(debounceT[key]); debounceT[key] = setTimeout(fn, ms); }
  function toast(msg, sev) {
    var t = document.createElement('div');
    t.className = 'toast ' + (sev || '');
    t.textContent = msg;
    $('#toasts').appendChild(t);
    setTimeout(function () { t.remove(); }, sev === 'critical' || sev === 'high' ? 9000 : 4500);
  }
  function store(k, v) { try { if (v === undefined) return localStorage.getItem(k); localStorage.setItem(k, v); } catch (e) { return null; } }

  var TYPE_COLORS = window.OctoMap ? OctoMap.colors : {};
  var SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
  var SEV_COLORS = { critical: 'var(--critical)', high: 'var(--high)', medium: 'var(--medium)', low: 'var(--low)', info: 'var(--info)' };

  // ---------- state ----------
  var S = { state: null, devices: [], topology: null, findings: null, events: [], flows: null, storm: null, l2: null };
  var current = 'overview', mapInst = null, mapOpts = { infraOnly: false };
  var devFilter = { q: '', type: '', sort: 'ip', dir: 1, alive: false };

  function loadState() { return api('/api/state').then(function (s) { S.state = s; chrome(); return s; }); }
  function loadDevices() { return api('/api/devices').then(function (d) { S.devices = d || []; return d; }); }
  function loadFindings() { return api('/api/findings').then(function (f) { S.findings = f; return f; }); }
  function loadTopology() { return api('/api/topology').then(function (t) { S.topology = t; return t; }); }
  function loadEvents() { return api('/api/events?n=400').then(function (e) { S.events = e || []; return e; }); }
  function loadFlows() { return api('/api/flows').then(function (f) { S.flows = f; return f; }); }
  function loadStorm() { return api('/api/storm').then(function (s) { S.storm = s; return s; }); }
  function loadL2() { return api('/api/l2').then(function (s) { S.l2 = s; return s; }); }

  // ---------- chrome (sidebar, top bar) ----------
  function chrome() {
    var s = S.state; if (!s) return;
    $('#ver').textContent = 'OctoLAN ' + s.version + ' · ' + s.capabilities.os + '/' + s.capabilities.arch;
    var siteInput = $('#site-name');
    if (document.activeElement !== siteInput) siteInput.value = s.site || '';
    document.title = (s.site ? s.site + ' · ' : '') + 'OctoLAN';
    $('#nav-devices').textContent = s.counts.devices || '';
    var sevN = (s.severity.critical || 0) + (s.severity.high || 0);
    $('#nav-findings').textContent = s.counts.findings ? (sevN ? sevN + ' ⚠' : s.counts.findings) : '';
    var dot = $('#nav-storm'); dot.className = 'dot ' + (s.storm.running ? s.storm.state : '');
    var c = s.capabilities;
    $('#cap-pill').innerHTML = (c.rawCapture
      ? '<span class="status ok">Raw capture on ' + esc(c.defaultIface) + '</span>'
      : '<span class="status warn">Limited mode</span><br><span style="opacity:.8">' + esc(c.captureNote || '') + '</span>') +
      '<br><span style="opacity:.8">ICMP: ' + esc(c.icmpMode) + ' · ' + esc(c.hostname) + '</span>';
    scanChrome(s.scan);
  }

  function scanChrome(sc) {
    if (!sc) return;
    var running = !!sc.running;
    $('#scanbar').hidden = !running && !(sc.finished && Date.now() - new Date(sc.finished).getTime() < 8000);
    $('#scan-phase').textContent = running ? sc.phase : (sc.message || 'Done');
    $('#scan-msg').textContent = running ? (sc.message || '') : '';
    $('#scan-prog').style.width = Math.round((sc.progress || 0) * 100) + '%';
    $('#stop-btn').hidden = !running;
    $('#scan-btn').disabled = running;
    $('#scan-btn').textContent = running ? 'Scanning…' : 'New assessment';
  }

  // ---------- router ----------
  var views = {};
  function route() {
    var v = (location.hash.replace(/^#\//, '') || 'overview').split('?')[0];
    if (!views[v]) v = 'overview';
    if (mapInst && v !== 'map') { mapInst.destroy(); mapInst = null; }
    current = v;
    $$('#nav a').forEach(function (a) { a.classList.toggle('active', a.dataset.v === v); });
    $('#side').classList.remove('open');
    views[v](true);
    // Deep link: #/devices?dev=<id>&tab=host opens a device's drawer.
    var qs = (location.hash.split('?')[1] || '').split('&').reduce(function (o, kv) { var p = kv.split('='); if (p[0]) o[p[0]] = decodeURIComponent(p[1] || ''); return o; }, {});
    if (qs.dev) { if (qs.tab) drawerTab = qs.tab; setTimeout(function () { openDevice(qs.dev); }, 300); }
  }
  function refreshCurrent() { if (views[current]) views[current](false); }

  // ---------- Overview ----------
  views.overview = function () {
    Promise.all([loadState(), loadFindings(), loadEvents(), loadDevices()]).then(function () {
      var s = S.state, view = $('#view');
      if (!s.counts.devices && !s.scan.running) { view.innerHTML = welcome(s); bindWelcome(); return; }
      var sev = s.severity, f = (S.findings && S.findings.findings) || [];
      var score = s.score < 0 ? null : s.score;
      var col = score == null ? 'var(--muted)' : score >= 80 ? 'var(--ok)' : score >= 60 ? 'var(--medium)' : 'var(--critical)';
      var total = SEV_ORDER.reduce(function (a, k) { return a + (sev[k] || 0); }, 0) || 1;
      var types = Object.keys(s.types).map(function (k) { return [k, s.types[k]]; }).sort(function (a, b) { return b[1] - a[1]; });
      var maxT = types.length ? types[0][1] : 1;
      var ps = s.passive || {};
      var pkts = ps.protocols || {};
      view.innerHTML =
        '<div class="grid cols-4">' +
        '<div class="card"><h3>Posture score</h3><div class="score">' + gauge(score, col) +
        '<div><div class="grade" style="color:' + col + '">' + esc(s.grade || '–') + '</div><div class="muted small">' + (score == null ? 'run an assessment' : 'of 100') + '</div></div></div></div>' +
        kpi(s.counts.devices, 'Devices', (s.counts.alive || 0) + ' responding') +
        kpi(s.counts.infrastructure || 0, 'Infrastructure', (s.counts.snmp || 0) + ' via SNMP · ' + (s.counts.links || 0) + ' links') +
        kpi((sev.critical || 0) + (sev.high || 0), 'Critical / high issues', (s.counts.findings || 0) + ' findings total' + (s.counts.eol ? ' · ' + s.counts.eol + ' EOL' : ''), (sev.critical || sev.high) ? 'var(--high)' : '') +
        '</div>' +
        '<div class="grid cols-3" style="margin-top:16px">' +
        '<div class="card span-2"><h3>Top findings <a class="right" href="#/findings">View all →</a></h3>' +
        '<div class="sevbar" style="margin-bottom:12px">' + SEV_ORDER.map(function (k) { return sev[k] ? '<i title="' + k + '" style="width:' + (sev[k] / total * 100) + '%;background:' + SEV_COLORS[k] + '"></i>' : ''; }).join('') + '</div>' +
        (f.length ? '<ul class="list">' + f.slice(0, 7).map(function (x) {
          return '<li><span class="sev ' + x.severity + '">' + x.severity + '</span><span style="flex:1">' + esc(x.title) + '</span><span class="muted small">' + (x.devices ? x.devices.length + ' device' + (x.devices.length > 1 ? 's' : '') : 'network') + '</span></li>';
        }).join('') + '</ul>' : '<p class="muted">No findings yet.</p>') + '</div>' +
        '<div class="card"><h3>Device mix</h3><div class="bars">' + types.map(function (t) {
          return '<div class="row"><span style="display:flex;gap:8px;align-items:center"><span class="tdot" style="background:' + (TYPE_COLORS[t[0]] || '#999') + '"></span>' + esc(title(t[0])) + '</span><div class="track"><i style="width:' + (t[1] / maxT * 100) + '%;background:' + (TYPE_COLORS[t[0]] || 'var(--accent)') + '"></i></div><span class="num">' + t[1] + '</span></div>';
        }).join('') + '</div></div>' +
        '</div>' +
        '<div class="grid cols-3" style="margin-top:16px">' +
        '<div class="card"><h3>Network</h3><dl class="kv">' +
        s.subnets.map(function (n) { return '<dt>' + (n.local ? 'Local subnet' : 'Subnet') + '</dt><dd class="mono">' + esc(n.cidr) + (n.gateway ? ' <span class="muted">gw ' + esc(n.gateway) + '</span>' : '') + '</dd>'; }).join('') +
        '<dt>DHCP servers</dt><dd>' + (s.dhcp.length ? s.dhcp.map(function (d) { return '<span class="mono">' + esc(d.ip) + '</span>'; }).join(', ') + (s.dhcp.length > 1 ? ' <span class="sev high">rogue?</span>' : '') : '<span class="muted">none heard yet</span>') + '</dd>' +
        '<dt>VLANs</dt><dd>' + (s.vlanCount || '<span class="muted">none seen</span>') + '</dd></dl></div>' +
        '<div class="card"><h3>Monitors</h3><dl class="kv">' +
        '<dt>Passive listener</dt><dd>' + (ps.running ? '<span class="status ok">' + esc(ps.mode) + ' on ' + esc(ps.iface) + '</span><div class="sub">' + fmtNum(ps.packets) + ' packets · ' + Object.keys(pkts).sort().map(function (k) { return k + ' ' + fmtNum(pkts[k]); }).join(', ') + '</div>' : '<span class="status">off</span>') + '</dd>' +
        '<dt>Storm Guard</dt><dd>' + (!s.storm.running && s.storm.state && s.storm.state !== 'off' && s.storm.state !== 'unavailable' ? '<span class="status">saved session</span> <span class="muted">state ' + esc(s.storm.state) + '</span> <a href="#/storm">view</a>' : s.storm.running ? '<span class="status ' + (s.storm.state === 'ok' ? 'ok' : s.storm.state === 'warning' ? 'warn' : 'bad') + '">' + esc(s.storm.state) + '</span> <span class="muted">' + fmtNum(s.storm.bcast) + ' bcast+mcast pps</span>' : '<span class="status warn">unavailable</span><div class="sub">' + esc(s.storm.error || '') + '</div>') + '</dd>' +
        '<dt>NetFlow</dt><dd>' + (!s.netflow.listening && s.netflow.flows ? '<span class="status">saved session</span><div class="sub">' + fmtNum(s.netflow.flows) + ' flows · <a href="#/traffic">view</a></div>' : s.netflow.listening ? '<span class="status ok">listening ' + esc(s.netflow.addr) + '</span><div class="sub">' + s.netflow.exporters + ' exporter(s), ' + fmtNum(s.netflow.flows) + ' flows</div>' : '<span class="status">off</span> <a href="#/traffic">enable</a>') + '</dd>' +
        '</dl></div>' +
        '<div class="card"><h3>Recent activity <a class="right" href="#/activity">All →</a></h3><ul class="list">' + S.events.slice(-8).reverse().map(evRow).join('') + '</ul></div>' +
        '</div>' +
        (s.scan.phases && s.scan.phases.length ? '<div class="card" style="margin-top:16px"><h3>Last assessment <span class="right muted">' + (s.scan.started ? new Date(s.scan.started).toLocaleString() : '') + '</span></h3>' + phasesHTML(s.scan.phases) + '</div>' : '');
    });
  };

  function welcome(s) {
    var c = s.capabilities;
    return '<div class="hero"><div><h1>Ready to assess ' + esc(s.site || 'this network') + '</h1>' +
      '<p>OctoLAN maps the network from this laptop: discovery, SNMP inventory, topology, traffic and a scored security posture report.</p>' +
      '<p><button class="primary" id="go-scan">Start assessment</button> <button class="ghost" id="go-passive">Passive only</button></p></div>' +
      '<div class="card"><h3>This collector</h3><dl class="kv">' +
      '<dt>Host</dt><dd>' + esc(c.hostname) + ' (' + esc(c.os) + '/' + esc(c.arch) + ')</dd>' +
      '<dt>Interface</dt><dd>' + esc(c.defaultIface || 'none') + '</dd>' +
      '<dt>Raw capture</dt><dd>' + (c.rawCapture ? '<span class="status ok">available</span>' : '<span class="status warn">unavailable</span><div class="sub">' + esc(c.captureNote) + '</div>') + '</dd>' +
      '<dt>ICMP</dt><dd>' + esc(c.icmpMode) + '</dd></dl>' +
      (c.rawCapture ? '' : '<p class="muted small" style="margin-bottom:0">Without raw capture OctoLAN still discovers via ping, the OS ARP cache, TCP, SNMP, SMB, DNS, NetBIOS and mDNS. ARP sweeps, passive DHCP/LLDP/STP and Storm Guard need it.</p>') +
      '</div></div>';
  }
  function bindWelcome() {
    var a = $('#go-scan'), b = $('#go-passive');
    if (a) a.onclick = function () { openScan(false); };
    if (b) b.onclick = function () { openScan(true); };
  }
  function kpi(v, l, sub, color) {
    return '<div class="card kpi"><h3>' + esc(l) + '</h3><div class="v"' + (color ? ' style="color:' + color + '"' : '') + '>' + fmtNum(v) + '</div><div class="s muted">' + esc(sub || '') + '</div></div>';
  }
  function gauge(score, col) {
    var c = 2 * Math.PI * 36, v = score == null ? 0 : score;
    return '<svg width="96" height="96" viewBox="0 0 96 96"><circle cx="48" cy="48" r="36" fill="none" stroke="var(--line)" stroke-width="10"/>' +
      '<circle cx="48" cy="48" r="36" fill="none" stroke="' + col + '" stroke-width="10" stroke-linecap="round" stroke-dasharray="' + (c * v / 100) + ' ' + c + '" transform="rotate(-90 48 48)"/>' +
      '<text x="48" y="55" text-anchor="middle" font-size="22" font-weight="800" fill="currentColor">' + (score == null ? '–' : score) + '</text></svg>';
  }
  function evRow(e) {
    var dev = e.deviceId ? ' <a href="#" data-dev="' + esc(e.deviceId) + '">view</a>' : '';
    return '<li><span class="t">' + hhmmss(e.time) + '</span>' + (e.severity !== 'info' ? '<span class="sev ' + e.severity + '">' + e.severity + '</span>' : '') +
      '<span style="flex:1">' + esc(e.message) + dev + '</span><span class="muted small">' + esc(e.source) + '</span></li>';
  }
  function phasesHTML(ph) {
    return '<div class="phases">' + ph.map(function (p) {
      return '<div class="phase ' + p.state + '"><span class="ic"></span><b>' + esc(p.name) + '</b><span class="d muted">' + esc(p.detail || '') + '</span><span class="muted small" style="text-align:right">' + (p.durationMs ? (p.durationMs / 1000).toFixed(1) + 's' : p.state === 'skipped' ? 'skipped' : '') + '</span></div>';
    }).join('') + '</div>';
  }

  // ---------- Map ----------
  views.map = function (first) {
    loadTopology().then(function (t) {
      if (mapInst && !first) { mapInst.update(t, mapOpts); return; }
      var types = {};
      (t.nodes || []).forEach(function (n) { types[n.type] = 1; });
      $('#view').innerHTML = '<div class="mapbox"><div class="ctrl">' +
        '<input type="search" id="map-q" placeholder="Find device…">' +
        '<button class="ghost small" id="map-infra">' + (mapOpts.infraOnly ? 'Show all devices' : 'Infrastructure only') + '</button>' +
        '<button class="ghost small" id="map-fit">Fit</button><button class="ghost small" id="map-relayout">Re-layout</button></div>' +
        '<div id="mapsvg"></div><div class="legend">' + Object.keys(types).sort().map(function (k) {
          return '<span><span class="tdot" style="background:' + (TYPE_COLORS[k] || '#999') + '"></span>' + esc(title(k)) + '</span>';
        }).join('') + '<span>━ LLDP/CDP</span><span>╍ MAC table</span><span>┈ inferred</span></div></div>';
      var opts = Object.assign({ scale: 1.25, bottomPad: 70 }, mapOpts, { onSelect: openDevice, positions: (mapInst && mapInst.positions) || savedPositions() });
      mapInst = OctoMap.render($('#mapsvg'), t, opts);
      $('#map-q').oninput = function () { mapInst.search(this.value); };
      $('#map-fit').onclick = function () { mapInst.fit(); };
      $('#map-relayout').onclick = function () { mapInst.relayout(); persistPositions(); };
      $('#map-infra').onclick = function () {
        mapOpts.infraOnly = !mapOpts.infraOnly;
        this.textContent = mapOpts.infraOnly ? 'Show all devices' : 'Infrastructure only';
        mapInst.update(S.topology, mapOpts); mapInst.fit();
      };
      $('#mapsvg').addEventListener('mouseup', function () { debounce('pos', persistPositions, 500); });
    });
  };
  function savedPositions() { try { return JSON.parse(store('octolan-pos') || '{}'); } catch (e) { return {}; } }
  function persistPositions() { if (mapInst) store('octolan-pos', JSON.stringify(mapInst.positions)); }

  // ---------- Devices ----------
  views.devices = function () {
    loadDevices().then(function () {
      var view = $('#view');
      if (!$('#dev-table')) {
        view.innerHTML = '<div class="toolbar"><input type="search" id="dev-q" placeholder="Search name, IP, MAC, vendor, OS, port…" value="' + esc(devFilter.q) + '">' +
          '<label class="chip"><input type="checkbox" id="dev-alive"' + (devFilter.alive ? ' checked' : '') + ' style="margin:0"> responding only</label>' +
          '<div class="chips" id="dev-types"></div><span class="muted small" id="dev-count" style="margin-left:auto"></span></div>' +
          '<div class="table-wrap"><table id="dev-table"><thead><tr>' +
          [['name', 'Name'], ['ip', 'IP'], ['mac', 'MAC / vendor'], ['type', 'Type'], ['os', 'OS'], ['ports', 'Services'], ['rtt', 'Latency'], ['seen', 'Last seen']]
            .map(function (c) { return '<th data-k="' + c[0] + '">' + c[1] + '</th>'; }).join('') + '</tr></thead><tbody></tbody></table></div>';
        $('#dev-q').oninput = function () { devFilter.q = this.value; drawDevices(); };
        $('#dev-alive').onchange = function () { devFilter.alive = this.checked; drawDevices(); };
        $$('#dev-table th').forEach(function (th) {
          th.onclick = function () { var k = th.dataset.k; devFilter.dir = devFilter.sort === k ? -devFilter.dir : 1; devFilter.sort = k; drawDevices(); };
        });
      }
      drawDevices();
    });
  };
  function ipNum(d) {
    var ip = (d.ips && d.ips[0]) || '';
    var p = ip.split('.'); if (p.length !== 4) return 9e9;
    return ((+p[0]) * 16777216) + ((+p[1]) * 65536) + ((+p[2]) * 256) + (+p[3]);
  }
  function drawDevices() {
    var types = {};
    S.devices.forEach(function (d) { types[d.type] = (types[d.type] || 0) + 1; });
    $('#dev-types').innerHTML = '<span class="chip' + (devFilter.type ? '' : ' on') + '" data-t="">All</span>' + Object.keys(types).sort().map(function (k) {
      return '<span class="chip' + (devFilter.type === k ? ' on' : '') + '" data-t="' + esc(k) + '"><span class="tdot" style="background:' + (TYPE_COLORS[k] || '#999') + '"></span>' + esc(title(k)) + ' ' + types[k] + '</span>';
    }).join('');
    $$('#dev-types .chip').forEach(function (c) { c.onclick = function () { devFilter.type = c.dataset.t; drawDevices(); }; });
    var q = devFilter.q.toLowerCase().trim();
    var rows = S.devices.filter(function (d) {
      if (devFilter.type && d.type !== devFilter.type) return false;
      if (devFilter.alive && !d.alive) return false;
      if (!q) return true;
      var hay = [label(d), d.hostname, (d.ips || []).join(' '), d.mac, d.vendor, d.type, osName(d), d.model, d.serial, (d.names || []).join(' '),
        (d.ports || []).map(function (p) { return p.port + ' ' + (p.service || '') + ' ' + (p.banner || ''); }).join(' ')].join(' ').toLowerCase();
      return hay.indexOf(q) >= 0;
    });
    var k = devFilter.sort, dir = devFilter.dir;
    var key = {
      name: function (d) { return label(d).toLowerCase(); }, ip: ipNum, mac: function (d) { return (d.vendor || '') + d.mac; },
      type: function (d) { return d.type; }, os: osName, ports: function (d) { return -(d.ports || []).length; },
      rtt: function (d) { return d.rttMicro || 9e12; }, seen: function (d) { return -new Date(d.lastSeen).getTime(); }
    }[k] || ipNum;
    rows.sort(function (a, b) { var x = key(a), y = key(b); return (x < y ? -1 : x > y ? 1 : 0) * dir; });
    $('#dev-count').textContent = rows.length + ' of ' + S.devices.length + ' devices';
    $('#dev-table tbody').innerHTML = rows.map(function (d) {
      var ports = (d.ports || []).map(function (p) { return p.service || p.port; });
      return '<tr class="clickable' + (d.alive ? '' : ' dim') + '" data-id="' + esc(d.id) + '">' +
        '<td><b>' + esc(label(d)) + '</b>' + (d.isSelf ? ' <span class="tag">this collector</span>' : '') + (d.isGateway ? ' <span class="tag">gateway</span>' : '') +
        (d.model ? '<div class="sub">' + esc(d.model) + '</div>' : '') + '</td>' +
        '<td class="mono">' + esc((d.ips || []).join(', ')) + '</td>' +
        '<td><span class="mono">' + esc(d.mac || '') + '</span><div class="sub">' + esc(d.vendor || (d.randomMac ? 'private (randomized) MAC' : '')) + '</div></td>' +
        '<td><span style="display:inline-flex;gap:6px;align-items:center"><span class="tdot" style="background:' + (TYPE_COLORS[d.type] || '#999') + '"></span>' + esc(title(d.type)) + '</span></td>' +
        '<td>' + esc(osName(d)) + (d.os && d.os.eol ? ' <span class="sev high">EOL</span>' : '') + '</td>' +
        '<td class="small">' + esc(ports.slice(0, 8).join(', ')) + (ports.length > 8 ? ' +' + (ports.length - 8) : '') + '</td>' +
        '<td class="small">' + fmtRTT(d.rttMicro) + '</td>' +
        '<td class="small muted">' + ago(d.lastSeen) + '</td></tr>';
    }).join('') || '<tr><td colspan="8" class="empty">No devices match.</td></tr>';
    $$('#dev-table tbody tr[data-id]').forEach(function (tr) { tr.onclick = function () { openDevice(tr.dataset.id); }; });
  }

  // ---------- Device drawer ----------
  var drawerTab = 'overview', drawerId = null;
  function openDevice(id) {
    drawerId = id;
    api('/api/devices/' + encodeURIComponent(id)).then(function (d) {
      $('#drawer').hidden = false;
      $('#dr-title').textContent = label(d);
      $('#dr-sub').innerHTML = esc((d.ips || []).join(', ')) + (d.mac ? ' · <span class="mono">' + esc(d.mac) + '</span>' : '') + ' · ' + esc(title(d.type));
      var tabs = [['overview', 'Overview'], ['services', 'Services (' + ((d.ports || []).length + (d.services || []).length) + ')']];
      if (d.windows || d.linux || d.netos || d.config || (d.credTries || []).length) tabs.splice(1, 0, ['host', 'Host details']);
      if ((d.interfaces || []).length) tabs.push(['interfaces', 'Interfaces (' + d.interfaces.length + ')']);
      if ((d.neighbors || []).length) tabs.push(['neighbors', 'Neighbors (' + d.neighbors.length + ')']);
      if ((d.fdb || []).length) tabs.push(['fdb', 'MAC table (' + d.fdb.length + ')']);
      tabs.push(['findings', 'Findings'], ['edit', 'Edit']);
      if (!tabs.some(function (t) { return t[0] === drawerTab; })) drawerTab = 'overview';
      $('#dr-tabs').innerHTML = tabs.map(function (t) { return '<button class="' + (t[0] === drawerTab ? 'on' : '') + '" data-t="' + t[0] + '">' + t[1] + '</button>'; }).join('');
      $$('#dr-tabs button').forEach(function (b) { b.onclick = function () { drawerTab = b.dataset.t; openDevice(id); }; });
      $('#dr-body').innerHTML = drawerBody(d, drawerTab);
      bindDrawer(d);
    }).catch(function (e) { toast(e.message, 'high'); });
  }
  function kv(pairs) {
    return '<dl class="kv">' + pairs.filter(function (p) { return p[1] !== undefined && p[1] !== null && p[1] !== ''; })
      .map(function (p) { return '<dt>' + esc(p[0]) + '</dt><dd>' + (p[2] ? p[1] : esc(p[1])) + '</dd>'; }).join('') + '</dl>';
  }
  function drawerBody(d, tab) {
    if (tab === 'overview') {
      var os = d.os || {}, sn = d.snmp, smb = d.smb;
      var up = sn && sn.sysUpTimeSec ? Math.floor(sn.sysUpTimeSec / 86400) + ' days' : '';
      return kv([
        ['Hostname', d.hostname], ['Other names', (d.names || []).filter(function (n) { return n !== d.hostname; }).join(', ')],
        ['Domain', d.domain], ['IP addresses', (d.ips || []).join(', ')], ['MAC', d.mac],
        ['Vendor', d.vendor || (d.randomMac ? 'Private / randomized MAC' : '')],
        ['Type', title(d.type)], ['Model', d.model], ['Serial', d.serial], ['Firmware', d.firmware],
        ['Operating system', (os.name || os.family || '') + (os.eol ? ' <span class="sev high">end of life</span>' : '') + (os.confidence ? ' <span class="muted small">(' + os.confidence + '% confidence)</span>' : ''), true],
        ['TCP/IP stack', os.initialTtl ? 'TTL ' + os.initialTtl + (os.window ? ' · window ' + os.window + ' · DF ' + (os.df ? 'set' : 'clear') + (os.mss ? ' · MSS ' + os.mss : '') : '') : ''],
        ['Latency', fmtRTT(d.rttMicro)], ['Location', d.location], ['Contact', d.contact],
        ['SNMP', sn ? sn.version + (sn.defaultCommunity ? ' <span class="sev high">default community</span>' : '') : '', true],
        ['sysDescr', sn && sn.sysDescr], ['Uptime', up],
        ['SMB', smb ? (smb.dialect || '') + (smb.smb1 ? ' · <span class="sev high">SMBv1 enabled</span>' : '') + ' · signing ' + (smb.signingRequired ? 'required' : 'not required') : '', true],
        ['Windows build', smb && smb.osBuild ? smb.osVersion + '.' + smb.osBuild : ''],
        ['Discovered by', (d.sources || []).map(function (s) { return '<span class="tag">' + esc(s) + '</span>'; }).join(''), true],
        ['First seen', d.firstSeen ? new Date(d.firstSeen).toLocaleString() : ''], ['Last seen', ago(d.lastSeen)],
        ['Notes', d.notes],
        ['Evidence', (os.evidence || []).map(function (e) { return '<div class="small">• ' + esc(e) + '</div>'; }).join(''), true]
      ]);
    }
    if (tab === 'host') {
      var h = '', w = d.windows;
      if (w) {
        var fw = Object.keys(w.firewall || {}).map(function (k) { return k + ' ' + (w.firewall[k] ? '✓' : '<span style="color:var(--high)">off</span>'); }).join(' · ');
        var bl = (w.bitlocker || []).map(function (b) { return b.drive + ' ' + (b.protected ? '✓' : '<span style="color:var(--high)">off</span>'); }).join(' · ');
        var lastFix = realDate(w.lastHotfix), inst = realDate(w.installDate), boot = realDate(w.lastBoot);
        var days = lastFix ? Math.round((Date.now() - lastFix) / 864e5) : null;
        h += '<h4>Windows (credentialed)</h4>' + kv([
          ['OS', w.os + (w.displayVersion ? ' ' + w.displayVersion : '') + ' · build ' + w.build + (w.ubr ? '.' + w.ubr : '')],
          ['Hardware', [w.manufacturer, w.model].filter(Boolean).join(' ') + (w.serial ? ' · S/N ' + w.serial : '')],
          ['CPU / RAM', (w.cpu || '') + (w.ramGb ? ' · ' + w.ramGb + ' GB' : '')],
          ['Domain', (w.domainJoined ? w.domain : 'not domain-joined')],
          ['Last update', lastFix ? esc(lastFix.toLocaleDateString() + ' (' + w.lastHotfixId + ', ' + days + ' days ago)') + (days > 60 ? ' <span class="sev high">stale</span>' : '') : 'unknown', true],
          ['Updates installed', w.hotfixCount], ['Pending reboot', w.pendingReboot ? 'yes' : 'no'],
          ['Antivirus', (w.defenderRealtime === false ? '<span style="color:var(--high)">Defender real-time off</span>' : w.defenderRealtime ? 'Defender real-time on' : '') + ((w.avProducts || []).length ? ' · ' + esc(w.avProducts.join(', ')) : '') + (w.signatureAgeDays ? ' · signatures ' + w.signatureAgeDays + 'd old' : ''), true],
          ['Firewall', fw, true], ['BitLocker', bl, true],
          ['RDP NLA', w.rdpNla === false ? '<span style="color:var(--high)">off</span>' : w.rdpNla ? 'required' : '', true],
          ['Auto-logon', w.autoLogon ? '<span style="color:var(--high)">enabled</span>' : 'off', true],
          ['Disks', (w.disks || []).map(function (x) { return x.drive + ' ' + x.freeGb + '/' + x.sizeGb + ' GB free'; }).join(' · ')],
          ['Local admins', (w.admins || []).map(function (a) { return '<div class="small">' + esc(a) + '</div>'; }).join(''), true],
          ['Installed', inst || boot ? 'since ' + (inst ? inst.toLocaleDateString() : '?') + ' · last boot ' + (boot ? boot.toLocaleString() : '?') : '']
        ]);
        if ((w.software || []).length) {
          h += '<h4>Installed software (' + w.softwareCount + ')</h4><input type="search" id="sw-q" placeholder="Filter…" style="width:100%;margin-bottom:8px;background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:6px 10px">' +
            '<div class="table-wrap" style="max-height:340px"><table id="sw-table"><tr><th>Name</th><th>Version</th><th>Publisher</th></tr>' +
            w.software.map(function (s) { return '<tr><td>' + esc(s.name) + '</td><td class="small">' + esc(s.version || '') + '</td><td class="small muted">' + esc(s.publisher || '') + '</td></tr>'; }).join('') + '</table></div>';
        }
      }
      if (d.linux) {
        var l = d.linux;
        h += '<h4>Linux (credentialed)</h4>' + kv([['Distribution', l.distro], ['Kernel', l.kernel], ['Uptime', l.uptime], ['CPUs', l.cpus], ['Memory', l.memMb ? l.memMb + ' MB' : ''], ['Root disk used', l.rootUsePct ? l.rootUsePct + '%' : '']]);
      }
      if (d.netos) {
        var n = d.netos;
        h += '<h4>Network OS (credentialed)</h4>' + kv([['Platform', n.platform], ['Version', n.version], ['Model', n.model], ['Serial', n.serial], ['Uptime', n.uptime]]);
      }
      if (d.config) {
        var cf = d.config;
        h += '<h4>Configuration backup</h4>' + kv([['Captured', new Date(cf.captured).toLocaleString() + (cf.changed ? ' <span class="tag">changed since last backup</span>' : ''), true],
          ['Size', cf.lines + ' lines'], ['SHA-256', '<span class="mono small">' + esc(cf.sha256.slice(0, 16)) + '…</span>', true],
          ['Issues', (cf.issues || []).length ? cf.issues.map(function (i) { return '<span class="tag">' + esc(CFG_ISSUES[i] || i) + '</span>'; }).join('') : 'none', true]]) +
          '<p><a href="/api/vault/config/' + encodeURIComponent(d.id) + '">Download config</a> <span class="muted small">(requires the vault to be unlocked)</span></p>';
      }
      if ((d.credTries || []).length) {
        h += '<h4>Credential attempts</h4><ul class="list">' + d.credTries.map(function (t) {
          return '<li><span class="t">' + hhmmss(t.at) + '</span><span class="tag">' + esc(t.method) + '</span><span style="flex:1">' + esc(t.credName) + '</span>' + (t.ok ? '<span class="status ok">ok</span>' : '<span class="status bad">' + esc(t.error || 'failed') + '</span>') + '</li>';
        }).join('') + '</ul>';
      }
      return h;
    }
    if (tab === 'services') {
      var p = d.ports || [], sv = d.services || [], tls = d.tls || [];
      return (p.length ? '<h4>Open TCP ports</h4><div class="table-wrap"><table><tr><th>Port</th><th>Service</th><th>Banner</th></tr>' + p.map(function (x) {
        return '<tr><td class="mono">' + x.port + '</td><td>' + esc(x.service || '') + '</td><td class="small">' + esc(x.banner || '') + '</td></tr>';
      }).join('') + '</table></div>' : '<p class="muted">No open TCP ports found.</p>') +
        (tls.length ? '<h4>TLS certificates</h4><div class="table-wrap"><table><tr><th>Port</th><th>Subject</th><th>Issuer</th><th>Expires</th><th>TLS</th></tr>' + tls.map(function (t) {
          var exp = new Date(t.notAfter), days = Math.round((exp - Date.now()) / 864e5);
          return '<tr><td class="mono">' + t.port + '</td><td>' + esc(t.subject) + (t.selfSigned ? ' <span class="tag">self-signed</span>' : '') + '</td><td class="small">' + esc(t.issuer) + '</td><td' + (days < 30 ? ' style="color:var(--high)"' : '') + '>' + exp.toLocaleDateString() + ' <span class="muted small">(' + days + 'd)</span></td><td class="small">' + esc(t.version || '') + '</td></tr>';
        }).join('') + '</table></div>' : '') +
        (sv.length ? '<h4>Advertised services (mDNS / SSDP)</h4><ul class="list">' + sv.map(function (s) {
          return '<li><span class="tag">' + esc(s.type) + '</span><span style="flex:1">' + esc(s.name || '') + '</span><span class="muted small">' + esc(s.detail || '') + '</span></li>';
        }).join('') + '</ul>' : '');
    }
    if (tab === 'interfaces') {
      return '<div class="table-wrap"><table><tr><th>#</th><th>Name</th><th>Status</th><th>Speed</th><th>VLAN</th><th>Traffic in/out</th><th>Errors</th></tr>' + d.interfaces.map(function (i) {
        var st = !i.adminUp ? '<span class="status">admin down</span>' : i.operUp ? '<span class="status ok">up</span>' : '<span class="status warn">down</span>';
        return '<tr><td>' + i.index + '</td><td><b>' + esc(i.name) + '</b>' + (i.alias ? '<div class="sub">' + esc(i.alias) + '</div>' : '') + '</td><td>' + st + '</td><td>' + (i.speedMbps ? (i.speedMbps >= 1000 ? i.speedMbps / 1000 + ' G' : i.speedMbps + ' M') : '') + '</td><td>' + (i.pvid || '') + '</td><td class="small">' + fmtBytes(i.inOctets) + ' / ' + fmtBytes(i.outOctets) + '</td><td' + ((i.inErrors + i.outErrors) > 1000 ? ' style="color:var(--high)"' : '') + '>' + fmtNum((i.inErrors || 0) + (i.outErrors || 0)) + '</td></tr>';
      }).join('') + '</table></div>';
    }
    if (tab === 'neighbors') {
      return '<div class="table-wrap"><table><tr><th>Local port</th><th>Neighbor</th><th>Remote port</th><th>Address</th><th>Proto</th></tr>' + d.neighbors.map(function (n) {
        return '<tr><td>' + esc(n.localPort) + '</td><td><b>' + esc(n.remoteName || n.remoteChassis) + '</b><div class="sub">' + esc((n.remoteDescr || '').slice(0, 90)) + '</div></td><td>' + esc(n.remotePort) + '</td><td class="mono">' + esc(n.remoteIp || '') + '</td><td>' + esc(n.protocol) + (n.nativeVlan ? '<div class="sub">VLAN ' + n.nativeVlan + '</div>' : '') + '</td></tr>';
      }).join('') + '</table></div>';
    }
    if (tab === 'fdb') {
      var byPort = {};
      d.fdb.forEach(function (e) { (byPort[e.port] = byPort[e.port] || []).push(e); });
      var macIdx = {};
      S.devices.forEach(function (x) { if (x.mac) macIdx[x.mac] = x; });
      return '<div class="table-wrap"><table><tr><th>Port</th><th>MACs</th><th>Devices</th></tr>' + Object.keys(byPort).sort(function (a, b) { return byPort[a].length - byPort[b].length; }).map(function (p) {
        var es = byPort[p];
        return '<tr><td><b>' + esc(p) + '</b>' + (es.length > 6 ? '<div class="sub">uplink / trunk</div>' : '') + '</td><td>' + es.length + '</td><td class="small">' + es.slice(0, 12).map(function (e) {
          var x = macIdx[e.mac];
          return x ? '<a href="#" data-dev="' + esc(x.id) + '">' + esc(label(x)) + '</a>' : '<span class="mono">' + esc(e.mac) + '</span>';
        }).join(', ') + (es.length > 12 ? ' …' : '') + '</td></tr>';
      }).join('') + '</table></div>';
    }
    if (tab === 'findings') {
      var fs = ((S.findings && S.findings.findings) || []).filter(function (f) { return (f.devices || []).indexOf(d.id) >= 0; });
      return fs.length ? fs.map(findingHTML).join('') : '<p class="muted">No findings for this device.</p>';
    }
    if (tab === 'edit') {
      var types = ['unknown', 'router', 'firewall', 'switch', 'access-point', 'server', 'workstation', 'hypervisor', 'nas', 'printer', 'voip-phone', 'camera', 'mobile', 'media', 'iot', 'ups'];
      return '<form id="dev-edit" class="modal-body" style="padding:0"><label>Name<input name="hostname" value="' + esc(d.hostname || '') + '"></label>' +
        '<label>Type<select name="type">' + types.map(function (t) { return '<option value="' + t + '"' + (t === d.type ? ' selected' : '') + '>' + title(t) + '</option>'; }).join('') + '</select></label>' +
        '<label>Notes<textarea name="notes" rows="4">' + esc(d.notes || '') + '</textarea></label><div><button class="primary" type="submit">Save</button></div></form>';
    }
    return '';
  }
  function bindDrawer(d) {
    var q = $('#sw-q');
    if (q) q.oninput = function () {
      var s = q.value.toLowerCase();
      $$('#sw-table tr').forEach(function (tr, i) { if (i) tr.style.display = tr.textContent.toLowerCase().indexOf(s) >= 0 ? '' : 'none'; });
    };
    var f = $('#dev-edit');
    if (f) f.onsubmit = function (ev) {
      ev.preventDefault();
      var fd = new FormData(f);
      api('/api/devices/' + encodeURIComponent(d.id), { method: 'PATCH', body: { hostname: fd.get('hostname'), type: fd.get('type'), notes: fd.get('notes') } })
        .then(function () { toast('Saved'); return api('/api/analyze', { method: 'POST' }); }).then(function () { openDevice(d.id); refreshCurrent(); })
        .catch(function (e) { toast(e.message, 'high'); });
    };
  }
  $('#dr-close').onclick = function () { $('#drawer').hidden = true; drawerId = null; };
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') { $('#drawer').hidden = true; $('#modal').hidden = true; $('#export-menu').hidden = true; }
  });
  document.addEventListener('click', function (e) {
    var a = e.target.closest && e.target.closest('a[data-dev]');
    if (a) { e.preventDefault(); openDevice(a.dataset.dev); }
  });

  // ---------- Findings ----------
  function findingHTML(f) {
    var byId = {};
    S.devices.forEach(function (d) { byId[d.id] = d; });
    return '<div class="finding ' + f.severity + '"><div style="display:flex;gap:10px;align-items:baseline;flex-wrap:wrap"><h4>' + esc(f.title) + '</h4>' +
      '<span class="muted small">' + esc(f.category) + '</span><span class="sev ' + f.severity + '" style="margin-left:auto">' + f.severity + '</span></div>' +
      '<div style="margin-top:6px">' + md(f.detail) + '</div><div class="fix"><b>Fix:</b> ' + md(f.remediation) + '</div>' +
      (f.devices && f.devices.length ? '<div class="devs">' + f.devices.map(function (id) {
        var d = byId[id];
        return '<a href="#" data-dev="' + esc(id) + '">' + esc(d ? label(d) + (d.ips && d.ips[0] && label(d) !== d.ips[0] ? ' · ' + d.ips[0] : '') : id) + '</a>';
      }).join('') + '</div>' : '') + '</div>';
  }
  views.findings = function () {
    Promise.all([loadFindings(), loadDevices()]).then(function () {
      var f = S.findings.findings || [];
      var sev = {};
      f.forEach(function (x) { sev[x.severity] = (sev[x.severity] || 0) + 1; });
      $('#view').innerHTML = '<div class="grid cols-4" style="margin-bottom:16px">' +
        '<div class="card kpi"><h3>Score</h3><div class="v">' + (S.findings.score < 0 ? '–' : S.findings.score) + ' <span style="font-size:18px" class="muted">' + esc(S.findings.grade || '') + '</span></div></div>' +
        ['critical', 'high', 'medium'].map(function (k) { return '<div class="card kpi"><h3>' + k + '</h3><div class="v" style="color:' + SEV_COLORS[k] + '">' + (sev[k] || 0) + '</div></div>'; }).join('') + '</div>' +
        (f.length ? f.map(findingHTML).join('') : '<div class="empty"><h2>No findings yet</h2><p>Run an assessment to evaluate the network\'s posture.</p></div>');
    });
  };

  // ---------- VLANs & L2 ----------
  views.l2 = function () {
    Promise.all([loadL2(), loadDevices()]).then(function () {
      var l = S.l2, stp = l.stp || {};
      var dups = l.duplicates || {};
      $('#view').innerHTML = '<div class="grid cols-2">' +
        '<div class="card"><h3>VLANs <span class="right muted">' + (l.vlans || []).length + '</span></h3>' + ((l.vlans || []).length ?
          '<div class="table-wrap"><table><tr><th>ID</th><th>Name</th><th>Seen via</th></tr>' + l.vlans.map(function (v) {
            return '<tr><td><b>' + v.id + '</b></td><td>' + esc(v.name || '') + '</td><td class="small">' + esc(v.source) + (v.tagged ? ' · tagged on wire' : '') + '</td></tr>';
          }).join('') + '</table></div>' : '<p class="muted">No VLANs seen. VLANs are learned from SNMP (Q-BRIDGE / Cisco VTP), LLDP/CDP and 802.1Q tags on the wire.</p>') + '</div>' +
        '<div class="card"><h3>Spanning tree</h3>' + (stp.seen ? kv([
          ['Protocol', stp.protocol], ['Root bridge', stp.rootBridge], ['Root priority', stp.rootPriority], ['Path cost to root', stp.rootCost],
          ['Sending bridge', stp.senderBridge], ['Topology changes', stp.topologyChanges + (stp.lastTc ? ' (last ' + ago(stp.lastTc) + ')' : '')],
          ['Root changes', stp.rootChanges], ['BPDUs heard', fmtNum(stp.bpdus)]]) : '<p class="muted">No BPDUs heard on this port (needs raw capture; ports with BPDU filter or networks without STP send none).</p>') +
        '<h3 style="margin-top:18px">DHCP servers</h3>' + ((l.dhcp || []).length ? '<ul class="list">' + l.dhcp.map(function (d) {
          return '<li><span class="mono" style="min-width:110px">' + esc(d.ip) + '</span><span style="flex:1" class="small">router ' + esc(d.router || '?') + ' · DNS ' + esc((d.dns || []).join(', ')) + (d.domain ? ' · ' + esc(d.domain) : '') + '</span><span class="muted small">' + d.offers + ' offers</span></li>';
        }).join('') + '</ul>' + (l.dhcp.length > 1 ? '<p class="sev high" style="display:inline-block">Multiple DHCP servers: check for a rogue server</p>' : '') : '<p class="muted">None heard yet (DHCP offers appear as clients renew leases).</p>') +
        (Object.keys(dups).length ? '<h3 style="margin-top:18px">Duplicate IPs</h3><ul class="list">' + Object.keys(dups).map(function (ip) { return '<li><span class="mono">' + esc(ip) + '</span><span class="small">' + esc(dups[ip].join(', ')) + '</span></li>'; }).join('') + '</ul>' : '') +
        '</div>' +
        '<div class="card span-2"><h3>LLDP / CDP neighbors <span class="right muted">' + (l.neighbors || []).length + '</span></h3>' + ((l.neighbors || []).length ?
          '<div class="table-wrap"><table><tr><th>Device</th><th>Local port</th><th>Neighbor</th><th>Remote port</th><th>Address</th><th>Capabilities</th><th>Proto</th></tr>' + l.neighbors.map(function (n) {
            return '<tr><td><a href="#" data-dev="' + esc(n.deviceId) + '">' + esc(n.device) + '</a></td><td>' + esc(n.localPort) + '</td><td><b>' + esc(n.remoteName || n.remoteChassis) + '</b><div class="sub">' + esc((n.remoteDescr || '').slice(0, 80)) + '</div></td><td>' + esc(n.remotePort) + '</td><td class="mono">' + esc(n.remoteIp || '') + '</td><td class="small">' + esc(n.remoteCaps || '') + '</td><td>' + esc(n.protocol) + (n.nativeVlan ? '<div class="sub">native VLAN ' + n.nativeVlan + '</div>' : '') + '</td></tr>';
          }).join('') + '</table></div>' : '<p class="muted">No neighbors yet. Switches report LLDP/CDP neighbors over SNMP; the collector also hears LLDP/CDP from the switch port it is plugged into.</p>') + '</div>' +
        '</div>';
    });
  };

  // ---------- Traffic ----------
  views.traffic = function () {
    Promise.all([loadFlows(), S.devices.length ? null : loadDevices()]).then(function (r) {
      var f = r[0];
      var v = $('#view');
      if (f) ['series', 'topTalkers', 'topApps', 'conversations'].forEach(function (k) { f[k] = f[k] || []; });
      if (f) { f.exporters = f.exporters || {}; f.versions = f.versions || {}; }
      var listening = f && f.listening;
      var head = '<div class="card" style="margin-bottom:16px"><h3>NetFlow / IPFIX collector</h3><div class="toolbar" style="margin:0">' +
        (listening ? '<span class="status ok">Listening on UDP ' + esc(f.listenAddr) + '</span><button class="ghost small" id="nf-stop">Stop</button>' :
          (f && f.totalFlows ? '<span class="status">Showing saved session data</span>' : '') +
          '<span class="status">Off</span><input id="nf-addr" value=":2055" style="width:110px;background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:6px 8px"><button class="primary small" id="nf-start">Start collector</button>') +
        '<span class="muted small">Point the customer\'s router/firewall flow export (v5, v9 or IPFIX) at this laptop: ' + esc(collectorIPs()) + '</span></div></div>';
      if (!f || !f.totalFlows) {
        v.innerHTML = head + '<div class="empty"><h2>' + (listening ? 'Waiting for flow exports…' : 'Traffic analysis is off') + '</h2><p>Most firewalls (FortiGate, SonicWall, Meraki, pfSense, UniFi, MikroTik, Cisco) can export NetFlow or IPFIX. OctoLAN aggregates top talkers, applications and conversations.</p>' +
          (f && f.errors && Object.keys(f.errors).length ? '<p class="small">Parser notes: ' + esc(Object.keys(f.errors).join('; ')) + '</p>' : '') + '</div>';
        bindNF();
        return;
      }
      var maxT = f.topTalkers.length ? f.topTalkers[0].bytes : 1, maxA = f.topApps.length ? f.topApps[0].bytes : 1;
      var byIP = {};
      S.devices.forEach(function (d) { (d.ips || []).forEach(function (ip) { byIP[ip] = d; }); });
      v.innerHTML = head +
        '<div class="grid cols-4">' + kpi(f.totalFlows, 'Flows', fmtBytes(f.totalBytes) + ' total') + kpi(Object.keys(f.exporters).length, 'Exporters', Object.keys(f.exporters).join(', ')) +
        kpi(f.totalPackets, 'Packets', Object.keys(f.versions || {}).join(', ')) +
        kpi(f.series.length ? Math.round(f.series[f.series.length - 1].v / 1e6) : 0, 'Current Mbps', 'averaged over 5 s') + '</div>' +
        '<div class="card" style="margin-top:16px"><h3>Throughput</h3><canvas class="chart" id="nf-chart"></canvas></div>' +
        '<div class="grid cols-2" style="margin-top:16px">' +
        '<div class="card"><h3>Top talkers</h3><div class="bars">' + f.topTalkers.slice(0, 12).map(function (t) {
          var d = byIP[t.key];
          return '<div class="row"><span class="mono" title="' + esc(t.key) + '">' + (d ? '<a href="#" data-dev="' + esc(d.id) + '">' + esc(label(d)) + '</a>' : esc(t.key)) + '</span><div class="track"><i style="width:' + (t.bytes / maxT * 100) + '%"></i></div><span class="num small">' + fmtBytes(t.bytes) + '</span></div>';
        }).join('') + '</div></div>' +
        '<div class="card"><h3>Applications</h3><div class="bars">' + f.topApps.slice(0, 12).map(function (t) {
          return '<div class="row"><span>' + esc(t.key) + '</span><div class="track"><i style="width:' + (t.bytes / maxA * 100) + '%;background:#8b5cf6"></i></div><span class="num small">' + fmtBytes(t.bytes) + '</span></div>';
        }).join('') + '</div></div></div>' +
        '<div class="card" style="margin-top:16px"><h3>Top conversations</h3><div class="table-wrap"><table><tr><th>Source</th><th>Destination</th><th>Proto</th><th>Bytes</th><th>Packets</th><th>Exporter</th></tr>' +
        f.conversations.slice(0, 50).map(function (c) {
          var pn = { 1: 'ICMP', 6: 'TCP', 17: 'UDP' }[c.proto] || c.proto;
          return '<tr><td class="mono">' + esc(c.src) + ':' + c.srcPort + '</td><td class="mono">' + esc(c.dst) + ':' + c.dstPort + '</td><td>' + pn + '</td><td>' + fmtBytes(c.bytes) + '</td><td>' + fmtNum(c.packets) + '</td><td class="mono small">' + esc(c.exporter) + '</td></tr>';
        }).join('') + '</table></div></div>';
      lineChart($('#nf-chart'), [{ values: f.series.map(function (p) { return [p.t, p.v]; }), color: '#14b8a6', label: 'bps' }], fmtBits);
      bindNF();
    });
  };
  function collectorIPs() {
    var c = S.state && S.state.capabilities;
    return c ? c.interfaces.map(function (i) { return i.addrs.map(function (a) { return a.split('/')[0]; }).join(', '); }).join(', ') : '';
  }
  function bindNF() {
    var s = $('#nf-start'), t = $('#nf-stop');
    if (s) s.onclick = function () { api('/api/netflow', { method: 'POST', body: { enable: true, addr: $('#nf-addr').value } }).then(function () { toast('NetFlow collector started'); views.traffic(); }).catch(function (e) { toast(e.message, 'high'); }); };
    if (t) t.onclick = function () { api('/api/netflow', { method: 'POST', body: { enable: false } }).then(function () { views.traffic(); }); };
  }

  // ---------- Storm Guard ----------
  views.storm = function () { loadStorm().then(drawStorm); };
  function drawStorm(s) {
    var v = $('#view');
    if (!s || (!s.running && s.state !== 'ok')) {
      v.innerHTML = '<div class="empty"><h2>Storm Guard unavailable</h2><p>' + esc((s && s.error) || 'Raw capture is required.') + '</p>' +
        '<p class="muted">Storm Guard meters every frame on the wire in promiscuous mode to catch broadcast storms, layer-2 loops and spanning-tree instability. Restart OctoLAN with sudo (macOS/Linux) or install Npcap (Windows).</p></div>';
      return;
    }
    var c = s.current || {};
    if (!$('#storm-chart')) {
      v.innerHTML = '<div class="grid cols-4">' +
        '<div class="card"><h3>State</h3><div id="st-state" class="storm-state"></div><div class="muted small" id="st-th"></div></div>' +
        '<div class="card kpi"><h3>Broadcast pps</h3><div class="v" id="st-b"></div><div class="s muted" id="st-bp"></div></div>' +
        '<div class="card kpi"><h3>Multicast pps</h3><div class="v" id="st-m"></div><div class="s muted" id="st-mp"></div></div>' +
        '<div class="card kpi"><h3>Total pps</h3><div class="v" id="st-t"></div><div class="s muted" id="st-tp"></div></div></div>' +
        '<div class="card" style="margin-top:16px"><h3>Packets per second (last 5 minutes) <span class="right small"><span style="color:#ef4444">■</span> broadcast <span style="color:#f59e0b">■</span> multicast <span style="color:#64748b">■</span> unicast <span style="color:#b91c1c">■</span> repeated</span></h3><canvas class="chart" id="storm-chart" style="height:260px"></canvas></div>' +
        '<div class="grid cols-2" style="margin-top:16px"><div class="card"><h3>Spanning tree</h3><div id="st-stp"></div></div>' +
        '<div class="card"><h3>Top broadcasters</h3><div id="st-top"></div></div></div>';
    }
    var st = $('#st-state'); st.className = 'storm-state ' + s.state; st.textContent = s.state.toUpperCase();
    $('#st-th').textContent = 'on ' + s.interface + ' · warn ≥ ' + fmtNum(s.warnPps) + ' · storm ≥ ' + fmtNum(s.critPps) + ' bcast+mcast pps';
    $('#st-b').textContent = fmtNum(c.broadcast); $('#st-bp').textContent = 'peak ' + fmtNum(s.peak.broadcast);
    $('#st-m').textContent = fmtNum(c.multicast); $('#st-mp').textContent = 'peak ' + fmtNum(s.peak.multicast);
    $('#st-t').textContent = fmtNum(c.total); $('#st-tp').textContent = fmtBytes(c.bytes) + '/s · ARP ' + fmtNum(c.arp) + '/s';
    var ser = s.series || [];
    lineChart($('#storm-chart'), [
      { values: ser.map(function (p) { return [p.t, p.unicast]; }), color: '#64748b' },
      { values: ser.map(function (p) { return [p.t, p.multicast]; }), color: '#f59e0b' },
      { values: ser.map(function (p) { return [p.t, p.broadcast]; }), color: '#ef4444' },
      { values: ser.map(function (p) { return [p.t, p.dups]; }), color: '#b91c1c', dash: true }
    ], fmtNum, [{ v: s.warnPps, color: '#f59e0b' }, { v: s.critPps, color: '#b91c1c' }]);
    var stp = s.stp || {};
    $('#st-stp').innerHTML = stp.seen ? kv([['Protocol', stp.protocol], ['Root bridge', stp.rootBridge], ['Root priority', stp.rootPriority],
      ['Path cost', stp.rootCost], ['Topology changes', stp.topologyChanges], ['Root changes', stp.rootChanges], ['BPDUs', fmtNum(stp.bpdus)]]) : '<p class="muted">No BPDUs heard yet.</p>';
    var top = s.topBroadcasters || [], max = top.length ? top[0].packets : 1;
    var macIdx = {};
    S.devices.forEach(function (d) { if (d.mac) macIdx[d.mac] = d; });
    $('#st-top').innerHTML = top.length ? '<div class="bars">' + top.map(function (t) {
      var d = macIdx[t.key];
      return '<div class="row"><span class="small" title="' + esc(t.key) + '">' + (d ? '<a href="#" data-dev="' + esc(d.id) + '">' + esc(label(d)) + '</a>' : '<span class="mono">' + esc(t.key) + '</span>') + '<div class="sub">' + esc(t.label || '') + '</div></span><div class="track"><i style="width:' + (t.packets / max * 100) + '%;background:#ef4444"></i></div><span class="num small">' + fmtNum(t.packets) + '</span></div>';
    }).join('') + '</div>' : '<p class="muted">Quiet so far.</p>';
  }


  // ---------- Credentials (vault) ----------
  var V = null, vaultEdit = null;
  var CRED_TYPES = { windows: 'Windows admin (WinRM)', ssh: 'SSH (switch / firewall / Linux)', snmp: 'SNMP' };
  function loadVault() { return api('/api/vault').then(function (v) { V = v; vaultDot(); return v; }); }
  function vaultDot() {
    var d = $('#nav-vault'); if (!d || !V) return;
    d.className = 'dot ' + (V.unlocked ? 'ok' : V.exists ? 'warning' : '');
    d.title = V.unlocked ? 'Vault unlocked' : V.exists ? 'Vault locked' : '';
  }
  views.vault = function () {
    loadVault().then(function (v) {
      var view = $('#view');
      if (!v.site) {
        view.innerHTML = '<div class="empty"><h2>Name the site first</h2><p>Each customer gets their own encrypted vault. Enter the customer / site name at the top of the page.</p></div>';
        return;
      }
      if (!v.exists || !v.unlocked) {
        var create = !v.exists;
        view.innerHTML = '<div class="card" style="max-width:560px;margin:4vh auto">' +
          '<h3>' + (create ? 'Create credential vault' : 'Unlock credential vault') + '</h3>' +
          '<p>' + (create ? 'Store the credentials <b>' + esc(v.site) + '</b> gave you. OctoLAN uses them during scans for patch levels, installed software, security settings and switch config backups.'
            : 'The vault for <b>' + esc(v.site) + '</b> is locked.') + '</p>' +
          '<form id="vault-form" class="modal-body" style="padding:0">' +
          '<label>Passphrase<input type="password" name="p1" autocomplete="' + (create ? 'new-password' : 'current-password') + '" required minlength="10"></label>' +
          (create ? '<label>Confirm passphrase<input type="password" name="p2" autocomplete="new-password" required></label>' : '') +
          '<div><button class="primary" type="submit">' + (create ? 'Create vault' : 'Unlock') + '</button></div>' +
          '<p class="muted small">Encrypted with XChaCha20-Poly1305; the key is derived from your passphrase with Argon2id. The passphrase is never stored: if it\'s lost, the vault can\'t be recovered.<br>File: <span class="mono">' + esc(v.path) + '</span></p>' +
          '</form></div>';
        $('#vault-form').onsubmit = function (ev) {
          ev.preventDefault();
          var f = ev.target;
          if (create && f.p1.value !== f.p2.value) { toast('Passphrases don\'t match', 'high'); return; }
          var btn = f.querySelector('button'); btn.disabled = true; btn.textContent = create ? 'Creating…' : 'Unlocking…';
          api('/api/vault/' + (create ? 'create' : 'unlock'), { method: 'POST', body: { passphrase: f.p1.value } })
            .then(function () { f.reset(); toast(create ? 'Vault created' : 'Vault unlocked'); views.vault(); })
            .catch(function (e) { btn.disabled = false; btn.textContent = create ? 'Create vault' : 'Unlock'; toast(e.message, 'high'); });
        };
        setTimeout(function () { var i = $('#vault-form input'); if (i) i.focus(); }, 30);
        return;
      }
      var rows = v.creds.map(function (c) {
        var who = c.type === 'snmp' ? (c.snmpVersion === 'v3' ? 'v3 user ' + esc(c.username) : 'community ••••') : esc((c.domain ? c.domain + '\\' : '') + c.username);
        return '<tr><td><b>' + esc(c.name) + '</b>' + (c.notes ? '<div class="sub">' + esc(c.notes) + '</div>' : '') + '</td><td>' + esc(CRED_TYPES[c.type] || c.type) + '</td><td class="mono">' + who + '</td>' +
          '<td class="small">' + (c.scope && c.scope.length ? esc(c.scope.join(', ')) : '<span class="muted">scan targets</span>') + '</td>' +
          '<td class="small">' + (c.hasPassword ? 'password ' : '') + (c.hasKey ? 'key ' : '') + (c.hasEnable ? 'enable' : '') + '</td>' +
          '<td style="white-space:nowrap"><button class="ghost small" data-edit="' + c.id + '">Edit</button> ' + (c.type !== 'snmp' ? '<button class="ghost small" data-test="' + c.id + '">Test</button> ' : '') +
          '<button class="ghost small" data-del="' + c.id + '">Delete</button></td></tr>';
      }).join('');
      view.innerHTML = '<div class="toolbar"><span class="status ok">Vault unlocked</span><span class="muted small">' + esc(v.site) + ' · auto-locks after 30 min idle</span>' +
        '<span style="margin-left:auto"></span><button class="primary small" id="v-add">Add credential</button><button class="ghost small" id="v-pass">Change passphrase</button><button class="ghost small" id="v-lock">Lock</button></div>' +
        '<div class="card"><h3>Credentials <span class="right muted">' + v.creds.length + '</span></h3>' + (v.creds.length ?
          '<div class="table-wrap"><table><tr><th>Name</th><th>Type</th><th>Account</th><th>Scope</th><th>Stored</th><th></th></tr>' + rows + '</table></div>' :
          '<p class="muted">No credentials yet. Add the admin, switch or SNMP credentials the customer gave you.</p>') + '</div>' +
        '<div id="v-editor"></div>' +
        '<div class="card" style="margin-top:16px"><h3>How credentials are used</h3><ul class="small" style="margin:0;padding-left:18px;line-height:1.7">' +
        '<li>Each credential is only sent to hosts inside its <b>scope</b> (blank = the scan\'s targets), and only to matching devices: Windows credentials to Windows hosts with WinRM open, SSH credentials to hosts with SSH open.</li>' +
        '<li>Domain credentials are only offered to hosts that report the <b>same domain</b>, so a rogue machine can\'t collect them.</li>' +
        '<li>One attempt per credential per host; a credential rejected 3 times is <b>paused</b> for the rest of the scan to avoid locking the account.</li>' +
        '<li>SSH host keys are remembered; if a device\'s key changes, the login is refused.</li>' +
        '<li>Only read-only commands are run. Config backups are stored <b>inside this encrypted vault</b>, never in session files or reports.</li></ul></div>' +
        (v.configs && v.configs.length ? '<div class="card" style="margin-top:16px"><h3>Config backups <span class="right muted">' + v.configs.length + '</span></h3><div class="table-wrap"><table><tr><th>Device</th><th>Platform</th><th>Lines</th><th>Captured</th><th>Versions</th><th></th></tr>' +
          v.configs.map(function (c) { return '<tr><td><b>' + esc(c.name) + '</b><div class="sub mono">' + esc(c.ip) + '</div></td><td>' + esc(c.platform) + '</td><td>' + c.lines + '</td><td class="small">' + new Date(c.captured).toLocaleString() + '</td><td>' + c.versions + '</td><td><a href="/api/vault/config/' + encodeURIComponent(c.deviceId) + '">Download</a></td></tr>'; }).join('') +
          '</table></div></div>' : '');
      $('#v-add').onclick = function () { credEditor({ type: 'windows' }); };
      $('#v-lock').onclick = function () { api('/api/vault/lock', { method: 'POST' }).then(function () { toast('Vault locked'); views.vault(); }); };
      $('#v-pass').onclick = passEditor;
      $$('[data-edit]').forEach(function (b) { b.onclick = function () { credEditor(v.creds.filter(function (c) { return c.id === b.dataset.edit; })[0]); }; });
      $$('[data-del]').forEach(function (b) {
        b.onclick = function () {
          var c = v.creds.filter(function (x) { return x.id === b.dataset.del; })[0];
          if (!confirm('Delete credential "' + c.name + '"?')) return;
          api('/api/vault/creds/' + encodeURIComponent(c.id), { method: 'DELETE' }).then(function () { toast('Deleted'); views.vault(); }).catch(function (e) { toast(e.message, 'high'); });
        };
      });
      $$('[data-test]').forEach(function (b) {
        b.onclick = function () {
          var ip = prompt('Test against which IP address?');
          if (!ip) return;
          b.disabled = true; b.textContent = 'Testing…';
          api('/api/vault/test', { method: 'POST', body: { id: b.dataset.test, ip: ip } }).then(function (r) {
            toast(r.message, r.ok ? '' : 'high');
          }).catch(function (e) { toast(e.message, 'high'); }).then(function () { b.disabled = false; b.textContent = 'Test'; });
        };
      });
    }).catch(function (e) { $('#view').innerHTML = '<div class="empty"><h2>Vault unavailable</h2><p>' + esc(e.message) + '</p></div>'; });
  };
  function credEditor(c) {
    var isNew = !c.id;
    var box = $('#v-editor');
    var t = c.type || 'windows';
    function field(name, labelText, value, type, extra) {
      return '<label>' + labelText + '<input name="' + name + '" type="' + (type || 'text') + '" value="' + esc(value || '') + '" autocomplete="off"' + (extra || '') + '></label>';
    }
    function secretField(name, labelText, has) {
      return field(name, labelText + (has && !isNew ? ' <span class="muted">(leave blank to keep)</span>' : ''), '', 'password', ' autocomplete="new-password"');
    }
    function typeFields(t) {
      if (t === 'windows') return '<div class="grid2">' + field('domain', 'Domain <span class="muted">(blank = local account)</span>', c.domain) + field('username', 'Username', c.username) + '</div>' +
        secretField('password', 'Password', c.hasPassword);
      if (t === 'ssh') return '<div class="grid2">' + field('username', 'Username', c.username) + secretField('password', 'Password', c.hasPassword) + '</div>' +
        '<label>Private key (PEM, optional)' + (c.hasKey && !isNew ? ' <span class="muted">(leave blank to keep)</span>' : '') + '<textarea name="privateKey" rows="3" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea></label>' +
        '<div class="grid2">' + secretField('keyPassphrase', 'Key passphrase', false) + secretField('enable', 'Enable secret (Cisco)', c.hasEnable) + '</div>';
      return '<div class="grid2"><label>Version<select name="snmpVersion"><option value="v2c"' + (c.snmpVersion !== 'v3' ? ' selected' : '') + '>v1 / v2c community</option><option value="v3"' + (c.snmpVersion === 'v3' ? ' selected' : '') + '>v3 user</option></select></label>' +
        secretField('community', 'Community (v2c)', c.hasPassword && c.snmpVersion !== 'v3') + '</div>' +
        '<div class="grid3">' + field('username', 'v3 user', c.username) +
        '<label>Auth<select name="authProto">' + ['SHA', 'SHA256', 'SHA512', 'MD5'].map(function (p) { return '<option' + (c.authProto === p ? ' selected' : '') + '>' + p + '</option>'; }).join('') + '</select></label>' +
        secretField('authPass', 'Auth password', c.hasPassword && c.snmpVersion === 'v3') +
        '<label>Privacy<select name="privProto">' + ['AES', 'AES256', 'AES192', 'DES'].map(function (p) { return '<option' + (c.privProto === p ? ' selected' : '') + '>' + p + '</option>'; }).join('') + '</select></label>' +
        secretField('privPass', 'Privacy password', false) + '</div>';
    }
    box.innerHTML = '<form class="card" id="cred-form" style="margin-top:16px" autocomplete="off"><h3>' + (isNew ? 'Add credential' : 'Edit ' + esc(c.name)) + '</h3><div class="modal-body" style="padding:0">' +
      '<div class="grid2"><label>Type<select name="type"' + (isNew ? '' : ' disabled') + '>' + Object.keys(CRED_TYPES).map(function (k) { return '<option value="' + k + '"' + (k === t ? ' selected' : '') + '>' + CRED_TYPES[k] + '</option>'; }).join('') + '</select></label>' +
      field('name', 'Name', c.name, 'text', ' placeholder="e.g. Domain admin, Core switches"') + '</div>' +
      '<div id="cred-type-fields">' + typeFields(t) + '</div>' +
      '<label>Scope <span class="muted">CIDRs, ranges or IPs this credential may be used on (blank = the scan\'s targets)</span><input name="scope" value="' + esc((c.scope || []).join(', ')) + '" placeholder="10.0.0.0/24, 10.0.5.10-20"></label>' +
      field('notes', 'Notes', c.notes, 'text', ' placeholder="Who provided it, expiry…"') +
      '<div><button class="primary" type="submit">Save</button> <button class="ghost" type="button" id="cred-cancel">Cancel</button></div></div></form>';
    var f = $('#cred-form');
    f.type.onchange = function () { t = f.type.value; $('#cred-type-fields').innerHTML = typeFields(t); };
    $('#cred-cancel').onclick = function () { box.innerHTML = ''; };
    f.onsubmit = function (ev) {
      ev.preventDefault();
      var body = { id: c.id || '', type: t, name: f.name.value, notes: f.notes.value, scope: [f.scope.value] };
      ['domain', 'username', 'password', 'privateKey', 'keyPassphrase', 'enable', 'snmpVersion', 'community', 'authProto', 'authPass', 'privProto', 'privPass']
        .forEach(function (k) { if (f[k]) body[k] = f[k].value; });
      api('/api/vault/creds', { method: 'POST', body: body }).then(function () { toast('Credential saved'); views.vault(); })
        .catch(function (e) { toast(e.message, 'high'); });
    };
    box.scrollIntoView({ behavior: 'smooth' });
  }
  function passEditor() {
    var box = $('#v-editor');
    box.innerHTML = '<form class="card" id="pass-form" style="margin-top:16px"><h3>Change passphrase</h3><div class="modal-body" style="padding:0">' +
      '<label>Current passphrase<input type="password" name="cur" autocomplete="current-password"></label><div class="grid2"><label>New passphrase<input type="password" name="p1" autocomplete="new-password" minlength="10"></label>' +
      '<label>Confirm<input type="password" name="p2" autocomplete="new-password"></label></div><div><button class="primary" type="submit">Change</button></div></div></form>';
    $('#pass-form').onsubmit = function (ev) {
      ev.preventDefault(); var f = ev.target;
      if (f.p1.value !== f.p2.value) { toast('Passphrases don\'t match', 'high'); return; }
      api('/api/vault/passphrase', { method: 'POST', body: { passphrase: f.cur.value, newPassphrase: f.p1.value } })
        .then(function () { toast('Passphrase changed'); box.innerHTML = ''; }).catch(function (e) { toast(e.message, 'high'); });
    };
  }

  // ---------- Activity ----------
  var actFilter = '';
  views.activity = function () {
    loadEvents().then(function () {
      $('#view').innerHTML = '<div class="toolbar"><div class="chips">' + ['', 'critical', 'high', 'medium', 'low', 'info'].map(function (s) {
        return '<span class="chip' + (actFilter === s ? ' on' : '') + '" data-s="' + s + '">' + (s || 'All') + '</span>';
      }).join('') + '</div></div><div class="card"><ul class="list" id="act-list"></ul></div>';
      $$('.chips .chip').forEach(function (c) { c.onclick = function () { actFilter = c.dataset.s; views.activity(); }; });
      drawActivity();
    });
  };
  function drawActivity() {
    var l = $('#act-list'); if (!l) return;
    l.innerHTML = S.events.slice().reverse().filter(function (e) { return !actFilter || e.severity === actFilter; }).slice(0, 400).map(evRow).join('') || '<li class="muted">Nothing yet.</li>';
  }

  // ---------- charts ----------
  function lineChart(cv, series, fmt, thresholds) {
    if (!cv) return;
    var dpr = window.devicePixelRatio || 1, W = cv.clientWidth, H = cv.clientHeight;
    cv.width = W * dpr; cv.height = H * dpr;
    var g = cv.getContext('2d'); g.scale(dpr, dpr); g.clearRect(0, 0, W, H);
    var cs = getComputedStyle(document.documentElement);
    var line = cs.getPropertyValue('--line').trim(), muted = cs.getPropertyValue('--muted').trim();
    var all = [];
    series.forEach(function (s) { s.values.forEach(function (p) { all.push(p); }); });
    if (!all.length) { g.fillStyle = muted; g.font = '13px sans-serif'; g.fillText('Collecting data…', 12, H / 2); return; }
    var t0 = Math.min.apply(null, all.map(function (p) { return p[0]; })), t1 = Math.max.apply(null, all.map(function (p) { return p[0]; }));
    var vmax = Math.max.apply(null, all.map(function (p) { return p[1]; }));
    (thresholds || []).forEach(function (t) { if (t.v < vmax * 3) vmax = Math.max(vmax, t.v * 1.05); });
    vmax = vmax || 1;
    var L = 58, R = 10, T = 10, B = 22, pw = W - L - R, ph = H - T - B;
    g.font = '11px sans-serif'; g.fillStyle = muted; g.strokeStyle = line; g.lineWidth = 1;
    for (var i = 0; i <= 4; i++) {
      var y = T + ph - ph * i / 4;
      g.beginPath(); g.moveTo(L, y); g.lineTo(W - R, y); g.stroke();
      g.fillText(fmt(Math.round(vmax * i / 4)), 4, y + 4);
    }
    g.fillText(new Date(t0).toLocaleTimeString(), L, H - 6);
    var tl = new Date(t1).toLocaleTimeString(); g.fillText(tl, W - R - g.measureText(tl).width, H - 6);
    var X = function (t) { return L + (t1 === t0 ? pw : (t - t0) / (t1 - t0) * pw); }, Y = function (v) { return T + ph - v / vmax * ph; };
    (thresholds || []).forEach(function (t) {
      if (t.v > vmax) return;
      g.setLineDash([4, 4]); g.strokeStyle = t.color; g.beginPath(); g.moveTo(L, Y(t.v)); g.lineTo(W - R, Y(t.v)); g.stroke(); g.setLineDash([]);
    });
    series.forEach(function (s) {
      if (!s.values.length) return;
      g.strokeStyle = s.color; g.lineWidth = 1.8; g.setLineDash(s.dash ? [3, 3] : []);
      g.beginPath();
      s.values.forEach(function (p, i) { if (i) g.lineTo(X(p[0]), Y(p[1])); else g.moveTo(X(p[0]), Y(p[1])); });
      g.stroke(); g.setLineDash([]);
    });
  }

  // ---------- scan modal ----------
  function openScan(passiveOnly) {
    var s = S.state; if (!s) return;
    var f = $('#scan-form');
    f.site.value = s.site || '';
    var sel = $('#f-iface');
    sel.innerHTML = s.capabilities.interfaces.map(function (i) {
      return '<option value="' + esc(i.name) + '"' + (i.name === s.capabilities.defaultIface ? ' selected' : '') + '>' + esc(i.name) + ' (' + esc(i.addrs.join(', ')) + ')</option>';
    }).join('');
    if (!$('#f-targets').value) $('#f-targets').value = s.defaults.targets || '';
    f.zero.checked = !!passiveOnly;
    var c = s.capabilities;
    var note = $('#f-caps');
    note.className = 'note' + (c.rawCapture ? '' : ' warn');
    note.innerHTML = c.rawCapture ? '✓ Raw capture available: full layer-2 discovery, passive listening and Storm Guard.'
      : '⚠ <b>Limited mode</b>: ' + esc(c.captureNote) + '. Discovery continues using ping (' + esc(c.icmpMode) + '), the OS ARP cache, TCP, SNMP, SMB and name services.';
    loadVault().then(function (v) {
      var n = v.creds ? v.creds.length : 0;
      $('#f-vault').innerHTML = v.unlocked ? '(' + n + ' saved for ' + esc(v.site) + ')' : v.exists ? '(vault locked: <a href="#/vault">unlock it</a> first)' : '(no vault for this site yet: <a href="#/vault">create one</a>)';
      f.usevault.checked = !!v.unlocked;
      f.usevault.disabled = !v.unlocked;
    }).catch(function () {});
    $('#modal').hidden = false;
    setTimeout(function () { (f.site.value ? f.targets : f.site).focus(); }, 30);
  }
  $('#scan-btn').onclick = function () { openScan(false); };
  $('#modal-close').onclick = $('#modal-cancel').onclick = function () { $('#modal').hidden = true; };
  $('#scan-form').onsubmit = function (ev) {
    ev.preventDefault();
    var f = ev.target;
    var body = {
      site: f.site.value, interface: f.interface.value, targets: f.targets.value, communities: f.communities.value,
      ports: f.ports.value, passiveSeconds: +f.passive.value, zeroFootprint: f.zero.checked, rate: +f.rate.value, snmpv3: [],
      useVault: f.usevault.checked
    };
    if (f.v3user.value.trim()) body.snmpv3.push({ user: f.v3user.value.trim(), authProto: f.v3auth.value, authPass: f.v3authpass.value, privProto: f.v3priv.value, privPass: f.v3privpass.value });
    api('/api/scan', { method: 'POST', body: body }).then(function () {
      $('#modal').hidden = true;
      f.v3authpass.value = ''; f.v3privpass.value = '';
      toast('Assessment started');
      loadState().then(refreshCurrent);
    }).catch(function (e) { toast(e.message, 'high'); });
  };
  $('#stop-btn').onclick = function () { api('/api/scan/stop', { method: 'POST' }).then(function () { toast('Stopping…'); }); };

  // ---------- misc chrome ----------
  $('#site-name').onchange = function () {
    api('/api/site', { method: 'POST', body: { name: this.value } }).then(loadState).then(function () { loadVault(); if (current === 'vault') views.vault(); });
  };
  $('#export-btn').onclick = function (e) { e.stopPropagation(); $('#export-menu').hidden = !$('#export-menu').hidden; };
  document.addEventListener('click', function () { $('#export-menu').hidden = true; });
  $('#theme-btn').onclick = function () {
    var t = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = t; store('octolan-theme', t);
    if (mapInst) { mapInst.update(S.topology, mapOpts); }
    refreshCurrent();
  };
  $('#menu-btn').onclick = function () { $('#side').classList.toggle('open'); };
  window.addEventListener('hashchange', route);
  window.addEventListener('resize', function () { debounce('resize', function () { if (current === 'storm' || current === 'traffic') refreshCurrent(); }, 300); });

  // ---------- live updates ----------
  function connect() {
    var es = new EventSource('/api/stream');
    es.onmessage = function (m) {
      var msg; try { msg = JSON.parse(m.data); } catch (e) { return; }
      switch (msg.type) {
        case 'scan':
          S.state && (S.state.scan = msg.data);
          scanChrome(msg.data);
          if (!msg.data.running && msg.data.finished) {
            debounce('done', function () { loadState().then(refreshCurrent); }, 600);
          }
          if (current === 'overview') debounce('ov', refreshCurrent, 1500);
          break;
        case 'devices':
          debounce('dev', function () {
            loadState();
            if (current === 'devices') loadDevices().then(drawDevices);
            else if (current === 'map') views.map(false);
            else if (current === 'overview') refreshCurrent();
            if (drawerId && !$('#drawer').hidden && drawerTab !== 'edit') openDevice(drawerId);
          }, 900);
          break;
        case 'topology':
          if (current === 'map') debounce('map', function () { views.map(false); }, 500);
          break;
        case 'findings':
          debounce('find', function () { loadState(); if (current === 'findings' || current === 'overview') refreshCurrent(); }, 500);
          break;
        case 'event':
          S.events.push(msg.data);
          if (S.events.length > 1000) S.events.shift();
          if (msg.data.severity === 'critical' || msg.data.severity === 'high') toast(msg.data.message, msg.data.severity);
          if (current === 'activity') drawActivity();
          break;
        case 'storm':
          S.storm = msg.data;
          if (current === 'storm') drawStorm(msg.data);
          var dot = $('#nav-storm'); dot.className = 'dot ' + (msg.data.running ? msg.data.state : '');
          break;
      }
    };
    es.onerror = function () { es.close(); setTimeout(connect, 3000); };
  }

  loadState().then(function () { route(); connect(); loadVault().catch(function () {}); });
  setInterval(function () { if (current === 'traffic') views.traffic(); }, 10000);
})();
