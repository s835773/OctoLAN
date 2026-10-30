/* OctoMap: dependency-free topology renderer shared by the dashboard and
 * the HTML report. Tiered force layout (gateway → switches → APs →
 * endpoints), pan/zoom, node drag, severity badges. */
(function (global) {
  'use strict';
  var NS = 'http://www.w3.org/2000/svg';

  var ICONS = {
    router: 'M4 12h16M12 4v16M8 8l-4 4 4 4M16 8l4 4-4 4',
    firewall: 'M3 6h18v12H3zM3 10h18M3 14h18M9 6v4M15 10v4M9 14v4',
    switch: 'M4 9h14l-3-3M20 15H6l3 3',
    'access-point': 'M5 10a10 10 0 0 1 14 0M8 13a6 6 0 0 1 8 0M12 17v.5',
    server: 'M5 4h14v6H5zM5 14h14v6H5zM8 7h.5M8 17h.5',
    workstation: 'M4 5h16v11H4zM9 20h6M12 16v4',
    hypervisor: 'M12 3l9 5-9 5-9-5zM3 13l9 5 9-5',
    nas: 'M5 4h14v16H5zM5 9.3h14M5 14.6h14M8 6.6h.5M8 12h.5M8 17.3h.5',
    printer: 'M7 9V4h10v5M6 18H4v-7h16v7h-2M7 14h10v6H7z',
    'voip-phone': 'M7 4h3l1.5 4.5-2 1.2a11 11 0 0 0 4.8 4.8l1.2-2L20 14v3a2 2 0 0 1-2 2A15 15 0 0 1 5 6a2 2 0 0 1 2-2',
    camera: 'M3 8h12v8H3zM15 11l6-3v8l-6-3',
    mobile: 'M8 3h8v18H8zM11 18h2',
    media: 'M3 6h18v11H3zM8 20h8',
    iot: 'M7 7h10v10H7zM10 3v4M14 3v4M10 17v4M14 17v4M3 10h4M3 14h4M17 10h4M17 14h4',
    ups: 'M6 7h11v10H6zM17 10h2v4h-2M12.5 9l-2 3h3l-2 3',
    cloud: 'M7 18h10a4 4 0 0 0 .4-8A6 6 0 0 0 6 11.2 3.5 3.5 0 0 0 7 18z',
    unknown: 'M9.5 9a2.5 2.5 0 1 1 3.5 2.3c-.6.3-1 .9-1 1.6V14M12 17.5v.5'
  };
  var COLORS = {
    router: '#0ea5e9', firewall: '#ef4444', switch: '#14b8a6', 'access-point': '#8b5cf6',
    server: '#f59e0b', hypervisor: '#f97316', nas: '#eab308', workstation: '#3b82f6',
    printer: '#64748b', 'voip-phone': '#10b981', camera: '#ec4899', mobile: '#6366f1',
    media: '#a855f7', iot: '#84cc16', ups: '#78716c', cloud: '#94a3b8', unknown: '#9ca3af'
  };
  var SEV = { critical: '#b91c1c', high: '#ef4444', medium: '#f59e0b', low: '#3b82f6', info: '#94a3b8' };
  var INFRA = { router: 1, firewall: 1, switch: 1, 'access-point': 1 };

  function tier(n) {
    if (n.kind === 'cloud') return 1.6;
    if (n.gateway || n.type === 'firewall' || n.type === 'router') return 0;
    if (n.type === 'switch') return 1;
    if (n.type === 'access-point') return 2.2;
    return 3;
  }

  function el(tag, attrs, parent) {
    var e = document.createElementNS(NS, tag);
    for (var k in attrs) if (attrs[k] !== undefined && attrs[k] !== null) e.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(e);
    return e;
  }

  function render(container, data, opts) {
    opts = opts || {};
    container.innerHTML = '';
    var w = container.clientWidth || 900, h = container.clientHeight || 600;
    var svg = el('svg', { width: '100%', height: '100%', viewBox: '0 0 ' + w + ' ' + h, 'class': 'octomap' }, container);
    svg.style.display = 'block';
    svg.style.cursor = 'grab';
    svg.style.userSelect = 'none';
    var vp = el('g', {}, svg);
    var gl = el('g', {}, vp), gn = el('g', {}, vp);
    var view = { k: 1, x: 0, y: 0 };
    var positions = opts.positions || {};
    var nodes = [], links = [], byId = {}, sel = null, filter = '';
    var textColor = opts.light ? '#0f172a' : 'var(--map-text, #cbd5e1)';
    var lineColor = opts.light ? '#94a3b8' : 'var(--map-line, #475569)';

    function applyView() { vp.setAttribute('transform', 'translate(' + view.x + ',' + view.y + ') scale(' + view.k + ')'); }

    function build(d) {
      nodes = []; links = []; byId = {};
      var hide = {};
      (d.nodes || []).forEach(function (n) {
        var x = Object.assign({}, n);
        if (opts.infraOnly && !INFRA[x.type] && !x.gateway && !x.self) { hide[x.id] = 1; return; }
        nodes.push(x); byId[x.id] = x;
      });
      (d.links || []).forEach(function (l) {
        [l.a, l.b].forEach(function (id) {
          if (!byId[id] && !hide[id] && id.indexOf('net:') === 0) {
            var c = { id: id, label: id.slice(4) === 'other' ? 'other' : id.slice(4), type: 'cloud', kind: 'cloud', alive: true };
            nodes.push(c); byId[id] = c;
          }
        });
        if (byId[l.a] && byId[l.b]) links.push({ s: byId[l.a], t: byId[l.b], kind: l.kind, aPort: l.aPort, bPort: l.bPort });
      });
      // Drop clouds with nothing attached after filtering.
      var deg = {};
      links.forEach(function (l) { deg[l.s.id] = (deg[l.s.id] || 0) + 1; deg[l.t.id] = (deg[l.t.id] || 0) + 1; });
      nodes = nodes.filter(function (n) { return n.kind !== 'cloud' || deg[n.id] > 1 || opts.infraOnly; });
      layout();
    }

    function layout() {
      var n = nodes.length;
      if (!n) return;
      var tiers = {}, fresh = 0;
      nodes.forEach(function (nd) {
        var t = tier(nd);
        tiers[t] = (tiers[t] || 0) + 1;
        var p = positions[nd.id];
        if (p) { nd.x = p.x; nd.y = p.y; } else { fresh++; }
      });
      var idx = {};
      var rowH = Math.max(110, h / 4.2);
      nodes.forEach(function (nd) {
        if (nd.x !== undefined) return;
        var t = tier(nd); idx[t] = (idx[t] || 0) + 1;
        var count = tiers[t];
        nd.x = w / 2 + (idx[t] - (count + 1) / 2) * Math.min(90, (w * 1.5) / count) + (Math.random() - .5) * 10;
        nd.y = 60 + t * rowH + (Math.random() - .5) * 20;
      });
      if (!fresh) return;
      var iters = Math.max(60, 320 - Math.floor(n / 2));
      var adj = links.map(function (l) {
        var infra = INFRA[l.s.type] && INFRA[l.t.type];
        return { s: l.s, t: l.t, len: infra ? 170 : (l.s.kind === 'cloud' || l.t.kind === 'cloud' ? 80 : 95) };
      });
      for (var it = 0; it < iters; it++) {
        var alpha = 1 - it / iters;
        for (var i = 0; i < n; i++) { nodes[i].vx = 0; nodes[i].vy = 0; }
        for (i = 0; i < n; i++) {
          var a = nodes[i];
          for (var j = i + 1; j < n; j++) {
            var b = nodes[j], dx = a.x - b.x, dy = a.y - b.y, d2 = dx * dx + dy * dy + .01;
            if (d2 > 160000) continue;
            var f = 1800 / d2;
            a.vx += dx * f; a.vy += dy * f; b.vx -= dx * f; b.vy -= dy * f;
          }
        }
        adj.forEach(function (l) {
          var dx = l.t.x - l.s.x, dy = l.t.y - l.s.y, d = Math.sqrt(dx * dx + dy * dy) || 1;
          var f = (d - l.len) * 0.04;
          l.s.vx += dx / d * f; l.s.vy += dy / d * f; l.t.vx -= dx / d * f; l.t.vy -= dy / d * f;
        });
        nodes.forEach(function (nd) {
          if (positions[nd.id]) return; // keep user-placed / previous nodes still
          nd.vy += (60 + tier(nd) * rowH - nd.y) * 0.06;
          nd.vx += (w / 2 - nd.x) * 0.002;
          var lim = 30 * alpha + 2;
          nd.x += Math.max(-lim, Math.min(lim, nd.vx));
          nd.y += Math.max(-lim, Math.min(lim, nd.vy));
        });
      }
      nodes.forEach(function (nd) { positions[nd.id] = { x: nd.x, y: nd.y }; });
    }

    function draw() {
      gl.innerHTML = ''; gn.innerHTML = '';
      var q = filter.toLowerCase();
      links.forEach(function (l) {
        var dash = l.kind === 'fdb' ? '6 4' : (l.kind === 'inferred' || l.kind === 'gateway') ? '2 4' : null;
        var ln = el('line', { x1: l.s.x, y1: l.s.y, x2: l.t.x, y2: l.t.y, stroke: lineColor,
          'stroke-width': (l.kind === 'lldp' || l.kind === 'cdp') ? 2.2 : 1.3, 'stroke-dasharray': dash, opacity: .85 }, gl);
        var tip = (l.aPort || '') + (l.bPort ? ' ↔ ' + l.bPort : '');
        if (tip) el('title', {}, ln).textContent = l.kind.toUpperCase() + ': ' + tip;
        l.el = ln;
      });
      nodes.forEach(function (nd) {
        var g = el('g', { transform: 'translate(' + nd.x + ',' + nd.y + ')', 'class': 'octonode' }, gn);
        g.style.cursor = 'pointer';
        var r = nd.kind === 'cloud' ? 15 : (INFRA[nd.type] || nd.gateway ? 19 : 14);
        var match = !q || (nd.label + ' ' + (nd.ip || '') + ' ' + (nd.vendor || '')).toLowerCase().indexOf(q) >= 0;
        g.setAttribute('opacity', match ? (nd.alive === false ? .45 : 1) : .12);
        if (nd.self) el('circle', { r: r + 5, fill: 'none', stroke: COLORS.router, 'stroke-width': 2, 'stroke-dasharray': '3 3' }, g);
        if (sel === nd.id) el('circle', { r: r + 6, fill: 'none', stroke: '#fbbf24', 'stroke-width': 3 }, g);
        el('circle', { r: r, fill: COLORS[nd.type] || COLORS.unknown, stroke: opts.light ? '#fff' : 'rgba(15,23,42,.9)', 'stroke-width': 2 }, g);
        var s = r / 13;
        el('path', { d: ICONS[nd.type] || ICONS.unknown, transform: 'translate(' + (-12 * s) + ',' + (-12 * s) + ') scale(' + s + ')',
          fill: 'none', stroke: '#fff', 'stroke-width': 1.9, 'stroke-linecap': 'round', 'stroke-linejoin': 'round' }, g);
        if (nd.worst && SEV[nd.worst] && nd.worst !== 'info') {
          el('circle', { cx: r * .75, cy: -r * .75, r: 6, fill: SEV[nd.worst], stroke: opts.light ? '#fff' : '#0f172a', 'stroke-width': 1.5 }, g);
        }
        var t = el('text', { y: r + 14, 'text-anchor': 'middle', 'font-size': INFRA[nd.type] || nd.gateway ? 12 : 10.5,
          fill: textColor, 'font-weight': INFRA[nd.type] || nd.gateway ? 600 : 400, 'pointer-events': 'none' }, g);
        t.textContent = (nd.label || '').length > 22 ? nd.label.slice(0, 21) + '…' : nd.label;
        el('title', {}, g).textContent = nd.label + (nd.ip ? '\n' + nd.ip : '') + (nd.vendor ? '\n' + nd.vendor : '') + '\n' + nd.type +
          (nd.findings ? '\n' + nd.findings + ' finding(s)' : '');
        nd.el = g;
        g.addEventListener('mousedown', function (ev) { startDrag(ev, nd); });
        g.addEventListener('click', function (ev) {
          ev.stopPropagation();
          if (moved) return;
          sel = nd.id; draw();
          if (opts.onSelect && nd.kind !== 'cloud') opts.onSelect(nd.id);
        });
      });
    }

    // --- interaction ---
    var drag = null, pan = null, moved = false;
    function pt(ev) {
      var r = svg.getBoundingClientRect();
      return { x: (ev.clientX - r.left) * (w / r.width), y: (ev.clientY - r.top) * (h / r.height) };
    }
    function startDrag(ev, nd) { ev.stopPropagation(); drag = { nd: nd, p: pt(ev) }; moved = false; }
    svg.addEventListener('mousedown', function (ev) { pan = { p: pt(ev), x: view.x, y: view.y }; moved = false; svg.style.cursor = 'grabbing'; });
    function onMove(ev) {
      if (drag) {
        var p = pt(ev);
        drag.nd.x += (p.x - drag.p.x) / view.k; drag.nd.y += (p.y - drag.p.y) / view.k; drag.p = p; moved = true;
        positions[drag.nd.id] = { x: drag.nd.x, y: drag.nd.y };
        drag.nd.el.setAttribute('transform', 'translate(' + drag.nd.x + ',' + drag.nd.y + ')');
        links.forEach(function (l) {
          if (l.s === drag.nd || l.t === drag.nd) { l.el.setAttribute('x1', l.s.x); l.el.setAttribute('y1', l.s.y); l.el.setAttribute('x2', l.t.x); l.el.setAttribute('y2', l.t.y); }
        });
      } else if (pan) {
        var q = pt(ev); view.x = pan.x + q.x - pan.p.x; view.y = pan.y + q.y - pan.p.y;
        if (Math.abs(q.x - pan.p.x) + Math.abs(q.y - pan.p.y) > 3) moved = true;
        applyView();
      }
    }
    function onUp() { drag = null; pan = null; svg.style.cursor = 'grab'; setTimeout(function () { moved = false; }, 0); }
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
    svg.addEventListener('wheel', function (ev) {
      ev.preventDefault();
      var p = pt(ev), k = Math.max(0.15, Math.min(4, view.k * (ev.deltaY < 0 ? 1.12 : 1 / 1.12)));
      view.x = p.x - (p.x - view.x) * (k / view.k); view.y = p.y - (p.y - view.y) * (k / view.k); view.k = k; applyView();
    }, { passive: false });
    // Touch: one-finger pan.
    svg.addEventListener('touchstart', function (ev) { if (ev.touches.length === 1) { var t = ev.touches[0]; pan = { p: pt(t), x: view.x, y: view.y }; } }, { passive: true });
    svg.addEventListener('touchmove', function (ev) { if (pan && ev.touches.length === 1) { var q = pt(ev.touches[0]); view.x = pan.x + q.x - pan.p.x; view.y = pan.y + q.y - pan.p.y; applyView(); } }, { passive: true });
    svg.addEventListener('touchend', function () { pan = null; });

    function fit() {
      if (!nodes.length) return;
      var x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
      nodes.forEach(function (n) { x0 = Math.min(x0, n.x); y0 = Math.min(y0, n.y); x1 = Math.max(x1, n.x); y1 = Math.max(y1, n.y); });
      var pad = 60, bw = x1 - x0 + pad * 2, bh = y1 - y0 + pad * 2;
      view.k = Math.max(0.15, Math.min(1.6, Math.min(w / bw, h / bh)));
      view.x = (w - (x1 + x0) * view.k) / 2; view.y = (h - (y1 + y0) * view.k) / 2;
      applyView();
    }

    build(data); draw(); fit();

    if (!nodes.length) {
      var t = el('text', { x: w / 2, y: h / 2, 'text-anchor': 'middle', fill: textColor, 'font-size': 14 }, svg);
      t.textContent = 'No devices yet: run an assessment to build the map.';
    }

    return {
      update: function (d, o) { if (o) Object.assign(opts, o); build(d); draw(); },
      search: function (q) { filter = q || ''; draw(); },
      select: function (id) { sel = id; draw(); var n = byId[id]; if (n) { view.x = w / 2 - n.x * view.k; view.y = h / 2 - n.y * view.k; applyView(); } },
      fit: fit,
      destroy: function () { window.removeEventListener('mousemove', onMove); window.removeEventListener('mouseup', onUp); container.innerHTML = ''; },
      relayout: function () { for (var k in positions) delete positions[k]; nodes.forEach(function (n) { delete n.x; delete n.y; }); layout(); draw(); fit(); },
      positions: positions
    };
  }

  global.OctoMap = { render: render, colors: COLORS, icons: ICONS };
})(window);
