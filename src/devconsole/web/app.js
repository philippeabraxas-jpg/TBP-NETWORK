// TBP dev-test console — the page. Everything that comes from the network (agent names, resources, intents, reasons,
// addresses) is attacker-controlled in a red-team test: it is only ever put in the page with textContent, never as HTML.
(function () {
  'use strict';

  var $ = function (id) { return document.getElementById(id); };
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = String(text);
    return e;
  }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

  var state = {
    requests: new Map(), // id -> view, insertion order = arrival
    loose: [],
    machines: [],
    stats: {},
    selected: null,
    paused: false,
    queue: [],
    filter: 'all',
    tab: 'req',
    snapAt: 0,
    window: 500
  };

  // ---- formatting ---------------------------------------------------------------------------------------------
  function fmtUs(us) {
    if (!us || us <= 0) return '–';
    if (us < 1000) return us + ' µs';
    var ms = us / 1000;
    if (ms < 100) return ms.toFixed(1) + ' ms';
    if (ms < 1000) return Math.round(ms) + ' ms';
    return (ms / 1000).toFixed(2) + ' s';
  }
  function fmtAge(ms) {
    if (ms < 0) return 'never reported';
    var s = Math.round(ms / 1000);
    if (s < 2) return 'just now';
    if (s < 120) return s + ' s ago';
    return Math.round(s / 60) + ' min ago';
  }
  function fmtClock(ms) {
    var d = new Date(ms);
    var p = function (n) { return (n < 10 ? '0' : '') + n; };
    return p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
  }
  function shortKind(k) {
    return { 'executed': 'executed', 'executed-monitor': 'executed (pepd: no)', 'rejected': 'rejected', 'issued': 'token not used', 'incomplete': 'incomplete', 'running': 'in progress' }[k] || k;
  }

  // ---- components ---------------------------------------------------------------------------------------------
  var STALE_MS = 8000;
  function machineStatus(m) {
    if (m.machine === 'M3') return m.status;
    if (m.age_ms < 0) return 'unknown';
    var age = m.age_ms + (Date.now() - state.snapAt);
    if (age > STALE_MS) return 'unknown';
    return m.status;
  }
  function renderMachines() {
    var box = $('machines');
    clear(box);
    state.machines.forEach(function (m) {
      var st = machineStatus(m);
      var card = el('div', 'card');
      var h = el('h3');
      h.appendChild(el('span', null, m.machine + ' — ' + m.role));
      h.appendChild(el('span', 'pill ' + st, st === 'unknown' ? 'UNKNOWN' : st === 'idle' ? 'idle' : st.toUpperCase()));
      card.appendChild(h);
      var age = m.age_ms < 0 ? -1 : m.age_ms + (Date.now() - state.snapAt);
      var what = m.machine === 'M3' ? 'last request ' : 'last report ';
      card.appendChild(el('div', 'age', what + fmtAge(age) + (st === 'unknown' && m.age_ms >= 0 ? ' — silent: not shown as up' : '')));
      var ul = el('ul');
      (m.components || []).forEach(function (c) {
        var li = el('li');
        li.appendChild(el('span', 'dot ' + (st === 'unknown' ? 'unknown' : c.status)));
        li.appendChild(el('span', null, c.name + (c.detail ? ' — ' + c.detail : '')));
        ul.appendChild(li);
      });
      card.appendChild(ul);
      var keys = Object.keys(m.facts || {}).sort();
      if (keys.length) {
        var dl = el('dl', 'facts');
        keys.forEach(function (k) { dl.appendChild(el('dt', null, k)); dl.appendChild(el('dd', null, m.facts[k])); });
        card.appendChild(dl);
      }
      box.appendChild(card);
    });
  }

  // ---- latency ------------------------------------------------------------------------------------------------
  var ROWS = [
    ['total', 'End to end', 'agent (M3)', false],
    ['cell_total', 'Round trip to the cell', 'agent (M3)', false],
    ['cell_connect', 'TCP connect', 'agent (M3)', true],
    ['cell_tls', 'TLS handshake', 'agent (M3)', true],
    ['cell_network', 'network + HTTP', 'agent − cell', true],
    ['cell_decision', 'cell decision', 'brokerd (M1)', true],
    ['app_total', 'Round trip to the application', 'agent (M3)', false],
    ['app_connect', 'TCP connect', 'agent (M3)', true],
    ['app_network', 'network + HTTP', 'agent − app', true],
    ['app_handling', 'application handling', 'app (M2)', true],
    ['pepd_verdict', 'pepd verdict', 'pepd (M2)', true]
  ];
  function renderStats() {
    var body = $('stats').querySelector('tbody');
    clear(body);
    var maxP95 = 0;
    ROWS.forEach(function (r) { var s = state.stats[r[0]]; if (s && s.p95_us > maxP95) maxP95 = s.p95_us; });
    var any = false;
    ROWS.forEach(function (r) {
      var s = state.stats[r[0]];
      if (!s) return;
      any = true;
      var tr = el('tr');
      tr.appendChild(el('td', r[3] ? 'sub' : null, (r[3] ? '↳ ' : '') + r[1]));
      tr.appendChild(el('td', 'muted', r[2]));
      tr.appendChild(el('td', null, s.n));
      tr.appendChild(el('td', null, fmtUs(s.p50_us)));
      tr.appendChild(el('td', null, fmtUs(s.p95_us)));
      tr.appendChild(el('td', null, fmtUs(s.p99_us)));
      tr.appendChild(el('td', null, fmtUs(s.max_us)));
      var bc = el('td', 'barcol');
      var bar = el('div', 'bar');
      bar.style.width = maxP95 ? Math.max(1, Math.round(100 * s.p95_us / maxP95)) + '%' : '1%';
      bc.appendChild(bar);
      tr.appendChild(bc);
      body.appendChild(tr);
    });
    if (!any) {
      var tr0 = el('tr'); var td = el('td', 'empty', 'No latency measured yet — make a request.'); td.colSpan = 8; tr0.appendChild(td); body.appendChild(tr0);
    }
    $('window').textContent = '— percentiles over the last ' + state.window + ' requests; every duration is measured on one machine with one clock';
    renderSpark();
  }
  function renderSpark() {
    var svg = $('spark');
    clear(svg);
    var vals = [];
    var arr = Array.from(state.requests.values());
    arr.slice(-60).forEach(function (r) { if (r.total_us > 0) vals.push(r.total_us / 1000); });
    if (vals.length < 2) return;
    var max = Math.max.apply(null, vals), W = 300, H = 60;
    var ns = 'http://www.w3.org/2000/svg';
    var pl = document.createElementNS(ns, 'polyline');
    pl.setAttribute('fill', 'none'); pl.setAttribute('stroke', 'currentColor'); pl.setAttribute('stroke-width', '1.5');
    pl.setAttribute('points', vals.map(function (v, i) { return (i * W / (vals.length - 1)).toFixed(1) + ',' + (H - 4 - (H - 24) * v / max).toFixed(1); }).join(' '));
    svg.appendChild(pl);
    var t = document.createElementNS(ns, 'text');
    t.setAttribute('x', '2'); t.setAttribute('y', '10'); t.setAttribute('font-size', '9'); t.setAttribute('fill', 'currentColor');
    t.textContent = 'max ' + max.toFixed(1) + ' ms';
    svg.appendChild(t);
  }

  // ---- request list -------------------------------------------------------------------------------------------
  function passes(v) {
    var k = v.ending.kind;
    switch (state.filter) {
      case 'executed': return k === 'executed' || k === 'executed-monitor';
      case 'warn': return k === 'executed-monitor';
      case 'rejected': return k === 'rejected';
      case 'open': return k === 'running' || k === 'incomplete' || k === 'issued';
    }
    return true;
  }
  function miniPath(v) {
    var s = el('span', 'mini');
    (v.path || []).forEach(function (h) { var d = el('span', 'dot ' + h.status); d.title = h.name + ': ' + h.status; s.appendChild(d); });
    return s;
  }
  function rowFor(v) {
    var r = el('div', 'row' + (state.selected === v.id ? ' sel' : ''));
    r.setAttribute('role', 'listitem'); r.tabIndex = 0; r.dataset.id = v.id;
    r.appendChild(el('span', 'when', fmtClock(v.start_ms)));
    var w = el('span', 'what', v.summary || v.id);
    w.title = v.id + ' — ' + v.ending.text;
    r.appendChild(w);
    r.appendChild(miniPath(v));
    var right = el('span');
    right.appendChild(el('span', 'pill ' + v.ending.kind, shortKind(v.ending.kind)));
    right.appendChild(document.createTextNode(' '));
    right.appendChild(el('span', 'ms', fmtUs(v.total_us)));
    r.appendChild(right);
    var open = function () { state.selected = v.id; try { history.replaceState(null, '', '#' + v.id); } catch (e) { /* ignore */ } renderList(); renderDetail(); };
    r.addEventListener('click', open);
    r.addEventListener('keydown', function (ev) { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); open(); } });
    return r;
  }
  function renderList() {
    var box = $('list');
    clear(box);
    var arr = Array.from(state.requests.values()).reverse().filter(passes);
    $('count-req').textContent = '(' + state.requests.size + ')';
    if (!arr.length) { box.appendChild(el('div', 'empty', state.requests.size ? 'Nothing matches this filter.' : 'Waiting for a request…')); return; }
    arr.slice(0, 300).forEach(function (v) { box.appendChild(rowFor(v)); });
  }
  function renderLoose() {
    var box = $('loose');
    clear(box);
    $('count-loose').textContent = '(' + state.loose.length + ')';
    if (!state.loose.length) {
      box.appendChild(el('div', 'empty', 'Nothing yet. A client that is not our scripts — curl, a scanner, a red team — sends no trace id: what the cell and the application saw of it is listed here.'));
      return;
    }
    state.loose.slice(0, 300).forEach(function (e) {
      var li = el('div', 'row'); li.style.gridTemplateColumns = '70px 36px minmax(0,1fr)';
      li.appendChild(el('span', 'when', fmtClock(e.recv_ms)));
      li.appendChild(el('span', 'mach', e.machine));
      var t = el('span', null, e.component + ' — ' + e.text);
      if (e.why) t.title = e.reason + ' — ' + e.why.where + ': ' + e.why.meaning;
      li.appendChild(t);
      box.appendChild(li);
    });
  }

  // ---- detail -------------------------------------------------------------------------------------------------
  var LAT = [
    ['cell_connect', 'TCP connect to the cell', 1], ['cell_tls', 'TLS handshake', 1], ['cell_network', 'network + HTTP', 1],
    ['cell_decision', 'cell decision (M1)', 1], ['cell_total', 'round trip to the cell', 0],
    ['app_connect', 'TCP connect to the app', 1], ['app_network', 'network + HTTP', 1], ['app_handling', 'application handling (M2)', 1],
    ['pepd_verdict', 'pepd verdict (M2)', 2], ['app_total', 'round trip to the application', 0]
  ];
  function renderDetail() {
    var box = $('detail');
    clear(box);
    var v = state.selected && state.requests.get(state.selected);
    if (!v) { box.appendChild(el('p', 'muted', 'Click a request to see its path and where the time went.')); return; }
    box.appendChild(el('h3', null, v.summary || v.id));
    box.appendChild(el('div', 'muted', 'trace ' + v.id));
    box.appendChild(el('div', 'ending ' + v.ending.kind, v.ending.text));
    var path = el('div', 'path');
    (v.path || []).forEach(function (h, i) {
      if (i) path.appendChild(el('span', 'arrow', '→'));
      var c = el('div', 'hop ' + h.status);
      c.appendChild(el('div', 'n', h.name));
      c.appendChild(el('div', 'm', h.machine + ' · ' + h.status + (h.us ? ' · ' + fmtUs(h.us) : '')));
      if (h.detail) c.appendChild(el('div', 'd', h.detail));
      path.appendChild(c);
    });
    box.appendChild(path);
    var seg = v.segments || {};
    var maxUs = 0;
    LAT.forEach(function (l) { if (seg[l[0]] > maxUs) maxUs = seg[l[0]]; });
    if (maxUs) {
      var g = el('div', 'lat');
      LAT.forEach(function (l) {
        var us = seg[l[0]];
        if (us === undefined) return;
        g.appendChild(el('span', 'l' + (l[2] ? ' sub' : ''), (l[2] === 2 ? '↳ ' : l[2] ? '↳ ' : '') + l[1]));
        var b = el('div', 'bar'); b.style.width = Math.max(1, Math.round(100 * us / maxUs)) + '%';
        g.appendChild(b);
        g.appendChild(el('span', 'v', fmtUs(us)));
      });
      box.appendChild(g);
    }
    var ul = el('ul', 'events');
    (v.events || []).forEach(function (e) {
      var li = el('li');
      li.appendChild(el('span', 'mach', e.machine));
      li.appendChild(el('span', 'comp', e.component));
      li.appendChild(el('span', null, e.text));
      if (e.why) li.appendChild(el('span', 'why', e.reason + ' — ' + e.why.where + ': ' + e.why.meaning));
      ul.appendChild(li);
    });
    box.appendChild(ul);
  }

  // ---- data ---------------------------------------------------------------------------------------------------
  function apply(snap) {
    state.snapAt = Date.now();
    state.machines = snap.machines || [];
    state.stats = snap.stats || {};
    state.window = snap.window || 500;
    $('label').textContent = snap.label ? '— ' + snap.label : '';
  }
  function load(full) {
    return fetch('/api/snapshot?limit=' + (full ? 300 : 1), { credentials: 'same-origin', cache: 'no-store' }).then(function (r) {
      if (!r.ok) throw new Error('snapshot ' + r.status);
      return r.json();
    }).then(function (snap) {
      apply(snap);
      if (full) {
        state.requests = new Map();
        (snap.requests || []).slice().reverse().forEach(function (v) { state.requests.set(v.id, v); });
        state.loose = snap.loose || [];
        var want = decodeURIComponent((location.hash || '').replace(/^#/, ''));
        if (!state.selected && want && state.requests.has(want)) state.selected = want;
        renderList(); renderLoose();
      }
      renderMachines(); renderStats(); renderDetail();
    });
  }
  function setLive(ok, text) { var p = $('live'); p.className = 'pill ' + (ok ? 'up' : 'unknown'); p.textContent = text; }
  function handle(kind, data) {
    if (state.paused) { state.queue.push([kind, data]); setLive(true, 'paused (' + state.queue.length + ' waiting)'); return; }
    if (kind === 'request') {
      state.requests.delete(data.id);
      state.requests.set(data.id, data);
      renderList();
      if (state.selected === data.id) renderDetail();
      renderStats();
    } else if (kind === 'loose') {
      state.loose.unshift(data);
      renderLoose();
    } else if (kind === 'state') {
      var i = state.machines.findIndex(function (m) { return m.machine === data.machine; });
      if (i >= 0) {
        state.machines[i].components = data.components || [];
        state.machines[i].facts = data.facts || {};
        state.machines[i].age_ms = 0;
        var st = 'up';
        (data.components || []).forEach(function (c) { if (c.status === 'down') st = 'down'; else if (c.status === 'degraded' && st === 'up') st = 'degraded'; });
        state.machines[i].status = st;
        state.snapAt = Date.now();
        renderMachines();
      }
    }
  }
  function connect() {
    var es = new EventSource('/api/stream');
    es.onopen = function () { setLive(true, 'live'); };
    ['request', 'loose', 'state'].forEach(function (k) {
      es.addEventListener(k, function (ev) { try { handle(k, JSON.parse(ev.data)); } catch (e) { /* ignore a malformed update */ } });
    });
    es.onerror = function () {
      setLive(false, 'reconnecting…');
      es.close();
      setTimeout(function () { load(true).then(connect).catch(function () { setTimeout(connect, 3000); }); }, 2000);
    };
  }

  // ---- controls -----------------------------------------------------------------------------------------------
  $('filter').addEventListener('change', function (e) { state.filter = e.target.value; renderList(); });
  $('pause').addEventListener('click', function () {
    state.paused = !state.paused;
    $('pause').textContent = state.paused ? 'Resume' : 'Pause';
    if (!state.paused) {
      var q = state.queue; state.queue = [];
      q.forEach(function (x) { handle(x[0], x[1]); });
      setLive(true, 'live');
    } else { setLive(true, 'paused'); }
  });
  function tab(which) {
    state.tab = which;
    $('tab-req').className = 'tab' + (which === 'req' ? ' active' : '');
    $('tab-loose').className = 'tab' + (which === 'loose' ? ' active' : '');
    document.querySelector('.split').className = 'split' + (which === 'req' ? '' : ' hidden');
    $('loose').className = 'list' + (which === 'loose' ? '' : ' hidden');
  }
  $('tab-req').addEventListener('click', function () { tab('req'); });
  $('tab-loose').addEventListener('click', function () { tab('loose'); });

  setInterval(function () { renderMachines(); }, 1000);
  setInterval(function () { if (!state.paused) load(false).catch(function () {}); }, 3000);
  load(true).then(connect).catch(function () { setLive(false, 'cannot reach the console'); setTimeout(function () { location.reload(); }, 4000); });
})();
