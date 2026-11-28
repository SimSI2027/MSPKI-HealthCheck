// MSPKI Health Check demo site. Plain ES2017 module, no framework, no third-party code, no request to any other site.
// Everything shown comes from data/<scenario>/view.json, computed at build time by the window's own helpers from the results that the
// real engine produced against a simulated environment (docs/DEMO-SITE.md).

const NS = 'http://www.w3.org/2000/svg';
const main = document.getElementById('main');
const live = document.getElementById('live');
const cache = new Map();
let site = null;
const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)');

// ---- tiny DOM helpers (text only: data is never parsed as HTML) -------------------------------------------------------------------
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  for (const k of kids.flat()) { if (k === null || k === undefined || k === false) continue; el.append(k instanceof Node ? k : document.createTextNode(String(k))); }
  return el;
}
function s(tag, attrs, ...kids) {
  const el = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) { if (v !== null && v !== undefined) el.setAttribute(k, String(v)); }
  for (const k of kids.flat()) { if (k) el.append(k instanceof Node ? k : document.createTextNode(String(k))); }
  return el;
}
function announce(text) { live.textContent = ''; setTimeout(() => { live.textContent = text; }, 30); }

// ---- icons (drawn for this site to match the window's meaning; one per status and per object kind) ------------------------------------
const ICON = {
  Critical: 'M5.3 1h5.4L15 5.3v5.4L10.7 15H5.3L1 10.7V5.3L5.3 1Zm2 3.5v5h1.5v-5H7.3Zm0 6.2v1.6h1.5v-1.6H7.3Z',
  Fail: 'M8 1a7 7 0 1 1 0 14A7 7 0 0 1 8 1Zm-2.5 3.4L4.4 5.5 6.9 8l-2.5 2.5 1.1 1.1L8 9.1l2.5 2.5 1.1-1.1L9.1 8l2.5-2.5-1.1-1.1L8 6.9 5.5 4.4Z',
  Warning: 'M8 1.5 15.2 14H.8L8 1.5Zm-.8 4.5v4h1.6V6H7.2Zm0 5v1.6h1.6V11H7.2Z',
  Error: 'M8 1a7 7 0 1 1 0 14A7 7 0 0 1 8 1Zm-.8 3.5v4.8h1.6V4.5H7.2Zm0 6v1.6h1.6v-1.6H7.2Z',
  CouldNotCheck: 'M5 7V5a3 3 0 0 1 6 0v2h1v7H4V7h1Zm1.5 0h3V5a1.5 1.5 0 0 0-3 0v2Z',
  Information: 'M8 1a7 7 0 1 1 0 14A7 7 0 0 1 8 1Zm-.8 5.8v4.8h1.6V6.8H7.2Zm0-2.6v1.6h1.6V4.2H7.2Z',
  Pass: 'M8 1a7 7 0 1 1 0 14A7 7 0 0 1 8 1Zm3.3 4.3L7 9.6 4.8 7.4 3.7 8.5 7 11.8l5.4-5.4-1.1-1.1Z',
  Skipped: 'M2 7.2h12v1.6H2z',
  NotApplicable: 'M2 7.2h12v1.6H2z',
  overview: 'M8 1.5 1 7.3V15h5v-4.5h4V15h5V7.3L8 1.5Z',
  findings: 'M2 3h1.8v1.8H2V3Zm3.5.2h8.5v1.4H5.5V3.2ZM2 7.1h1.8v1.8H2V7.1Zm3.5.2h8.5v1.4H5.5V7.3ZM2 11.2h1.8V13H2v-1.8Zm3.5.2h8.5v1.4H5.5v-1.4Z',
  map: 'M3 2.5a2 2 0 1 1 0 4 2 2 0 0 1 0-4Zm10 0a2 2 0 1 1 0 4 2 2 0 0 1 0-4ZM8 9.5a2 2 0 1 1 0 4 2 2 0 0 1 0-4ZM4.6 5.6l3 4.2-1 .7-3-4.2 1-.7Zm6.8 0 1 .7-3 4.2-1-.7 3-4.2ZM5 4h6v1.2H5V4Z',
  play: 'M4 2.5v11l9-5.5-9-5.5Z', pause: 'M4 2.5h3v11H4zm5 0h3v11H9z', copy: 'M5 1h8v10H5V1Zm1.3 1.3v7.4h5.4V2.3H6.3ZM2.5 4.5h1.3v8.2h6.4V14H2.5V4.5Z',
  close: 'm3.5 2.4 4.5 4.5 4.5-4.5 1.1 1.1L9.1 8l4.5 4.5-1.1 1.1L8 9.1l-4.5 4.5-1.1-1.1L6.9 8 2.4 3.5l1.1-1.1Z',
  check: 'M13.4 3.6 6 11 2.6 7.6 1.5 8.7 6 13.2l8.5-8.5-1.1-1.1Z',
};
const KIND = {
  CA: 'M8 1.5 2.5 3.8v3.9c0 3.2 2.3 6 5.5 6.8 3.2-.8 5.5-3.6 5.5-6.8V3.8L8 1.5Z',
  Unknown: 'M8 1a7 7 0 1 1 0 14A7 7 0 0 1 8 1Zm0 2.6a2.6 2.6 0 0 0-2.6 2.6h1.5a1.1 1.1 0 1 1 1.8.9c-.8.5-1.4 1.1-1.4 2.2v.4h1.5v-.3c0-.5.3-.8.9-1.2a2.6 2.6 0 0 0-1.7-4.6Zm-.7 7.6v1.5h1.5v-1.5H7.3Z',
  Certificate: 'M2.5 2h11v8h-3.2l.9 4-2.2-1.2L6.8 14l.9-4H2.5V2Zm2 2v1.2h7V4h-7Zm0 2.4v1.2h4.5V6.4H4.5Z',
  Endpoint: 'M6.6 9.4 5.5 8.3l3.9-3.9 1.1 1.1-3.9 3.9ZM4.3 12.9a2.4 2.4 0 0 1-1.7-4.1l2-2 1.1 1.1-2 2a.9.9 0 1 0 1.3 1.3l2-2 1.1 1.1-2 2c-.5.4-1.1.6-1.8.6Zm6.1-3.3L9.3 8.5l2-2a.9.9 0 1 0-1.3-1.3l-2 2L6.9 6.1l2-2a2.4 2.4 0 1 1 3.4 3.4l-1.9 2.1Z',
  Host: 'M2 2h12v5H2V2Zm0 7h12v5H2V9Zm2-5v1.2h1.2V4H4Zm0 7v1.2h1.2V11H4Z',
  Directory: 'M1.5 3h5l1.5 1.5h6.5V13h-13V3Z',
  Cluster: 'M2 4h9v7H2V4Zm3-2h9v7h-1.5V3.5H5V2Z',
};
function icon(path, cls) { return s('svg', { viewBox: '0 0 16 16', class: cls || null, 'aria-hidden': 'true' }, s('path', { d: path })); }
const STATUS_TONE = { Critical: 'Bad', Fail: 'Bad', Warning: 'Warn', Error: 'Admin', CouldNotCheck: 'Admin', Information: 'Info', Pass: 'Good', Skipped: 'Neutral', NotApplicable: 'Neutral' };
const STATUS_ORDER = ['Critical', 'Fail', 'Warning', 'Error', 'CouldNotCheck', 'Information', 'Pass', 'Skipped', 'NotApplicable'];

// ---- data ---------------------------------------------------------------------------------------------------------------------------
async function getJson(url) { const r = await fetch(url, { credentials: 'omit' }); if (!r.ok) throw new Error(url + ': ' + r.status); return r.json(); }
async function loadSite() { if (!site) { site = await getJson('data/scenarios.json'); document.getElementById('sim-version').textContent = site.version; document.getElementById('sim-commit').textContent = site.commit || 'local build'; } return site; }
async function loadScenario(id) { if (!cache.has(id)) cache.set(id, await getJson('data/' + encodeURIComponent(id) + '/view.json')); return cache.get(id); }

// ---- routing: #/, #/how, #/s/<id>[/findings|/map|/finding/<fid>] ------------------------------------------------------------------
let replayStop = null;
async function route() {
  if (replayStop) { replayStop(); replayStop = null; }
  const parts = location.hash.replace(/^#\/?/, '').split('/').filter(Boolean).map(decodeURIComponent);
  try {
    await loadSite();
    if (parts[0] === 's' && parts[1]) {
      const v = await loadScenario(parts[1]);
      const page = parts[2] === 'finding' ? 'findings' : (parts[2] || 'overview');
      renderScenario(v, page, parts[2] === 'finding' ? parts[3] : null);
    } else if (parts[0] === 'how') renderHow();
    else renderHome();
  } catch (e) {
    main.replaceChildren(h('div', { class: 'wrap' }, h('div', { class: 'card' }, h('h1', {}, 'This page could not load its data'), h('p', { class: 'muted' }, String(e.message)), h('a', { class: 'btn', href: '#/' }, 'Back to the scenarios'))));
  }
  main.focus({ preventScroll: true });
}

// ---- home ---------------------------------------------------------------------------------------------------------------------------
function renderHome() {
  document.title = 'MSPKI Health Check · interactive demo';
  // The window replaying discovery of the As found scenario (a short clip of the real window; a still frame with reduced motion).
  const alt = 'The MSPKI Health Check window building its discovery map for the As found scenario: the CAs, the addresses they publish and the hosts that serve them appear as the run finds them.';
  const media = h('figure', { class: 'hero-media' });
  if (reduceMotion.matches) media.append(h('img', { src: 'assets/media/discovery-poster.png', alt, width: 960, height: 583 }));
  else {
    const vid = h('video', { src: 'assets/media/discovery.mp4', poster: 'assets/media/discovery-poster.png', autoplay: true, muted: true, loop: true, playsinline: true, preload: 'auto', 'aria-label': alt, width: 960, height: 583 });
    vid.muted = true;
    media.append(vid);
  }
  const cards = site.scenarios.map(sc => h('a', { class: 'scard', href: '#/s/' + encodeURIComponent(sc.id) },
    h('div', { class: 'scard-top' }, h('span', { class: 'scard-score' }, sc.score || '–'), h('span', { class: 'tone tone-' + (sc.tone || 'Neutral') }, sc.band || 'not scored')),
    h('h3', {}, sc.title), h('p', {}, sc.summary)));
  main.replaceChildren(h('div', { class: 'wrap' },
    h('section', { class: 'hero' },
      h('div', {},
        h('h1', {}, 'See your Microsoft PKI the way the health check sees it'),
        h('p', {}, 'MSPKI Health Check discovers an AD CS estate by itself (CAs, certificates, CRLs, publication points, templates, NDES) and explains every problem it finds: what it means, the likely causes, how to confirm each one, and how to fix it.'),
        h('ul', { class: 'promise', 'aria-label': 'What it never does' },
          h('li', {}, icon(ICON.check), 'Read-only'), h('li', {}, icon(ICON.check), 'No configuration'), h('li', {}, icon(ICON.check), 'No install'), h('li', {}, icon(ICON.check), 'Windows PowerShell 5.1')),
        h('p', { class: 'muted small' }, 'Pick a scenario of the fictional company Alcyone Orbital Systems. Each one was produced by the real analysers against a simulated network.')),
      media),
    h('h2', {}, 'Scenarios'),
    h('p', { class: 'muted' }, 'Each changes one thing in the same simulated estate.'),
    h('div', { class: 'cards' }, cards),
    h('p', { class: 'footer' }, 'Get the tool on GitHub: everything runs on your own domain-joined computer and never writes anywhere except its own output folder.')));
}

function renderHow() {
  document.title = 'How this demo is made · MSPKI Health Check';
  main.replaceChildren(h('div', { class: 'wrap how' }, h('div', { class: 'card' },
    h('h1', {}, 'How this demo is made'),
    h('p', {}, 'Nothing on this site is written by hand. For each scenario, the build:'),
    h('ol', {},
      h('li', {}, 'imports the real MSPKI Health Check module, unchanged;'),
      h('li', {}, 'replaces only its input and output boundary (directory reads, CA calls, DNS, TCP, TLS, HTTP, this computer’s stores and the clock) with answers from a simulated world described as data;'),
      h('li', {}, 'runs the full health check, records the events the window would receive, and keeps the results file;'),
      h('li', {}, 'computes this page’s score, areas, actions, findings, walkthroughs and map with the window’s own helpers.')),
    h('p', {}, 'A question the simulated world has no answer for stops the build: it can never fall back to a real network. The world’s certificates and CRLs are real cryptographic objects, generated with throw-away keys that never left memory, and the tool checks their signatures for itself.'),
    h('p', {}, 'Names use the reserved .example domain and addresses the documentation range 192.0.2.0/24.'),
    h('p', { class: 'muted small' }, 'Tool ' + site.version + ', commit ' + (site.commit || 'local build') + ', demo clock ' + site.demoClock + '.'),
    h('a', { class: 'btn btn-primary', href: '#/' }, 'Back to the scenarios'))));
}

// ---- scenario view ------------------------------------------------------------------------------------------------------------------
function renderScenario(v, page, findingId) {
  document.title = v.title + ' · MSPKI Health Check demo';
  const base = '#/s/' + encodeURIComponent(v.id);
  const bad = v.findings.filter(f => ['Critical', 'Fail', 'Warning', 'Error', 'CouldNotCheck'].includes(f.status)).length;
  const select = h('select', { 'aria-label': 'Scenario', onchange: e => { location.hash = '#/s/' + encodeURIComponent(e.target.value) + (page === 'overview' ? '' : '/' + page); } },
    site.scenarios.map(sc => h('option', { value: sc.id, selected: sc.id === v.id ? true : null }, sc.title)));
  const nav = h('nav', { class: 'nav', 'aria-label': 'Pages' },
    h('div', { class: 'nav-scen' }, h('div', { class: 'small muted' }, 'Scenario'), select),
    h('a', { href: base, 'aria-current': page === 'overview' ? 'page' : null }, icon(ICON.overview), 'Overview'),
    h('a', { href: base + '/findings', 'aria-current': page === 'findings' ? 'page' : null }, icon(ICON.findings), 'Findings', h('span', { class: 'count', title: bad + ' need attention' }, String(v.findings.length))),
    h('a', { href: base + '/map', 'aria-current': page === 'map' ? 'page' : null }, icon(ICON.map), 'Discovery map'),
    h('a', { href: '#/' }, icon(ICON.overview), 'All scenarios'));
  const content = h('div', { class: 'content' });
  main.replaceChildren(h('div', { class: 'shell' }, nav, content));
  if (page === 'findings') renderFindings(v, content, findingId);
  else if (page === 'map') renderMapPage(v, content);
  else renderOverview(v, content);
}

function ring(score) {
  const r = 70, c = 2 * Math.PI * r;
  const val = score.has ? Number(score.overall) : 0;
  const arc = s('circle', { class: 'arc arc-' + (score.has ? score.tone : 'Neutral'), cx: 84, cy: 84, r, 'stroke-dasharray': c.toFixed(1), 'stroke-dashoffset': c.toFixed(1) });
  const svg = s('svg', { class: 'ring', viewBox: '0 0 168 168', role: 'img', 'aria-label': score.has ? 'Health score ' + val + ' of 100, ' + score.band : 'Not scored' },
    s('circle', { class: 'track', cx: 84, cy: 84, r }), arc,
    s('text', { class: 'num', x: 84, y: 92, 'text-anchor': 'middle' }, score.has ? String(val) : '–'),
    s('text', { class: 'of', x: 84, y: 114, 'text-anchor': 'middle' }, score.has ? 'of 100' : 'not scored'));
  requestAnimationFrame(() => requestAnimationFrame(() => arc.setAttribute('stroke-dashoffset', (c * (1 - val / 100)).toFixed(1))));
  return svg;
}

function renderOverview(v, el) {
  const sc = v.score;
  const areas = h('div', { class: 'areas' }, sc.areas.map(a => {
    const span = h('span', { class: 'bar-' + a.tone });
    requestAnimationFrame(() => requestAnimationFrame(() => { span.style.width = (a.score === null ? 0 : Number(a.score)) + '%'; }));
    return h('div', { class: 'area', title: a.detail }, h('span', {}, a.name), h('strong', {}, a.text), h('div', { class: 'bar', 'aria-hidden': 'true' }, span));
  }));
  const actions = h('ol', { class: 'actions' }, v.actions.items.slice(0, 5).map((a, i) => h('li', {},
    h('button', { class: 'action', type: 'button', onclick: () => { location.hash = '#/s/' + encodeURIComponent(v.id) + '/finding/' + encodeURIComponent(a.tag); } },
      h('span', { class: 'rank tone-' + a.tone }, String(i + 1)),
      h('span', {}, h('strong', {}, a.title), h('div', { class: 'why' }, a.observed ? h('span', { class: 'obs' }, a.observed + ' ') : null, a.cause)),
      h('span', { class: 'small muted' }, a.count)))));
  el.append(
    h('p', { class: 'headline' }, v.headline),
    h('div', { class: 'mission' },
      h('div', { class: 'card ring-wrap' }, ring(sc), h('span', { class: 'tone tone-' + (sc.has ? sc.tone : 'Neutral') }, sc.has ? sc.band : 'Not scored'),
        sc.held ? h('div', { class: 'small muted' }, sc.held) : null, sc.partial ? h('div', { class: 'small muted' }, sc.partialText) : null, sc.reason ? h('div', { class: 'small muted' }, sc.reason) : null,
        areas, h('details', { class: 'small muted' }, h('summary', {}, 'How the score works'), h('p', {}, sc.how))),
      h('div', { class: 'card' }, h('h2', {}, 'What to do next'),
        v.actions.total ? h('p', { class: 'small muted' }, v.actions.total + ' action' + (v.actions.total === 1 ? '' : 's') + ', most urgent first. Select one to see why and how to fix it.') : h('p', {}, 'Nothing needs attention in what was checked.'),
        actions,
        v.actions.total > 5 ? h('a', { class: 'btn', href: '#/s/' + encodeURIComponent(v.id) + '/findings' }, 'All findings') : null)),
    mapCard(v, false),
    h('p', { class: 'small muted' }, 'As run on ' + v.run.computer + ' as ' + v.run.user + ' in ' + (v.run.forest || 'no forest') + ' · demo clock ' + v.manifest.demoClock + ' · ' + v.run.findings + ' findings · tool ' + v.manifest.version));
}

function renderMapPage(v, el) { el.append(h('h1', {}, 'Discovery map'), h('p', { class: 'muted' }, 'How this run found the PKI: each CA, the addresses it publishes in its certificates and properties, and what serves them. Select an object to see its findings.'), mapCard(v, true)); }

// ---- the map and its replay -----------------------------------------------------------------------------------------------------------
function mapCard(v, full) {
  const card = h('section', { class: 'card map-card', 'aria-label': 'Discovery map' });
  if (!v.map || !v.map.nodes.length) { card.append(h('h2', {}, 'Discovery map'), h('p', { class: 'empty' }, 'This run found no CA certificate or published address to draw.')); return card; }
  const m = v.map, pad = 20, W = m.width + pad * 2, H = m.height + pad * 2;
  const svg = s('svg', { class: 'map', viewBox: `${-pad} ${-pad} ${W} ${H}`, width: W, height: H, role: 'group', 'aria-label': 'Discovery map with ' + m.nodes.length + ' objects' });
  const byId = new Map(m.nodes.map(n => [n.id, n]));
  const linkEls = [], nodeEls = new Map();
  for (const l of m.links) {
    const a = byId.get(l.from), b = byId.get(l.to); if (!a || !b) continue;
    const mx = (a.x + b.x) / 2;
    const p = s('path', { class: 'link link-' + (l.kind === 'issued' ? 'issued' : l.tone), d: `M${a.x} ${a.y} C ${mx} ${a.y}, ${mx} ${b.y}, ${b.x} ${b.y}` }, s('title', {}, l.text || ''));
    svg.append(p); linkEls.push({ el: p, a: l.from, b: l.to });
  }
  for (const n of m.nodes) {
    const kind = KIND[n.kind] ? n.kind : (n.kind === 'Cluster' ? 'Cluster' : 'Endpoint');
    const g = s('g', { class: 'node node-' + n.tone, transform: `translate(${n.x} ${n.y})`, tabindex: 0, role: 'button', 'aria-label': `${n.label}, ${n.sub}` },
      s('title', {}, [n.full, n.sub, n.where].filter(Boolean).join('\n')),
      s('circle', { class: 'ping', r: 12 }),
      s('circle', { class: 'disc', r: 13 }),
      n.kind === 'Cluster' ? s('text', { class: 'glyph', 'text-anchor': 'middle', y: 4, 'font-size': 11, 'font-weight': 700 }, String(n.count || '')) : s('path', { class: 'glyph', d: KIND[kind] || KIND.Endpoint, transform: 'translate(-8 -8)' }),
      s('text', { class: 'label', x: 20, y: -1 }, n.label),
      s('text', { class: 'sub', x: 20, y: 13 }, n.sub));
    const open = () => { const fid = firstFindingFor(v, n); location.hash = '#/s/' + encodeURIComponent(v.id) + (fid ? '/finding/' + encodeURIComponent(fid) : '/findings'); };
    g.addEventListener('click', open);
    g.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(); } });
    svg.append(g); nodeEls.set(n.id, { el: g, n });
  }
  // Replay: objects appear when the run reported them (entity events), probes pulse, links follow their two ends.
  const appear = new Map(); const pulses = [];
  const entityTime = new Map();
  for (const e of v.replay) { if (e.k === 'e' && !entityTime.has(e.id)) entityTime.set(e.id, e.t); }
  const layerFirst = new Map();
  for (const n of m.nodes) { const t = entityTime.get(n.entity); if (t !== undefined) { appear.set(n.id, t); const lf = layerFirst.get(n.layer); if (lf === undefined || t < lf) layerFirst.set(n.layer, t); } }
  for (const n of m.nodes) { if (!appear.has(n.id)) appear.set(n.id, layerFirst.has(n.layer) ? layerFirst.get(n.layer) : 0); }
  const nodeByEntity = new Map(m.nodes.filter(n => n.entity).map(n => [n.entity, n.id]));
  for (const e of v.replay) { if (e.k === 'p' && e.phase === 'Start' && nodeByEntity.has(e.id)) pulses.push({ t: e.t, id: nodeByEntity.get(e.id) }); }
  const stages = v.replay.filter(e => e.k === 's');
  const end = Math.max(1, ...v.replay.map(e => e.t));
  const stage = h('span', { class: 'small muted', 'aria-live': 'off' }, '');
  const time = h('span', { class: 'time' }, '');
  const range = h('input', { type: 'range', min: 0, max: end, step: 10, value: end, 'aria-label': 'Replay position' });
  let at = end, playing = false, speed = 1, last = 0, raf = 0, pulseAt = 0;
  const draw = () => {
    for (const { el, n } of nodeEls.values()) el.classList.toggle('hidden', appear.get(n.id) > at);
    for (const l of linkEls) l.el.classList.toggle('hidden', appear.get(l.a) > at || appear.get(l.b) > at);
    let st = ''; for (const x of stages) { if (x.t <= at) st = x.text; }
    stage.textContent = at >= end ? 'Run complete' : st;
    time.textContent = (at / 1000).toFixed(1) + ' s / ' + (end / 1000).toFixed(1) + ' s';
    range.value = String(Math.round(at));
  };
  const tick = now => {
    if (!playing) return;
    const dt = last ? now - last : 16; last = now;
    const from = at; at = Math.min(end, at + dt * speed * 1.6);
    if (!reduceMotion.matches) { for (const p of pulses) { if (p.t > from && p.t <= at && now - pulseAt > 60) { const ne = nodeEls.get(p.id); if (ne) { ne.el.classList.remove('pulse'); void ne.el.getBBox(); ne.el.classList.add('pulse'); pulseAt = now; } } } }
    draw();
    if (at >= end) { setPlaying(false); announce('Replay finished: ' + m.nodes.length + ' objects found.'); return; }
    raf = requestAnimationFrame(tick);
  };
  const playBtn = h('button', { class: 'btn', type: 'button' }, icon(ICON.play), 'Replay discovery');
  const setPlaying = on => {
    playing = on; last = 0; cancelAnimationFrame(raf);
    playBtn.replaceChildren(icon(on ? ICON.pause : ICON.play), on ? 'Pause' : (at >= end ? 'Replay discovery' : 'Play'));
    playBtn.setAttribute('aria-pressed', on ? 'true' : 'false');
    if (on) { if (at >= end) at = 0; raf = requestAnimationFrame(tick); }
  };
  playBtn.addEventListener('click', () => setPlaying(!playing));
  range.addEventListener('input', () => { setPlaying(false); at = Number(range.value); draw(); });
  const speeds = [1, 2, 4].map(x => h('button', { class: 'btn', type: 'button', 'aria-pressed': x === 1 ? 'true' : 'false', 'aria-label': 'Speed ' + x + ' times', onclick: e => { speed = x; for (const b of e.target.closest('.replay').querySelectorAll('[data-speed]')) b.setAttribute('aria-pressed', b.dataset.speed === String(x) ? 'true' : 'false'); } }, x + 'x'));
  speeds.forEach((b, i) => { b.dataset.speed = String([1, 2, 4][i]); });
  card.append(h('div', { class: 'map-head' },
      h('div', { class: 'grow' }, h('h2', {}, full ? m.nodes.length + ' objects' : 'Discovery map'), h('div', { class: 'small muted' }, m.nodes.length + ' objects · ' + m.links.length + ' links · replay of the recorded run (' + (end / 1000).toFixed(1) + ' simulated seconds)')),
      h('div', { class: 'replay' }, playBtn, speeds, range, time)),
    h('div', { class: 'small muted' }, stage),
    h('div', { class: 'map-scroll' + (full ? '' : ' map-card-scroll') }, svg),
    h('div', { class: 'legend' }, [['Good', 'Healthy'], ['Warn', 'Warning'], ['Bad', 'Failing'], ['Admin', 'Could not check'], ['Neutral', 'No finding']].map(([t, w]) => h('span', { class: 'tone tone-' + t }, w))));
  draw();
  // Opaque plates behind the labels, as in the window, so links pass behind the text (measured once the map is on screen).
  requestAnimationFrame(() => { for (const { el } of nodeEls.values()) { try { const a = el.querySelector('.label').getBBox(), b = el.querySelector('.sub').getBBox(); const x = Math.min(a.x, b.x) - 3, y = a.y - 2, w = Math.max(a.x + a.width, b.x + b.width) - x + 3, hh = b.y + b.height - y + 2; el.insertBefore(s('rect', { class: 'plate', x: x.toFixed(1), y: y.toFixed(1), width: w.toFixed(1), height: hh.toFixed(1), rx: 3 }), el.querySelector('.label')); } catch (e) { /* not rendered */ } } });
  replayStop = () => { playing = false; cancelAnimationFrame(raf); };
  if (!full && !reduceMotion.matches && sessionStorageSafe()) { setTimeout(() => { if (document.body.contains(svg)) { at = 0; draw(); setPlaying(true); } }, 400); }
  return card;
}
function sessionStorageSafe() { return true; }
function firstFindingFor(v, n) {
  const words = [n.full, n.label].filter(Boolean).map(x => String(x).toLowerCase());
  const order = f => STATUS_ORDER.indexOf(f.status);
  const hits = v.findings.filter(f => words.some(w => w.length > 3 && (f.target.toLowerCase().includes(w) || f.title.toLowerCase().includes(w)))).sort((a, b) => order(a) - order(b));
  return hits.length ? hits[0].id : null;
}

// ---- findings and the details pane ----------------------------------------------------------------------------------------------------
function renderFindings(v, el, findingId) {
  const present = STATUS_ORDER.filter(st => v.findings.some(f => f.status === st));
  const state = { on: new Set(present.filter(st => !['Pass', 'Skipped', 'NotApplicable', 'Information'].includes(st))), q: '' };
  if (!state.on.size) present.forEach(x => state.on.add(x));
  if (findingId) { const f = v.findings.find(x => x.id === findingId); if (f) state.on.add(f.status); }
  const list = h('ul', { class: 'flist', 'aria-label': 'Findings' });
  const pane = h('aside', { class: 'card pane', 'aria-label': 'Details' }, h('p', { class: 'empty' }, 'Select a finding to see what it means, the likely causes, how to confirm each one and how to fix it.'));
  const chips = h('div', { class: 'filters', role: 'group', 'aria-label': 'Show findings with status' });
  const search = h('input', { class: 'search', type: 'search', placeholder: 'Search findings', 'aria-label': 'Search findings' });
  const fill = () => {
    const q = state.q.toLowerCase();
    const shown = v.findings.filter(f => state.on.has(f.status) && (!q || (f.title + ' ' + f.message + ' ' + f.category).toLowerCase().includes(q)))
      .map((f, i) => [f, i]).sort((a, b) => (STATUS_ORDER.indexOf(a[0].status) - STATUS_ORDER.indexOf(b[0].status)) || (a[1] - b[1])).map(x => x[0]);
    list.replaceChildren(...(shown.length ? shown.map(f => h('li', {}, h('button', { class: 'frow', type: 'button', 'data-id': f.id, 'aria-current': f.id === findingId ? 'true' : null, onclick: () => { history.replaceState(null, '', '#/s/' + encodeURIComponent(v.id) + '/finding/' + encodeURIComponent(f.id)); findingId = f.id; for (const b of list.querySelectorAll('.frow')) b.setAttribute('aria-current', b.dataset.id === f.id ? 'true' : 'false'); showDetail(v, f.id, pane); } },
      icon(ICON[f.status] || ICON.Information, 'st-' + f.status), h('span', {}, h('div', { class: 't' }, f.title), h('div', { class: 'm' }, f.word + (f.severity ? ' · ' + f.severity : '') + ' · ' + f.message))))) :
      [h('li', {}, h('div', { class: 'empty' }, 'No finding matches. ', h('button', { class: 'btn', type: 'button', onclick: () => { present.forEach(x => state.on.add(x)); state.q = ''; search.value = ''; drawChips(); fill(); } }, 'Show all')))]));
  };
  const drawChips = () => chips.replaceChildren(...present.map(st => h('button', { class: 'chip', type: 'button', 'aria-pressed': state.on.has(st) ? 'true' : 'false', onclick: () => { state.on.has(st) ? state.on.delete(st) : state.on.add(st); drawChips(); fill(); } },
    icon(ICON[st], 'st-' + st), wordOf(st) + ' ' + v.findings.filter(f => f.status === st).length)));
  search.addEventListener('input', () => { state.q = search.value; fill(); });
  drawChips(); fill();
  el.append(h('h1', {}, 'Findings'), h('p', { class: 'muted' }, v.findings.length + ' findings from ' + v.title.toLowerCase() + '. Every one carries its sources, evidence and confidence.'),
    h('div', { class: 'split' }, h('div', {}, chips, search, list), pane));
  if (findingId && v.details[findingId]) { showDetail(v, findingId, pane); const b = list.querySelector('[aria-current="true"]'); if (b) b.scrollIntoView({ block: 'nearest' }); }
}
function wordOf(st) { return { Critical: 'Critical', Fail: 'Failing', Warning: 'Warning', Error: 'Check failed', CouldNotCheck: 'Could not check', Information: 'Information', Pass: 'Healthy', Skipped: 'Skipped', NotApplicable: 'Not applicable' }[st] || st; }
function copyButton(text, label) {
  const b = h('button', { class: 'btn copy', type: 'button', 'aria-label': label, title: label }, icon(ICON.copy));
  b.addEventListener('click', async () => { try { await navigator.clipboard.writeText(text); b.replaceChildren(icon(ICON.check)); announce('Copied'); setTimeout(() => b.replaceChildren(icon(ICON.copy)), 1400); } catch (e) { announce('Copy is not available here'); } });
  return b;
}
function showDetail(v, id, pane) {
  const d = v.details[id]; if (!d) return;
  const tone = STATUS_TONE[(v.findings.find(f => f.id === id) || {}).status] || 'Neutral';
  const parts = [
    h('button', { class: 'btn close-sheet', type: 'button', 'aria-label': 'Close details', onclick: () => pane.classList.remove('open') }, icon(ICON.close)),
    h('h2', {}, d.title),
    h('div', { class: 'pills' }, h('span', { class: 'tone tone-' + tone }, d.statusText), d.severity ? h('span', { class: 'tone tone-Neutral' }, d.severity) : null, d.confidence ? h('span', { class: 'tone tone-Info' }, d.confidence) : null),
    h('p', { class: 'msg' }, d.message)];
  if (d.diag) {
    const causes = d.diag.causes.map(c => h('div', { class: 'cause' + (c.isTop ? ' top' : '') },
      h('h4', {}, (c.rank ? c.rank + '. ' : '') + (c.cause || c.heading), c.observed ? h('span', { class: 'tone tone-Info obsbadge' }, 'Observed in this run') : null),
      c.because && !(c.hint && c.hint.replace(/^Hint:\s*/i, '').trim() === c.because.replace(/^[•\s]+/, '').trim()) ? h('div', { class: 'small muted' }, c.because) : null, c.hint ? h('div', { class: 'small muted' }, c.hint) : null,
      c.checks.length ? h('div', { class: 'small' }, h('strong', {}, 'How to confirm (read-only)')) : null,
      c.checks.length ? h('ul', { class: 'checks' }, c.checks.map((k, i) => h('li', { class: 'check' }, k.command ? h('code', {}, k.text) : h('span', {}, k.text), k.command ? copyButton(k.text, 'Copy check ' + (i + 1)) : null))) : null,
      c.fix ? h('div', { class: 'fix' }, h('strong', {}, (c.fixLabel || 'How to fix') + (c.fixOwner && !(c.fixLabel || '').toLowerCase().includes(c.fixOwner.toLowerCase()) ? ' (' + c.fixOwner + ')' : '') + ': '), c.fix) : null));
    parts.push(h('section', {}, h('h3', {}, d.diag.title || 'Probable causes and next steps'), d.diag.summary ? h('p', { class: 'small' }, d.diag.summary) : null, causes,
      d.diag.basis ? h('p', { class: 'small muted' }, d.diag.basis) : null, d.diag.checkNote ? h('p', { class: 'small muted' }, d.diag.checkNote) : null,
      d.diag.sources.length ? h('div', { class: 'sources small' }, h('strong', {}, 'Sources'), h('ul', {}, d.diag.sources.map(x => h('li', {}, x.url ? h('a', { href: x.url, rel: 'noopener noreferrer', target: '_blank' }, x.title || x.url) : x.title)))) : null));
  }
  if (d.remediation) parts.push(h('section', {}, h('h3', {}, 'What to do'), h('p', { class: 'small' }, d.remediation)));
  if (d.evidence.length) parts.push(h('section', {}, h('h3', {}, 'Evidence'), h('ul', { class: 'evidence' }, d.evidence.flatMap(x => String(x).split(/\r?\n/)).filter(Boolean).slice(0, 40).map(x => h('li', {}, x)))));
  if (d.notes) parts.push(h('section', {}, h('h3', {}, 'Notes'), h('p', { class: 'small' }, d.notes)));
  if (d.sources.length) parts.push(h('p', { class: 'small muted' }, 'Read from: ' + d.sources.join(', ')));
  pane.replaceChildren(...parts);
  pane.classList.add('open');
  pane.scrollTop = 0;
}

// ---- theme switch (this page only; nothing is stored) ----------------------------------------------------------------------------------
document.getElementById('theme-btn').addEventListener('click', () => {
  const root = document.documentElement;
  const dark = root.dataset.theme ? root.dataset.theme === 'dark' : window.matchMedia('(prefers-color-scheme: dark)').matches;
  root.dataset.theme = dark ? 'light' : 'dark';
});
window.addEventListener('hashchange', route);
route();
