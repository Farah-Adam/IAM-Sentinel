/* IAM Sentinel dashboard */
'use strict';

const RISK = { critical: '#ef4444', warning: '#f97316', normal: '#3b82f6', resource: '#22c55e' };
const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const SEV_COLOR = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#3b82f6', INFO: '#64748b', NONE: '#16a34a' };
const TIER_NAMES = ['Principals / Trust', 'Users', 'Groups', 'Roles', 'Policies', 'Escalation', 'Resources'];

const S = { r: null, cy: null, hl: false, activePath: null, sev: new Set(SEV_ORDER), remSel: null, dashTimer: null };
const $ = (q, el = document) => el.querySelector(q);
const $$ = (q, el = document) => [...el.querySelectorAll(q)];
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const sevBadge = (s) => `<span class="sev sev-${s}">${s}</span>`;
const short = (a) => (a || '').split('/').pop();

function toast(msg, kind = 'info') {
  const t = $('#toast');
  t.className = `fixed bottom-5 left-1/2 -translate-x-1/2 z-[60] px-4 py-2 rounded-xl text-sm shadow-2xl ${kind === 'error' ? 'bg-rose-600 text-white' : 'bg-ink-700 text-slate-100 border border-ink-600'}`;
  t.textContent = msg;
  clearTimeout(t._h);
  t._h = setTimeout(() => t.classList.add('hidden'), 3500);
}
const loading = (on) => $('#loading').classList.toggle('hidden', !on);

async function copyText(text) {
  try { await navigator.clipboard.writeText(text); toast('Copied to clipboard'); }
  catch { toast('Copy failed - select and copy manually', 'error'); }
}
function download(name, text, mime = 'application/json') {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type: mime }));
  a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

/* ---------------------------------------------------------------- data loading
 * Two modes, same UI:
 *  - server: FastAPI backend (python main.py) - /api/analysis, /api/analyze, /api/report
 *  - static: no backend (GitHub Pages) - samples come pre-computed from ./data/default-scan.json,
 *            uploads and exports run in the browser engine (analyzer.js, a port of the Python engine).
 * URLs are relative so the site also works under a sub-path such as /IAM-Sentinel/. */
const MODE = { kind: null, bundle: null };
async function detectMode() {
  if (MODE.kind) return MODE.kind;
  if (document.querySelector('meta[name="iam-sentinel-mode"]')?.content === 'static') return (MODE.kind = 'static');
  try {
    const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), 2500);
    const res = await fetch('api/health', { signal: ctl.signal, cache: 'no-store' });
    clearTimeout(t);
    MODE.kind = res.ok && (res.headers.get('content-type') || '').includes('json') ? 'server' : 'static';
  } catch { MODE.kind = 'static'; }
  return MODE.kind;
}
async function staticBundle() {
  if (!MODE.bundle) {
    const res = await fetch('data/default-scan.json');
    if (!res.ok) throw new Error(`data/default-scan.json: ${res.status} ${res.statusText}`);
    MODE.bundle = await res.json();
  }
  return MODE.bundle;
}
function showMode() {
  const pill = $('#modePill');
  if (!pill) return;
  pill.textContent = MODE.kind === 'static' ? 'static · in-browser engine' : 'live · API server';
  pill.title = MODE.kind === 'static'
    ? 'No backend: samples are pre-computed, uploads and exports are analysed locally in your browser (nothing is uploaded anywhere).'
    : 'Connected to the IAM Sentinel FastAPI backend.';
  pill.classList.remove('hidden');
}
async function loadSample(id) {
  loading(true);
  try {
    let result;
    if ((await detectMode()) === 'server') {
      const res = await fetch(`api/analysis?sample=${encodeURIComponent(id)}`);
      if (!res.ok) throw new Error((await res.json()).detail || res.statusText);
      result = await res.json();
    } else {
      const b = await staticBundle();
      result = b.samples[id] || b.samples[b.default_sample];
      if (!result) throw new Error(`sample '${id}' not in data/default-scan.json`);
      result = JSON.parse(JSON.stringify(result)); // render() annotates the object; keep the cached copy pristine
    }
    showMode();
    render(result);
    $$('.sample-btn').forEach((b) => b.classList.toggle('active-sample', b.dataset.sample === id));
  } catch (e) { toast(`Load failed: ${e.message}`, 'error'); }
  finally { loading(false); }
}
async function analyseLocally(file) {
  if (!window.IAMSentinel) throw new Error('in-browser engine (analyzer.js) failed to load');
  let data;
  try { data = JSON.parse((await file.text()).replace(/^﻿/, '')); }
  catch (e) { throw new Error(`Not valid JSON: ${e.message}`); }
  await new Promise((r) => setTimeout(r, 30)); // let the spinner paint before the synchronous analysis
  return window.IAMSentinel.analyze(data, { source: file.name || 'upload.json' });
}
async function uploadFile(file) {
  if (!file) return;
  loading(true);
  try {
    let body;
    if ((await detectMode()) === 'server') {
      const fd = new FormData(); fd.append('file', file);
      const res = await fetch('api/analyze', { method: 'POST', body: fd });
      body = await res.json();
      if (!res.ok) throw new Error(body.detail || res.statusText);
    } else {
      body = await analyseLocally(file);
    }
    render(body);
    $$('.sample-btn').forEach((b) => b.classList.remove('active-sample'));
    toast(`Analysed ${file.name}: ${body.summary.findings_total} findings${MODE.kind === 'static' ? ' (in your browser)' : ''}`);
  } catch (e) { toast(`Upload failed: ${e.message}`, 'error'); }
  finally { loading(false); }
}
function exportReport(fmt) {
  if (!S.r) return;
  if (MODE.kind === 'server' && S.r.meta.engine !== 'browser') {
    window.location = `api/report/${S.r.meta.analysis_id}.${fmt}`;
    return;
  }
  const [fn, mime] = window.IAMSentinel.EXPORTERS[fmt];
  download(`iam-sentinel-${S.r.meta.account_id}.${fmt === 'sarif' ? 'sarif.json' : fmt}`, fn(S.r), mime);
}

/* ---------------------------------------------------------------- render root */
function render(r) {
  S.r = r; S.activePath = null; S.remSel = r.remediations[0]?.id || null;
  r.findingById = Object.fromEntries(r.findings.map((f) => [f.id, f]));
  r.identityByArn = Object.fromEntries(r.identities.map((i) => [i.arn, i]));
  r.remById = Object.fromEntries(r.remediations.map((x) => [x.id, x]));
  $('#sourcePill').textContent = `${r.meta.source} · acct ${r.meta.account_id}`;
  $('#sourcePill').classList.remove('hidden');
  renderPosture(); renderGraph(); renderPaths(); renderFindingsFilters(); renderFindings(); renderIdentities(); renderRemediations();
  $('#findCount').textContent = r.findings.length;
  $('#remCount').textContent = r.remediations.length;
  $('#inspector').innerHTML = `<div class="text-slate-400 text-sm">Click any node to inspect effective permissions, blast radius and trust relationships.
    <div class="mt-3 text-xs">Tip: toggle <b class="text-rose-300">Highlight Attack Paths</b> or click a path below.</div></div>`;
}

function renderPosture() {
  const s = S.r.summary;
  const gc = { A: '#22c55e', B: '#84cc16', C: '#eab308', D: '#f97316', F: '#ef4444' }[s.grade];
  const total = Math.max(1, s.findings_total);
  const bar = SEV_ORDER.map((k) => `<div title="${k}: ${s.findings_by_severity[k]}" style="width:${(s.findings_by_severity[k] / total) * 100}%;background:${SEV_COLOR[k]}"></div>`).join('');
  const circ = 2 * Math.PI * 34;
  $('#posture').innerHTML = `
    <div class="card col-span-2 md:col-span-1 flex items-center gap-4 relative overflow-hidden">
      <svg width="84" height="84" viewBox="0 0 84 84" class="shrink-0 -rotate-90">
        <circle cx="42" cy="42" r="34" stroke-width="8" fill="none" class="gauge-track"/>
        <circle cx="42" cy="42" r="34" stroke-width="8" fill="none" stroke="${gc}" stroke-linecap="round"
          stroke-dasharray="${(s.score / 100) * circ} ${circ}"/>
      </svg>
      <div class="absolute left-4 w-[84px] h-[84px] grid place-items-center"><span class="text-4xl font-extrabold" style="color:${gc}">${s.grade}</span></div>
      <div><div class="text-xs text-slate-400 uppercase tracking-wide">Security grade</div>
        <div class="text-2xl font-bold">${s.score}<span class="text-sm text-slate-500">/100</span></div>
        <div class="text-[11px] text-slate-400">${s.admin_identities.length} admin-equivalent</div></div>
    </div>
    ${kpi('Total identities', s.total_identities, `${s.users} users · ${s.groups} groups · ${s.roles} roles`)}
    ${kpi('Critical attack paths', s.critical_attack_paths, `${s.attack_paths} paths · ${s.multi_hop_paths} multi-hop`, s.critical_attack_paths ? '#f87171' : '#4ade80')}
    <div class="card"><div class="text-xs text-slate-400 uppercase tracking-wide">Excess permission ratio</div>
      <div class="text-3xl font-bold mt-1">${Math.round(s.excess_permission_ratio * 100)}<span class="text-base text-slate-500">%</span></div>
      <div class="h-1.5 rounded bg-ink-600 mt-2 overflow-hidden"><div class="h-full bg-gradient-to-r from-amber-400 to-rose-500" style="width:${s.excess_permission_ratio * 100}%"></div></div>
      <div class="text-[11px] text-slate-400 mt-1.5">${esc(s.excess_detail)}</div></div>
    <div class="card"><div class="text-xs text-slate-400 uppercase tracking-wide">Findings</div>
      <div class="text-3xl font-bold mt-1">${s.findings_total}</div>
      <div class="flex h-1.5 rounded overflow-hidden mt-2 bg-ink-600">${bar}</div>
      <div class="flex flex-wrap gap-x-2 text-[11px] mt-1.5">${SEV_ORDER.map((k) => `<span style="color:${SEV_COLOR[k]}">${k[0]}${k.slice(1).toLowerCase()} ${s.findings_by_severity[k]}</span>`).join('')}</div></div>
    ${kpi('Max blast radius', s.max_blast_radius, `avg ${s.avg_blast_radius} · ${s.positive_controls} positive control(s)`, s.max_blast_radius >= 80 ? '#f87171' : '#fbbf24')}
  `;
  const t = s.telemetry, note = $('#telemetryNote');
  const warn = [];
  if (!t.credential_report && t.users_with_activity < t.users_total) warn.push(`User activity telemetry absent for ${t.users_total - t.users_with_activity}/${t.users_total} users (no credential report / PasswordLastUsed) - dormant-user checks limited. Run <code class="mono">python cli.py collect</code> to include it.`);
  (S.r.meta.warnings || []).forEach((w) => warn.push(esc(w)));
  note.innerHTML = warn.map((w) => `⚠ ${w}`).join('<br>');
  note.classList.toggle('hidden', !warn.length);
}
const kpi = (label, val, sub, color = '#e2e8f0') => `<div class="card"><div class="text-xs text-slate-400 uppercase tracking-wide">${label}</div>
  <div class="text-3xl font-bold mt-1" style="color:${color}">${val}</div><div class="text-[11px] text-slate-400 mt-1">${sub}</div></div>`;

/* ---------------------------------------------------------------- graph */
function nodeColor(n) {
  const t = n.data('type'), r = n.data('risk');
  if (t === 'resource') return n.data('risk') === 'warning' ? RISK.warning : RISK.resource;
  if (t === 'policy') return r === 'critical' ? '#b91c1c' : r === 'warning' ? '#c2410c' : '#475569';
  if (t === 'service' || t === 'account' || t === 'principal') return '#64748b';
  return RISK[r] || RISK.normal;
}

function tieredPositions(cy) {
  const cols = {};
  cy.nodes().forEach((n) => { const t = n.data('tier') ?? 3; (cols[t] = cols[t] || []).push(n); });
  const pos = {};
  const order = { critical: 0, warning: 1, normal: 2, resource: 3 };
  Object.entries(cols).forEach(([tier, nodes]) => {
    nodes.sort((a, b) => (order[a.data('risk')] - order[b.data('risk')]) || a.data('label').localeCompare(b.data('label')));
    const gap = nodes.length > 14 ? 56 : 80;
    const x = Number(tier) === 7 ? 6.9 * 210 : Number(tier) * 210;
    nodes.forEach((n, i) => { pos[n.id()] = { x, y: (i - (nodes.length - 1) / 2) * gap }; });
  });
  return pos;
}

function renderGraph() {
  if (S.cy) S.cy.destroy();
  clearInterval(S.dashTimer);
  S.hl = false; $('#hlToggle').classList.remove('on');
  const els = [...S.r.graph.nodes, ...S.r.graph.edges];
  S.cy = cytoscape({
    container: $('#cy'), elements: els, wheelSensitivity: 0.25, minZoom: 0.15, maxZoom: 2.5,
    style: [
      { selector: 'node', style: { 'background-color': nodeColor, label: 'data(label)', color: '#cbd5e1', 'font-size': 12, 'font-family': 'Inter', 'min-zoomed-font-size': 6,
        'text-valign': 'bottom', 'text-margin-y': 5, 'text-wrap': 'ellipsis', 'text-max-width': 150, width: 30, height: 30,
        'border-width': 2, 'border-color': '#0b1020', 'text-outline-color': '#0b1020', 'text-outline-width': 2.5, 'transition-property': 'opacity', 'transition-duration': '200ms' } },
      { selector: 'node[type="user"]', style: { shape: 'ellipse', width: 34, height: 34 } },
      { selector: 'node[type="group"]', style: { shape: 'round-hexagon', width: 36, height: 34 } },
      { selector: 'node[type="role"]', style: { shape: 'round-rectangle', width: 40, height: 30 } },
      { selector: 'node[type="policy"]', style: { shape: 'round-tag', width: 24, height: 24, 'font-size': 9, color: '#94a3b8' } },
      { selector: 'node[type="resource"]', style: { shape: 'barrel', width: 30, height: 26, 'font-size': 9 } },
      { selector: 'node[?sensitive]', style: { 'border-color': '#f97316', 'border-width': 3 } },
      { selector: 'node[type="crown"]', style: { shape: 'star', width: 62, height: 62, 'font-weight': 800, color: '#fecaca', 'font-size': 11, 'background-color': '#ef4444', 'border-color': '#fecaca', 'border-width': 2 } },
      { selector: 'node[type="service"]', style: { shape: 'diamond' } },
      { selector: 'node[type="external"], node[type="account"], node[type="principal"]', style: { shape: 'octagon', width: 34, height: 34 } },
      { selector: 'node[type="anyone"]', style: { shape: 'vee', width: 42, height: 42, color: '#fecaca', 'font-weight': 700 } },
      { selector: 'node[type="federated"]', style: { shape: 'round-diamond', width: 36, height: 36 } },
      { selector: 'node[type="escalation"]', style: { shape: 'round-triangle', width: 32, height: 30, color: '#fca5a5', 'font-size': 9 } },
      { selector: 'node[?latent]', style: { 'border-style': 'dashed', 'border-color': '#fca5a5', 'border-width': 2, 'background-opacity': 0.55 } },
      { selector: 'edge', style: { width: 1.4, 'curve-style': 'bezier', 'line-color': '#334155', 'target-arrow-color': '#334155', 'target-arrow-shape': 'triangle',
        'arrow-scale': 0.8, 'font-size': 8, color: '#94a3b8', 'text-rotation': 'autorotate', 'text-background-color': '#0b1020', 'text-background-opacity': 0.85, 'text-background-padding': 2 } },
      { selector: 'edge[type="member_of"]', style: { 'line-style': 'dotted', 'line-color': '#60a5fa', 'target-arrow-color': '#60a5fa' } },
      { selector: 'edge[type="grants"]', style: { 'line-color': '#166534', 'target-arrow-color': '#16a34a' } },
      { selector: 'edge[type="trusts"]', style: { 'line-style': 'dashed', 'line-color': '#f97316', 'target-arrow-color': '#f97316' } },
      { selector: 'edge[type="can_assume"]', style: { 'line-color': '#a855f7', 'target-arrow-color': '#a855f7', width: 2 } },
      { selector: 'edge[type="escalates"]', style: { 'line-style': 'dashed', 'line-color': '#ef4444', 'target-arrow-color': '#ef4444', width: 2 } },
      { selector: 'edge[?blocked]', style: { 'line-color': '#475569', 'target-arrow-shape': 'tee', 'target-arrow-color': '#94a3b8', 'line-style': 'dashed', label: 'DENIED', color: '#94a3b8' } },
      { selector: 'edge[?inert]', style: { opacity: 0.45 } },
      { selector: '.labels', style: { label: 'data(label)' } },
      { selector: '.dim', style: { opacity: 0.09 } },
      { selector: 'node.hl', style: { 'border-color': '#facc15', 'border-width': 4, opacity: 1, 'z-index': 99 } },
      { selector: 'edge.hl', style: { width: 3.5, 'line-color': '#facc15', 'target-arrow-color': '#facc15', 'line-style': 'dashed', 'line-dash-pattern': [9, 5],
        label: 'data(label)', color: '#fde68a', opacity: 1, 'z-index': 99 } },
      { selector: 'node:selected', style: { 'border-color': '#fff', 'border-width': 4 } },
    ],
    layout: { name: 'preset' },
  });
  const cy = S.cy;
  cy.layout({ name: 'preset', positions: tieredPositions(cy), fit: true, padding: 40 }).run();
  cy.on('tap', 'node', (e) => inspect(e.target));
  cy.on('tap', (e) => { if (e.target === cy) { clearHighlight(); } });
  cy.on('mouseover', 'edge', (e) => e.target.addClass('labels'));
  cy.on('mouseout', 'edge', (e) => { if (!$('#edgeLabels').checked) e.target.removeClass('labels'); });
  let offset = 0;
  S.dashTimer = setInterval(() => { offset = (offset + 1) % 28; cy.edges('.hl').style('line-dash-offset', -offset); }, 45);
  $('#tierLabels').textContent = '← ' + TIER_NAMES.join('  ·  ') + ' →';
}

function highlightPaths(ids) {
  const cy = S.cy;
  cy.elements().removeClass('hl').addClass('dim');
  const set = new Set(ids);
  cy.elements().filter((el) => (el.data('paths') || []).some((p) => set.has(p))).removeClass('dim').addClass('hl');
}
function clearHighlight() {
  S.cy.elements().removeClass('hl dim');
  S.hl = false; S.activePath = null;
  $('#hlToggle').classList.remove('on');
  $$('.path-card').forEach((c) => c.classList.remove('on'));
}
function toggleHighlight() {
  if (S.hl) { clearHighlight(); return; }
  const crit = S.r.attack_paths.filter((p) => ['CRITICAL', 'HIGH'].includes(p.severity)).map((p) => p.id);
  if (!crit.length) { toast('No high/critical attack paths 🎉'); return; }
  S.hl = true; $('#hlToggle').classList.add('on');
  highlightPaths(crit);
  S.cy.animate({ fit: { eles: S.cy.elements('.hl'), padding: 60 }, duration: 500 });
}
function focusPath(id) {
  const p = S.r.attack_paths.find((x) => x.id === id);
  if (!p) return;
  switchTab('graph');
  S.activePath = id; S.hl = true; $('#hlToggle').classList.add('on');
  highlightPaths([id]);
  $$('.path-card').forEach((c) => c.classList.toggle('on', c.dataset.path === id));
  S.cy.animate({ fit: { eles: S.cy.elements('.hl'), padding: 80 }, duration: 500 });
  const src = S.cy.getElementById(p.source);
  if (src.length) inspect(src, true);
}

function renderPaths() {
  const ps = S.r.attack_paths;
  $('#pathCount').textContent = `${ps.length} found`;
  $('#pathList').innerHTML = ps.length ? ps.map((p) => `
    <div class="path-card" data-path="${p.id}">
      <div class="flex items-center gap-2 mb-1">${sevBadge(p.severity)}<span class="text-xs text-slate-400 mono">${p.id}</span>
        ${p.multi_hop ? '<span class="chip">multi-hop</span>' : ''}${p.exploitability === 'latent' ? '<span class="chip text-rose-200">latent</span>' : ''}
        <span class="ml-auto text-[11px] text-slate-500">${p.hops} hops</span></div>
      <div class="text-[13px] font-medium">${esc(p.source_label)} <span class="arrow">⟶</span> ${esc(p.target_label)}</div>
      <div class="mt-1 leading-6">${p.steps.map((s, i) => `${i ? `<span class="arrow">${esc(s.via || '')} →</span>` : ''}<span class="step">${esc(s.label)}</span>`).join('')}</div>
    </div>`).join('') : '<div class="text-sm text-slate-400">No attack paths discovered.</div>';
  $$('.path-card').forEach((c) => c.addEventListener('click', () => focusPath(c.dataset.path)));
}

/* ---------------------------------------------------------------- inspector */
function gauge(score, level) {
  const c = SEV_COLOR[level] || '#3b82f6', circ = Math.PI * 46;
  return `<svg viewBox="0 0 110 62" class="w-36"><path d="M8 56 A46 46 0 0 1 102 56" fill="none" stroke="#1a2440" stroke-width="10" stroke-linecap="round"/>
    <path d="M8 56 A46 46 0 0 1 102 56" fill="none" stroke="${c}" stroke-width="10" stroke-linecap="round" stroke-dasharray="${(score / 100) * circ} ${circ}"/>
    <text x="55" y="50" text-anchor="middle" font-size="22" font-weight="800" fill="${c}">${score}</text></svg>`;
}

function inspect(node, quiet) {
  const d = node.data(); const r = S.r;
  if (!quiet) { S.cy.elements().unselect(); node.select(); }
  let h = '';
  const ident = r.identityByArn[d.id];
  if (ident) {
    const b = ident.blast;
    h += `<div class="flex items-start gap-3"><div class="min-w-0 flex-1">
        <div class="flex items-center gap-2 flex-wrap"><span class="chip uppercase">${ident.kind}</span>${ident.admin ? '<span class="sev sev-CRITICAL">ADMIN</span>' : ''}
          ${b.admin_via_path ? '<span class="sev sev-CRITICAL">ADMIN VIA PATH</span>' : ''}</div>
        <div class="text-lg font-bold mt-1 break-all">${esc(ident.name)}</div>
        <div class="text-[11px] mono text-slate-400 break-all">${esc(ident.arn)}</div></div>
        <div class="text-center">${gauge(b.score, b.level)}<div class="text-[10px] uppercase tracking-wide text-slate-400 -mt-1">Blast radius · ${b.level}</div></div></div>
      <div class="mt-3 space-y-1">${b.factors.map((f) => `<div class="flex items-center gap-2 text-xs"><div class="w-28 shrink-0 text-slate-400 truncate" title="${esc(f.factor)}">${esc(f.factor)}</div>
        <div class="flex-1 h-1.5 bg-ink-600 rounded overflow-hidden"><div class="h-full bg-gradient-to-r from-amber-400 to-rose-500" style="width:${f.points}%"></div></div>
        <div class="w-8 text-right mono">+${f.points}</div></div><div class="text-[10px] text-slate-500 ml-[7.5rem] -mt-0.5 truncate" title="${esc(f.detail)}">${esc(f.detail)}</div>`).join('')}</div>
      <div class="kv mt-3">
        <div>Created</div><div>${ident.created ? ident.created.slice(0, 19).replace('T', ' ') : '—'}</div>
        <div>Last used</div><div>${ident.last_used ? `${ident.last_used.slice(0, 10)} (${ident.last_used_days} days ago, ${esc(ident.last_used_region || '')})` : ident.telemetry.length ? 'never / not recorded' : '<span class="text-amber-300">telemetry absent</span>'}</div>
        ${ident.groups.length ? `<div>Groups</div><div>${ident.groups.map(esc).join(', ')}</div>` : ''}
        ${ident.members.length ? `<div>Members</div><div>${ident.members.map(esc).join(', ')}</div>` : ''}
        ${b.reachable_roles.length ? `<div>Can reach roles</div><div>${b.reachable_roles.map(esc).join(', ')}</div>` : ''}
        ${b.sensitive_services.length ? `<div>Sensitive services</div><div>${b.sensitive_services.map((s) => `<span class="chip mr-1 mb-1">${esc(s)}</span>`).join('')}</div>` : ''}
      </div>`;
    if (Object.keys(b.capabilities).length) {
      h += `<h4 class="ins-h">Effective sensitive capabilities <span class="text-slate-500 font-normal">(deny-aware)</span></h4>
        <div class="space-y-1">${Object.entries(b.capabilities).map(([k, v]) => `<details class="text-xs"><summary class="cursor-pointer"><b>${esc(k)}</b> <span class="text-slate-500">${v.length}</span></summary>
          <div class="mono text-[11px] text-slate-300 pl-3 py-1">${v.map(esc).join(', ')}</div></details>`).join('')}</div>`;
    }
    if (ident.trust.length) {
      h += `<h4 class="ins-h">Trust relationships (who can assume)</h4>${ident.trust.map((t) => `<div class="text-xs py-1 border-b border-ink-700">
        <span class="chip ${t.external || t.kind === 'anyone' ? 'text-orange-300' : ''}">${t.kind}</span> <span class="mono break-all">${esc(t.principal)}</span>
        ${t.conditions ? `<div class="mono text-[10px] text-emerald-300 mt-0.5 break-all">Condition ${esc(JSON.stringify(t.conditions))}</div>` : '<div class="text-[10px] text-amber-300 mt-0.5">no conditions</div>'}</div>`).join('')}`;
    }
    h += `<h4 class="ins-h">Effective statements (${ident.statements.length})</h4><div class="space-y-1.5 max-h-64 overflow-auto pr-1">${ident.statements.map((s) => `
      <div class="text-[11px] bg-ink-850 border border-ink-700 rounded-lg p-2"><div class="flex gap-1.5 items-center flex-wrap">
        <span class="sev ${s.effect === 'Deny' ? 'sev-INFO' : 'sev-LOW'}">${s.effect}</span><b>${esc(s.policy)}</b><span class="text-slate-500">/ ${esc(s.sid)}</span>
        ${s.via !== 'direct' ? `<span class="chip">via ${esc(s.via)}</span>` : ''}</div>
        <div class="mono mt-1 text-slate-300 break-all">${esc(s.actions.slice(0, 8).join(', '))}${s.action_count > 8 ? ` <span class="text-slate-500">+${s.action_count - 8} more</span>` : ''}</div>
        <div class="mono text-slate-500 break-all">on ${esc(s.resources.slice(0, 3).join(', '))}</div>
        ${s.condition ? `<div class="mono text-emerald-300 break-all">if ${esc(JSON.stringify(s.condition))}</div>` : ''}</div>`).join('')}</div>`;
    h += findingLinks(ident.findings);
  } else if (d.type === 'policy') {
    const p = r.policies[d.id] || {};
    h += `<span class="chip uppercase">${esc(p.kind || 'policy')}</span><div class="text-lg font-bold mt-1 break-all">${esc(d.label)}</div>
      <div class="text-[11px] mono text-slate-400 break-all">${esc(p.arn || d.id)}</div>
      <div class="kv mt-3"><div>Attached to</div><div>${(p.attached_to || []).map(esc).join(', ') || '—'}</div>
      <div>Effective for</div><div>${(p.effective_for || []).map(esc).join(', ') || '—'}</div>
      ${p.synthesized ? '<div>Note</div><div class="text-amber-300">document reconstructed from built-in knowledge base</div>' : ''}</div>
      <h4 class="ins-h">Policy document</h4><pre class="code max-h-72">${esc(JSON.stringify(p.document, null, 2).slice(0, 6000))}</pre>`;
    h += findingLinks(r.findings.filter((f) => f.policy_key === d.id).map((f) => f.id));
  } else if (d.type === 'escalation') {
    const f = r.findings.find((x) => x.rule_id === d.method && node.incomers('node').some((n) => x.identity_arns.includes(n.id())));
    h += `<span class="chip uppercase text-rose-300">privilege escalation</span><div class="text-lg font-bold mt-1">${esc(d.label)}</div>
      <div class="flex gap-2 mt-2">${sevBadge(d.severity)}<span class="chip">${esc(d.exploitability)}</span><span class="chip mono">${esc(d.method)}</span></div>
      ${f ? `<p class="text-sm text-slate-300 mt-3">${esc(f.attack_scenario)}</p>${f.notes.map((n) => `<p class="text-xs text-slate-400 mt-1">• ${esc(n)}</p>`).join('')}` : ''}
      ${f ? findingLinks([f.id]) : ''}`;
  } else {
    const inc = node.incomers('edge').map((e) => `<div class="text-xs py-1 border-b border-ink-700"><b>${esc(e.source().data('label'))}</b> <span class="text-slate-500">${esc(e.data('label') || e.data('type'))}</span>${e.data('blocked') ? ' <span class="chip">DENIED</span>' : ''}</div>`).join('');
    const out = node.outgoers('edge').map((e) => `<div class="text-xs py-1 border-b border-ink-700"><span class="text-slate-500">${esc(e.data('label') || e.data('type'))}</span> → <b>${esc(e.target().data('label'))}</b></div>`).join('');
    h += `<span class="chip uppercase">${esc(d.type)}</span><div class="text-lg font-bold mt-1 break-all">${esc(d.label)}</div>
      ${d.arn ? `<div class="text-[11px] mono text-slate-400 break-all">${esc(d.arn)}</div>` : ''}
      ${d.type === 'crown' ? '<p class="text-sm text-rose-200 mt-2">Administrator-equivalent control of the account. Every path that ends here is an account-takeover path.</p>' : ''}
      ${d.cats && d.cats.length ? `<div class="mt-2 flex flex-wrap gap-1">${d.cats.map((c) => `<span class="chip text-orange-200">${esc(c)}</span>`).join('')}</div>` : ''}
      ${d.resources ? `<div class="mono text-[11px] text-slate-400 mt-2 break-all">${esc(d.resources.join(', '))}</div>` : ''}
      ${inc ? `<h4 class="ins-h">Inbound</h4>${inc}` : ''}${out ? `<h4 class="ins-h">Outbound</h4>${out}` : ''}`;
  }
  $('#inspector').innerHTML = h;
  $$('#inspector [data-finding]').forEach((el) => el.addEventListener('click', () => openFinding(el.dataset.finding)));
}
function findingLinks(ids) {
  if (!ids || !ids.length) return '<div class="text-xs text-emerald-300 mt-3">No findings for this element.</div>';
  return `<h4 class="ins-h">Findings (${ids.length})</h4><div class="space-y-1">${ids.map((id) => {
    const f = S.r.findingById[id];
    return `<div data-finding="${id}" class="text-xs flex gap-2 items-start cursor-pointer hover:bg-ink-700 rounded p-1">${sevBadge(f.severity)}<span>${esc(f.title)}</span></div>`;
  }).join('')}</div>`;
}

/* ---------------------------------------------------------------- findings table */
function renderFindingsFilters() {
  $('#sevFilters').innerHTML = SEV_ORDER.map((s) => `<span data-sev="${s}" class="sevf ${S.sev.has(s) ? 'on' : ''}">${sevBadge(s)} <span class="text-xs text-slate-400">${S.r.summary.findings_by_severity[s]}</span></span>`).join('');
  $$('#sevFilters [data-sev]').forEach((el) => el.addEventListener('click', () => {
    const s = el.dataset.sev; S.sev.has(s) ? S.sev.delete(s) : S.sev.add(s); el.classList.toggle('on'); renderFindings();
  }));
  const cats = [...new Set(S.r.findings.map((f) => f.category))].sort();
  $('#catFilter').innerHTML = '<option value="">All categories</option>' + cats.map((c) => `<option>${esc(c)}</option>`).join('');
}
function renderFindings() {
  const q = $('#searchBox').value.trim().toLowerCase(), cat = $('#catFilter').value, exp = $('#expFilter').value;
  const rows = S.r.findings.filter((f) => S.sev.has(f.severity) && (!cat || f.category === cat) && (!exp || f.exploitability === exp) &&
    (!q || JSON.stringify([f.id, f.rule_id, f.title, f.identity_names, f.policy_name, f.sid, f.offending_actions, f.resources]).toLowerCase().includes(q)));
  $('#findingsTable tbody').innerHTML = rows.map((f) => `<tr class="row" data-finding="${f.id}">
    <td class="td mono text-xs text-slate-400">${f.id}</td><td class="td">${sevBadge(f.severity)}</td>
    <td class="td mono text-xs">${f.rule_id}</td>
    <td class="td"><div class="font-medium">${esc(f.title)}</div><div class="text-[11px] text-slate-500">${esc(f.category)} · ${f.exploitability}${f.remediation_id ? ` · <span class="text-emerald-400">fix ${f.remediation_id}</span>` : ''}</div></td>
    <td class="td text-xs">${esc(f.identity_names.slice(0, 3).join(', '))}${f.identity_names.length > 3 ? '…' : ''}</td>
    <td class="td text-xs">${esc(f.policy_name || '—')}<div class="text-slate-500">${esc(f.sid || (f.statement_index !== null ? `Statement[${f.statement_index}]` : ''))}</div></td>
    <td class="td mono text-[11px] text-rose-200 max-w-[220px] break-all">${esc(f.offending_actions.slice(0, 4).join(', '))}${f.offending_actions.length > 4 ? '…' : ''}</td>
    <td class="td mono text-[11px] text-slate-400 max-w-[200px] break-all">${esc(f.resources.slice(0, 2).join(', '))}</td></tr>`).join('') ||
    '<tr><td colspan="8" class="td text-center text-slate-400 py-8">No findings match the filters.</td></tr>';
  $$('#findingsTable tr.row').forEach((tr) => tr.addEventListener('click', () => openFinding(tr.dataset.finding)));
}

/* ---------------------------------------------------------------- drawer */
function openFinding(id) {
  const f = S.r.findingById[id]; if (!f) return;
  const rem = f.remediation_id ? S.r.remById[f.remediation_id] : null;
  const ev = [
    ['Identity', f.identity_names.map((n, i) => `<div><b>${esc(n)}</b> <span class="mono text-[11px] text-slate-400 break-all">${esc(f.identity_arns[i] || '')}</span></div>`).join('') || '—'],
    f.policy_name && ['Policy', `<b>${esc(f.policy_name)}</b> <span class="chip">${esc(f.policy_kind)}</span> <span class="mono text-[11px] text-slate-400 break-all">${esc(f.policy_arn || '')}</span>`],
    f.statement_index !== null && ['Statement Sid', `<span class="mono">${esc(f.sid || '(no Sid)')}</span> <span class="text-slate-500 text-xs">index ${f.statement_index}</span>`],
    f.effect && ['Effect', `<span class="mono">${esc(f.effect)}</span>`],
    f.actions.length && ['Action', `<div class="mono text-xs break-all">${f.actions.slice(0, 60).map((a) => f.offending_actions.includes(a) ? `<mark class="bg-rose-500/25 text-rose-200 rounded px-0.5">${esc(a)}</mark>` : esc(a)).join(', ')}${f.actions.length > 60 ? ` … +${f.actions.length - 60}` : ''}</div>`],
    f.offending_actions.length && ['Offending', `<div class="mono text-xs text-rose-200 break-all">${esc(f.offending_actions.join(', '))}</div>`],
    f.resources.length && ['Resource', `<div class="mono text-xs break-all">${esc(f.resources.join(', '))}</div>`],
    ['Condition', f.condition ? `<pre class="code !p-2">${esc(JSON.stringify(f.condition, null, 2))}</pre>` : '<span class="text-amber-300 text-xs">none</span>'],
  ].filter(Boolean);
  $('#drawerBody').innerHTML = `
    <div class="flex items-start gap-3"><div class="flex-1"><div class="flex items-center gap-2 flex-wrap">${sevBadge(f.severity)}<span class="chip mono">${f.rule_id}</span>
      <span class="chip">${esc(f.category)}</span><span class="chip">${esc(f.exploitability)}</span>${f.mitre.map((m) => `<span class="chip text-violet-300" title="${esc(S.r.mitre[m] || '')}">ATT&CK ${m}</span>`).join('')}</div>
      <h2 class="text-xl font-bold mt-2">${esc(f.title)}</h2><div class="text-xs text-slate-500 mono">${f.id}</div></div>
      <button id="drawerClose" class="btn">✕ Close</button></div>
    <h4 class="ins-h">Policy-level evidence</h4><div class="kv !grid-cols-[120px_1fr] bg-ink-900 border border-ink-600 rounded-xl p-3">${ev.map(([k, v]) => `<div>${k}</div><div class="min-w-0">${v}</div>`).join('')}</div>
    <div class="grid md:grid-cols-2 gap-3 mt-4">
      <div class="card !bg-ink-900"><h4 class="font-semibold text-sm mb-1">Risk</h4><p class="text-sm text-slate-300">${esc(f.description)}</p></div>
      <div class="card !bg-ink-900 border-rose-900/60"><h4 class="font-semibold text-sm mb-1 text-rose-300">Attack path</h4><p class="text-sm text-slate-300">${esc(f.attack_scenario)}</p></div>
    </div>
    <div class="card !bg-ink-900 mt-3 border-emerald-900/60"><h4 class="font-semibold text-sm mb-1 text-emerald-300">Recommendation</h4><p class="text-sm text-slate-300">${esc(f.recommendation)}</p>
      ${f.notes.map((n) => `<p class="text-xs text-slate-400 mt-1">• ${esc(n)}</p>`).join('')}</div>
    ${rem ? `<h4 class="ins-h mt-5">Least-privilege remediation · ${rem.id}</h4>${remediationBlock(rem)}` : ''}`;
  bindRemediationBlock($('#drawerBody'), rem);
  $('#drawerClose').onclick = closeDrawer;
  $('#drawer').classList.remove('translate-x-full'); $('#drawerBack').classList.remove('hidden');
}
function closeDrawer() { $('#drawer').classList.add('translate-x-full'); $('#drawerBack').classList.add('hidden'); }

/* ---------------------------------------------------------------- diff + remediation */
function diffTable(rows, collapse = true) {
  const ctx = 3, keep = new Set();
  rows.forEach((r, i) => { if (r.t !== 'eq') for (let k = i - ctx; k <= i + ctx; k++) keep.add(k); });
  let out = '', hidden = 0;
  const flush = () => { if (hidden) { out += `<tr class="gap"><td colspan="4">⋯ ${hidden} unchanged line(s) ⋯</td></tr>`; hidden = 0; } };
  rows.forEach((r, i) => {
    if (collapse && r.t === 'eq' && !keep.has(i)) { hidden++; return; }
    flush();
    out += `<tr class="${r.t}"><td class="n">${r.ln ?? ''}</td><td class="l">${esc(r.l ?? '')}</td><td class="n">${r.rn ?? ''}</td><td class="r">${esc(r.r ?? '')}</td></tr>`;
  });
  flush();
  return `<div class="diff"><table><thead><tr><td class="n"></td><td>Original (risky)</td><td class="n"></td><td>Least-privilege (proposed)</td></tr></thead><tbody>${out}</tbody></table></div>`;
}
function remediationBlock(rem) {
  const v = rem.verification;
  return `<div class="flex flex-wrap items-center gap-2 mb-2 text-sm">
      <span class="text-slate-400">Residual risk (engine re-scan of proposed policy):</span>${sevBadge(v.before)}<span class="arrow">→</span>${sevBadge(v.after)}
      ${v.improved ? '<span class="text-emerald-400 text-xs">✓ verified improvement</span>' : ''}
      <span class="ml-auto text-xs text-slate-500">+${rem.diff.added} / −${rem.diff.removed} lines</span></div>
    ${v.residual.length ? `<div class="text-xs text-amber-200 mb-2">Residual: ${v.residual.map(esc).join('; ')}</div>` : ''}
    <ul class="text-sm text-slate-300 list-disc pl-5 space-y-0.5 mb-3">${rem.changes.map((c) => `<li>${esc(c)}</li>`).join('')}</ul>
    ${rem.placeholders.length ? `<div class="text-xs mb-3">Fill in before applying: ${rem.placeholders.map((p) => `<span class="chip mono text-amber-200">${esc(p)}</span>`).join(' ')}</div>` : ''}
    <div class="flex items-center gap-2 mb-2"><label class="text-xs text-slate-400 flex items-center gap-1.5"><input type="checkbox" class="collapse-toggle accent-sky-500" checked> collapse unchanged lines</label>
      <button class="btn ml-auto copy-json">Copy policy JSON</button><button class="btn dl-json">Download ${esc(rem.file_name.split('/').pop())}</button></div>
    <div class="diff-wrap">${diffTable(rem.diff.rows, true)}</div>
    <h4 class="ins-h">Apply with AWS CLI</h4><div class="relative"><pre class="code">${esc(rem.cli.join('\n'))}</pre>
    <button class="btn absolute top-2 right-2 !py-1 copy-cli">Copy</button></div>`;
}
function bindRemediationBlock(root, rem) {
  if (!rem) return;
  $('.collapse-toggle', root)?.addEventListener('change', (e) => { $('.diff-wrap', root).innerHTML = diffTable(rem.diff.rows, e.target.checked); });
  $('.copy-json', root)?.addEventListener('click', () => copyText(JSON.stringify(rem.proposed, null, 2)));
  $('.dl-json', root)?.addEventListener('click', () => download(rem.file_name.split('/').pop(), JSON.stringify(rem.proposed, null, 2)));
  $('.copy-cli', root)?.addEventListener('click', () => copyText(rem.cli.join('\n')));
}
function renderRemediations() {
  const rs = S.r.remediations;
  $('#remList').innerHTML = rs.length ? rs.map((x) => `<div class="path-card ${x.id === S.remSel ? 'on' : ''}" data-rem="${x.id}">
      <div class="flex items-center gap-2">${sevBadge(x.max_severity)}<span class="mono text-xs text-slate-400">${x.id}</span><span class="ml-auto text-[11px]">${sevBadge(x.verification.before)} → ${sevBadge(x.verification.after)}</span></div>
      <div class="font-semibold text-sm mt-1 break-all">${esc(x.policy_name)}</div>
      <div class="text-[11px] text-slate-400">${esc(x.policy_kind)} · ${esc(x.applies_to.join(', ') || 'unattached')}</div></div>`).join('')
    : '<div class="card text-sm text-slate-400">Nothing to remediate.</div>';
  $$('#remList [data-rem]').forEach((el) => el.addEventListener('click', () => { S.remSel = el.dataset.rem; renderRemediations(); }));
  const rem = S.r.remById[S.remSel];
  $('#remDetail').innerHTML = rem ? `<div class="flex items-center gap-2 flex-wrap"><h3 class="text-lg font-bold break-all">${esc(rem.policy_name)}</h3><span class="chip">${esc(rem.policy_kind)}</span>
      <span class="text-xs text-slate-400">applies to ${esc(rem.applies_to.join(', ') || '—')}</span></div>
      <div class="text-xs text-slate-400 mb-3">Fixes ${rem.finding_ids.map((id) => `<a class="text-sky-400 cursor-pointer" data-finding="${id}">${id}</a>`).join(', ')}</div>${remediationBlock(rem)}` : '';
  bindRemediationBlock($('#remDetail'), rem);
  $$('#remDetail [data-finding]').forEach((el) => el.addEventListener('click', () => openFinding(el.dataset.finding)));
}

/* ---------------------------------------------------------------- identities */
function renderIdentities() {
  $('#identityGrid').innerHTML = S.r.identities.map((i) => {
    const b = i.blast, c = SEV_COLOR[b.level];
    return `<div class="card cursor-pointer hover:border-ink-500 transition" data-arn="${esc(i.arn)}">
      <div class="flex items-start gap-3"><div class="min-w-0 flex-1"><div class="flex gap-1.5 items-center flex-wrap"><span class="chip uppercase">${i.kind}</span>
        ${i.admin ? '<span class="sev sev-CRITICAL">ADMIN</span>' : ''}${i.trust.some((t) => t.external || t.kind === 'anyone') ? '<span class="sev sev-HIGH">EXTERNAL TRUST</span>' : ''}</div>
        <div class="font-bold mt-1 truncate">${esc(i.name)}</div><div class="text-[10px] mono text-slate-500 truncate">${esc(i.arn)}</div></div>
        <div class="text-right"><div class="text-3xl font-extrabold" style="color:${c}">${b.score}</div><div class="text-[10px] uppercase text-slate-400">blast radius</div></div></div>
      <div class="h-1.5 bg-ink-600 rounded mt-2 overflow-hidden"><div class="h-full" style="width:${b.score}%;background:${c}"></div></div>
      <div class="flex flex-wrap gap-1 mt-2">${b.factors.slice(0, 4).map((f) => `<span class="chip">${esc(f.factor)} +${f.points}</span>`).join('')}</div>
      <div class="text-[11px] text-slate-400 mt-2">${i.findings.length} finding(s) · ${i.policies.length} direct polic${i.policies.length === 1 ? 'y' : 'ies'}${i.last_used_days !== null && i.last_used_days !== undefined ? ` · last used ${i.last_used_days}d ago` : ''}</div></div>`;
  }).join('');
  $$('#identityGrid [data-arn]').forEach((el) => el.addEventListener('click', () => {
    switchTab('graph');
    const n = S.cy.getElementById(el.dataset.arn);
    if (n.length) { inspect(n); S.cy.animate({ center: { eles: n }, zoom: 1.2, duration: 400 }); }
  }));
}

/* ---------------------------------------------------------------- misc wiring */
function switchTab(t) {
  $$('#tabs .tab').forEach((b) => b.classList.toggle('active', b.dataset.tab === t));
  $$('.panel').forEach((p) => p.classList.toggle('hidden', p.dataset.panel !== t));
  if (t === 'graph' && S.cy) setTimeout(() => S.cy.resize(), 30);
}
function applyScript() {
  const L = ['#!/usr/bin/env bash', '# IAM Sentinel least-privilege apply script - review every <PLACEHOLDER> first!', 'set -euo pipefail', 'mkdir -p remediation', ''];
  S.r.remediations.forEach((x) => {
    L.push(`# ${x.id} ${x.policy_name} (${x.max_severity} -> ${x.verification.after})`);
    L.push(`cat > ${x.file_name} <<'JSON'`, JSON.stringify(x.proposed, null, 2), 'JSON', '');
  });
  L.push('if grep -lE "<[A-Z0-9_-]+>" remediation/*.json; then', '  echo "Fill in the <PLACEHOLDERS> in the files above, then re-run." >&2; exit 1', 'fi', '');
  S.r.remediations.forEach((x) => L.push(`# ${x.id}`, ...x.cli, ''));
  download('apply-remediations.sh', L.join('\n'), 'text/x-shellscript');
}

document.addEventListener('DOMContentLoaded', () => {
  if (typeof cytoscape === 'undefined') toast('Cytoscape failed to load (offline?) - graph disabled', 'error');
  $$('#tabs .tab').forEach((b) => b.addEventListener('click', () => switchTab(b.dataset.tab)));
  $$('.sample-btn').forEach((b) => b.addEventListener('click', () => loadSample(b.dataset.sample)));
  $('#fileInput').addEventListener('change', (e) => { uploadFile(e.target.files[0]); e.target.value = ''; });
  $('#hlToggle').addEventListener('click', toggleHighlight);
  $('#fitBtn').addEventListener('click', () => S.cy.animate({ fit: { padding: 40 }, duration: 400 }));
  $('#edgeLabels').addEventListener('change', (e) => S.cy.edges().toggleClass('labels', e.target.checked));
  $('#layoutSel').addEventListener('change', (e) => {
    const lay = e.target.value === 'cose' ? { name: 'cose', animate: true, nodeRepulsion: 9000, idealEdgeLength: 90, padding: 40 } : { name: 'preset', positions: tieredPositions(S.cy), animate: true, padding: 40 };
    S.cy.layout(lay).run();
  });
  ['input', 'change'].forEach((ev) => ['#searchBox', '#catFilter', '#expFilter'].forEach((q) => $(q).addEventListener(ev, renderFindings)));
  $('#exportBtn').addEventListener('click', (e) => { e.stopPropagation(); $('#exportMenu').classList.toggle('hidden'); });
  document.addEventListener('click', () => $('#exportMenu').classList.add('hidden'));
  $$('.export-link[data-fmt]').forEach((a) => a.addEventListener('click', () => exportReport(a.dataset.fmt)));
  $('#applyScript').addEventListener('click', applyScript);
  $('#drawerBack').addEventListener('click', closeDrawer);
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeDrawer(); });
  let depth = 0;
  window.addEventListener('dragenter', (e) => { e.preventDefault(); depth++; $('#dropOverlay').classList.remove('hidden'); });
  window.addEventListener('dragleave', () => { if (--depth <= 0) { depth = 0; $('#dropOverlay').classList.add('hidden'); } });
  window.addEventListener('dragover', (e) => e.preventDefault());
  window.addEventListener('drop', (e) => { e.preventDefault(); depth = 0; $('#dropOverlay').classList.add('hidden'); uploadFile(e.dataTransfer.files[0]); });
  const qp = new URLSearchParams(location.search);
  loadSample(qp.get('sample') || 'default').then(() => {
    if (qp.get('tab')) switchTab(qp.get('tab'));
    if (qp.get('hl')) toggleHighlight();
    if (qp.get('path')) focusPath(qp.get('path'));
    if (qp.get('finding')) openFinding(qp.get('finding'));
    if (qp.get('node')) { const n = S.cy.getElementById(qp.get('node')); if (n.length) inspect(n); }
  });
});
