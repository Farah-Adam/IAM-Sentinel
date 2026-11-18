/* IAM Sentinel - in-browser analysis engine.
 *
 * A dependency-free JavaScript port of the Python `iamsentinel` package (loader -> deny-aware policy
 * evaluation -> detectors -> attack graph -> blast radius -> least-privilege synthesizer -> reports).
 * It produces the same result schema as `GET /api/analysis`, so the dashboard renders it unchanged.
 * Used when the dashboard is hosted statically (GitHub Pages) and no API server is reachable.
 *
 * The security knowledge base (sensitive actions, escalation methods, ...) is generated from
 * iamsentinel/catalog.py into catalog.js by tools/build_pages.py - one source of truth.
 */
(function (root) {
  'use strict';
  const C = root.IAMS_CATALOG;
  if (!C) throw new Error('IAM Sentinel: catalog.js must be loaded before analyzer.js');

  const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  const RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
  const BY_RANK = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  const SENTINEL_ACTION = 'zzsentinelservice:ZzSentinelAction';
  const SENS = C.SENSITIVE_ACTIONS; // ordered object action -> category
  const SENS_KEYS = Object.keys(SENS);
  const SENS_BY_LOWER = new Map(SENS_KEYS.map((k) => [k.toLowerCase(), k]));
  const SENS_LOWER = new Set(SENS_BY_LOWER.keys());
  const isSensitivePattern = (a) => (isWildcard(a) ? SENS_KEYS.some((s) => actionMatch(a, s)) : SENS_LOWER.has(a.toLowerCase()));
  const CRITICAL_SERVICES = new Set(C.CRITICAL_SERVICES);
  const HIGH_RISK_SERVICES = new Set(C.HIGH_RISK_SERVICES);
  const STRONG_KEYS = new Set(C.STRONG_CONDITION_KEYS);
  const DEPUTY_SAFE = new Set(C.CONFUSED_DEPUTY_SAFE_SERVICES);
  const STAR_ONLY = new Set(C.STAR_ONLY);
  const ASSUME_ACTIONS = ['sts:AssumeRole', 'sts:AssumeRoleWithWebIdentity', 'sts:AssumeRoleWithSAML'];

  class IAMParseError extends Error {}

  /* ------------------------------------------------------------------ small helpers */
  const downgrade = (s, n = 1) => BY_RANK[Math.max(0, RANK[s] - n)];
  const upgrade = (s, n = 1) => BY_RANK[Math.min(4, RANK[s] + n)];
  const asList = (v) => (v === null || v === undefined ? [] : Array.isArray(v) ? v : [v]);
  const hasKeys = (o) => !!o && typeof o === 'object' && Object.keys(o).length > 0;
  const uniq = (xs) => [...new Set(xs)];
  const sorted = (xs, key) => [...xs].sort(key ? (a, b) => { const x = key(a), y = key(b); return x < y ? -1 : x > y ? 1 : 0; } : undefined);
  const clone = (o) => (o === undefined ? undefined : JSON.parse(JSON.stringify(o)));
  const maxSev = (sevs) => { let best = null; for (const s of sevs) if (best === null || RANK[s] > RANK[best]) best = s; return best || 'INFO'; };
  const shortArn = (a) => (a || '').split('/').pop();
  const trunc = (xs, n) => xs.slice(0, n);
  const rxCache = new Map();
  function compile(pattern, ci) {
    const k = (ci ? 'i' : 's') + pattern;
    let rx = rxCache.get(k);
    if (!rx) {
      const body = pattern.replace(/[.*+?^${}()|[\]\\\/-]/g, '\\$&').replace(/\\\*/g, '.*').replace(/\\\?/g, '.');
      rx = new RegExp('^' + body + '$', ci ? 'is' : 's');
      rxCache.set(k, rx);
    }
    return rx;
  }
  const actionMatch = (p, a) => compile(String(p), true).test(a);
  const resourceMatch = (p, r) => compile(String(p), false).test(r);
  const isWildcard = (a) => a.includes('*') || a.includes('?');
  const probeAction = (a) => (a === '*' ? SENTINEL_ACTION : a.replace(/\*/g, 'Zz').replace(/\?/g, 'Z'));

  function parseTime(v) {
    if (v === null || v === undefined || ['', 'N/A', 'no_information', 'not_supported'].includes(v)) return null;
    let s = String(v).trim();
    if (/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/.test(s)) s += 'Z'; // naive -> UTC (as Python loader)
    const d = new Date(s);
    return isNaN(d.getTime()) ? null : d;
  }
  function isoPy(d) {
    if (!d) return null;
    const s = d.toISOString(), ms = s.slice(20, 23);
    return s.slice(0, 19) + (ms !== '000' ? `.${ms}000` : '') + '+00:00';
  }
  const ymd = (d) => d.toISOString().slice(0, 10);
  const ymdhm = (d) => d.toISOString().slice(0, 16).replace('T', ' ');

  /* ------------------------------------------------------------------ model */
  function parseStatement(raw, index) {
    raw = raw && typeof raw === 'object' ? raw : {};
    const st = {
      index, sid: String(raw.Sid || ''), effect: String(raw.Effect === undefined ? 'Allow' : raw.Effect),
      actions: asList(raw.Action).map(String), not_actions: asList(raw.NotAction).map(String),
      resources: asList(raw.Resource).map(String), not_resources: asList(raw.NotResource).map(String),
      condition: raw.Condition || {}, principal: raw.Principal, not_principal: raw.NotPrincipal, raw,
    };
    st.isAllow = st.effect.toLowerCase() === 'allow';
    st.isDeny = st.effect.toLowerCase() === 'deny';
    st.label = st.sid ? st.sid : `Statement[${index}]`;
    st.actionDisplay = () => (st.actions.length ? st.actions : st.not_actions.map((a) => `NotAction: ${a}`));
    st.resourceDisplay = () => (st.resources.length ? st.resources : st.not_resources.map((r) => `NotResource: ${r}`));
    return st;
  }
  function policyFromDocument(key, name, kind, document, extra = {}) {
    document = document || {};
    return {
      key, name, kind, document, statements: asList(document.Statement).map((s, i) => parseStatement(s, i)),
      arn: null, owner_arn: null, default_version: null, attachment_count: null, synthesized: false, ...extra,
    };
  }
  function newIdentity(o) {
    return {
      id: '', path: '/', create_date: null, policy_keys: [], group_arns: [], member_arns: [], trust: null, boundary_arn: null,
      last_used: null, last_used_region: null, password_last_used: null, password_enabled: null, mfa_active: null,
      access_keys: [], instance_profiles: [], tags: {}, telemetry: {}, ...o,
    };
  }
  const isServiceRole = (i) => i.kind === 'role' && (i.path.startsWith('/aws-service-role/') || i.path.startsWith('/service-role/'));
  function finding(o) {
    return {
      rule_id: '', title: '', severity: 'INFO', category: '', description: '', attack_scenario: '', recommendation: '',
      identity_arns: [], identity_names: [], policy_name: null, policy_arn: null, policy_key: null, policy_kind: null, sid: null,
      statement_index: null, effect: null, actions: [], resources: [], condition: null, offending_actions: [],
      exploitability: 'confirmed', mitre: [], notes: [], remediation_id: null, id: '', ...o,
    };
  }

  /* ------------------------------------------------------------------ loader */
  function decodeDocument(doc) {
    if (doc && typeof doc === 'object' && !Array.isArray(doc)) return doc;
    if (typeof doc === 'string') {
      let text = doc;
      if (text.trimStart().startsWith('%7B') || text.includes('%22')) {
        try { text = decodeURIComponent(text); } catch (e) { /* keep raw */ }
      }
      try { return JSON.parse(text); } catch (e) { throw new IAMParseError(`Policy document is not valid JSON: ${e.message}`); }
    }
    return {};
  }
  const accountFromArn = (arn) => { const m = /^arn:aws[\w-]*:iam::(\d{12}):/.exec(arn || ''); return m ? m[1] : null; };
  function b64decode(s) {
    if (typeof atob === 'function') return decodeURIComponent(escape(atob(String(s).replace(/\s+/g, ''))));
    return Buffer.from(String(s), 'base64').toString('utf-8');
  }
  function parseCSV(text) {
    const rows = []; let row = [], cur = '', q = false;
    for (let i = 0; i < text.length; i++) {
      const ch = text[i];
      if (q) {
        if (ch === '"' && text[i + 1] === '"') { cur += '"'; i++; } else if (ch === '"') q = false; else cur += ch;
      } else if (ch === '"') q = true;
      else if (ch === ',') { row.push(cur); cur = ''; }
      else if (ch === '\n' || ch === '\r') { if (ch === '\r' && text[i + 1] === '\n') i++; row.push(cur); rows.push(row); row = []; cur = ''; }
      else cur += ch;
    }
    if (cur || row.length) { row.push(cur); rows.push(row); }
    const [head, ...body] = rows.filter((r) => r.length && !(r.length === 1 && r[0] === ''));
    if (!head) return [];
    return body.map((r) => Object.fromEntries(head.map((h, i) => [h, r[i] ?? null])));
  }
  function parseCredentialReport(raw) {
    if (raw === null || raw === undefined) return [];
    if (raw && typeof raw === 'object' && !Array.isArray(raw) && 'Content' in raw) raw = b64decode(raw.Content);
    if (typeof raw === 'string') return parseCSV(raw);
    if (Array.isArray(raw)) return raw.filter((r) => r && typeof r === 'object' && !Array.isArray(r));
    return [];
  }
  const stem = (s) => { const b = String(s || '').split(/[\\/]/).pop(); const i = b.lastIndexOf('.'); return i > 0 ? b.slice(0, i) : b; };

  function normalize(data, source = 'upload') {
    if (!data || typeof data !== 'object' || Array.isArray(data)) throw new IAMParseError('Top-level JSON must be an object');
    const warnings = [];
    if ('Statement' in data && !['UserDetailList', 'RoleDetailList', 'Policies'].some((k) => k in data)) {
      data = { UserDetailList: [{ UserName: 'uploaded-policy-subject', Arn: 'arn:aws:iam::000000000000:user/uploaded-policy-subject',
        UserPolicyList: [{ PolicyName: stem(source) || 'uploaded-policy', PolicyDocument: data }] }] };
      warnings.push('Input was a single policy document; it was analysed as an inline policy of a synthetic user.');
    }
    const known = ['UserDetailList', 'GroupDetailList', 'RoleDetailList', 'Policies', 'Users', 'CredentialReport'];
    if (!known.some((k) => k in data)) {
      throw new IAMParseError('Unrecognised IAM export. Expected output of `aws iam get-account-authorization-details` ' +
        '(UserDetailList/GroupDetailList/RoleDetailList/Policies) or a policy document.');
    }
    const policies = new Map(), identities = new Map();
    for (const p of asList(data.Policies)) {
      const arn = p.Arn || '';
      const versions = asList(p.PolicyVersionList);
      const def = versions.find((v) => v.IsDefaultVersion) || versions[0] || null;
      const doc = def ? decodeDocument(def.Document) : {};
      const kind = arn.includes(':aws:policy/') ? 'aws-managed' : 'customer-managed';
      policies.set(arn, policyFromDocument(arn, p.PolicyName || arn.split('/').pop(), kind, doc,
        { arn, default_version: p.DefaultVersionId ?? null, attachment_count: p.AttachmentCount ?? null }));
    }
    const managedRef = (ref) => {
      const arn = ref.PolicyArn || '';
      if (!policies.has(arn)) {
        const name = ref.PolicyName || arn.split('/').pop();
        const doc = arn.includes(':aws:policy/') ? C.KNOWN_MANAGED_DOCUMENTS[name] || null : null;
        policies.set(arn, policyFromDocument(arn, name, arn.includes(':aws:policy/') ? 'aws-managed' : 'customer-managed', clone(doc) || {},
          { arn, synthesized: doc !== null }));
        if (doc === null) warnings.push(`Managed policy ${name} is referenced but its document is not in the export; it was not evaluated.`);
      }
      return arn;
    };
    const inline = (owner, items) => asList(items).map((ip) => {
      const name = ip.PolicyName || 'inline', key = `inline:${owner}:${name}`;
      policies.set(key, policyFromDocument(key, name, 'inline', decodeDocument(ip.PolicyDocument), { owner_arn: owner }));
      return key;
    });
    const tags = (t) => Object.fromEntries(asList(t).map((x) => [x.Key, x.Value]));
    const groupByName = new Map();
    for (const g of asList(data.GroupDetailList)) {
      const arn = g.Arn || `arn:aws:iam::000000000000:group/${g.GroupName}`;
      const ident = newIdentity({ arn, name: g.GroupName || arn, kind: 'group', id: g.GroupId || '', path: g.Path || '/', create_date: parseTime(g.CreateDate) });
      ident.policy_keys = [...inline(arn, g.GroupPolicyList), ...asList(g.AttachedManagedPolicies).map(managedRef)];
      identities.set(arn, ident); groupByName.set(ident.name, arn);
    }
    for (const u of asList(data.UserDetailList)) {
      const arn = u.Arn || `arn:aws:iam::000000000000:user/${u.UserName}`;
      const ident = newIdentity({ arn, name: u.UserName || arn, kind: 'user', id: u.UserId || '', path: u.Path || '/', create_date: parseTime(u.CreateDate),
        tags: tags(u.Tags), boundary_arn: (u.PermissionsBoundary || {}).PermissionsBoundaryArn || null });
      ident.policy_keys = [...inline(arn, u.UserPolicyList), ...asList(u.AttachedManagedPolicies).map(managedRef)];
      for (const gname of asList(u.GroupList)) {
        const garn = groupByName.get(gname);
        if (garn) { ident.group_arns.push(garn); identities.get(garn).member_arns.push(arn); }
        else warnings.push(`User ${ident.name} is in group ${gname}, which is missing from GroupDetailList.`);
      }
      if (u.PasswordLastUsed) { ident.password_last_used = parseTime(u.PasswordLastUsed); ident.telemetry.password_last_used = true; }
      identities.set(arn, ident);
    }
    for (const r of asList(data.RoleDetailList)) {
      const arn = r.Arn || `arn:aws:iam::000000000000:role/${r.RoleName}`;
      const ident = newIdentity({ arn, name: r.RoleName || arn, kind: 'role', id: r.RoleId || '', path: r.Path || '/', create_date: parseTime(r.CreateDate),
        tags: tags(r.Tags), boundary_arn: (r.PermissionsBoundary || {}).PermissionsBoundaryArn || null });
      ident.policy_keys = [...inline(arn, r.RolePolicyList), ...asList(r.AttachedManagedPolicies).map(managedRef)];
      ident.trust = policyFromDocument(`trust:${arn}`, `${ident.name} trust policy`, 'trust', decodeDocument(r.AssumeRolePolicyDocument), { owner_arn: arn });
      ident.instance_profiles = asList(r.InstanceProfileList).map((ip) => ip.InstanceProfileName || '');
      if ('RoleLastUsed' in r) {
        ident.telemetry.role_last_used = true;
        ident.last_used = parseTime((r.RoleLastUsed || {}).LastUsedDate);
        ident.last_used_region = (r.RoleLastUsed || {}).Region || null;
      }
      identities.set(arn, ident);
    }
    const byName = new Map([...identities.values()].filter((i) => i.kind === 'user').map((i) => [i.name, i]));
    for (const u of asList(data.Users)) {
      const ident = byName.get(u.UserName);
      if (ident && u.PasswordLastUsed) { ident.password_last_used = parseTime(u.PasswordLastUsed); ident.telemetry.password_last_used = true; }
    }
    const rows = parseCredentialReport(data.CredentialReport);
    const low = (x) => String(x ?? '').toLowerCase();
    for (const row of rows) {
      const ident = byName.get(row.user);
      if (!ident) continue;
      ident.telemetry.credential_report = true;
      ident.password_enabled = low(row.password_enabled) === 'true';
      ident.mfa_active = low(row.mfa_active) === 'true';
      if (![null, undefined, '', 'N/A', 'no_information'].includes(row.password_last_used)) ident.password_last_used = parseTime(row.password_last_used);
      for (const n of ['1', '2']) {
        const rot = row[`access_key_${n}_last_rotated`];
        if (['true', 'false'].includes(low(row[`access_key_${n}_active`])) && ![null, undefined, '', 'N/A'].includes(rot)) {
          ident.access_keys.push({ key_id: `access_key_${n}`, active: low(row[`access_key_${n}_active`]) === 'true',
            last_rotated: parseTime(rot), last_used: parseTime(row[`access_key_${n}_last_used_date`]) });
        }
      }
    }
    const counts = new Map();
    const bump = (a) => { if (a) counts.set(a, (counts.get(a) || 0) + 1); };
    for (const i of identities.values()) bump(accountFromArn(i.arn));
    for (const p of policies.values()) bump(accountFromArn(p.arn || ''));
    let accountId = '000000000000', best = 0;
    for (const [a, n] of counts) if (n > best) { best = n; accountId = a; }
    const all = [...identities.values()];
    return {
      account_id: accountId, identities, policies, source, has_credential_report: rows.length > 0, warnings,
      users: () => all.filter((i) => i.kind === 'user'), groups: () => all.filter((i) => i.kind === 'group'), roles: () => all.filter((i) => i.kind === 'role'),
    };
  }

  /* ------------------------------------------------------------------ deny-aware evaluation */
  // Indexed + memoised per statement: exports often contain managed policies with thousands of actions
  // shared by hundreds of principals, so each (statement, action) pair is decided once.
  function actionIndex(list) {
    const exact = new Set(), wild = [];
    for (const p of list) { if (isWildcard(p)) wild.push(compile(p, true)); else exact.add(p.toLowerCase()); }
    return { exact, wild, test: (a) => exact.has(a.toLowerCase()) || wild.some((r) => r.test(a)) };
  }
  function stmtMatchesAction(st, action) {
    const memo = st._am || (st._am = new Map()), k = action.toLowerCase();
    let v = memo.get(k);
    if (v === undefined) {
      if (!st.actions.length && !st.not_actions.length) v = false;
      else {
        const idx = st._ai || (st._ai = actionIndex(st.actions.length ? st.actions : st.not_actions));
        v = st.actions.length ? idx.test(action) : !idx.test(action);
      }
      memo.set(k, v);
    }
    return v;
  }
  function stmtMatchesResource(st, resource) {
    if (resource === '*') {
      if (st.resources.length) return true;
      if (st.not_resources.length) return !st.not_resources.includes('*');
      return true;
    }
    if (st.resources.length) return st.resources.some((p) => resourceMatch(p, resource));
    if (st.not_resources.length) return !st.not_resources.some((p) => resourceMatch(p, resource));
    return true;
  }
  const stmtIsGlobal = (st) => st.resources.includes('*') || st.not_resources.length > 0;

  class PermissionSet {
    constructor(statements, boundary = null) {
      this.statements = statements; // [[policy, statement]]
      this.allows = statements.filter(([, s]) => s.isAllow).map(([p, s]) => ({ policy: p, statement: s, conditional: hasKeys(s.condition) }));
      this.denies = statements.filter(([, s]) => s.isDeny).map(([p, s]) => ({ policy: p, statement: s, conditional: hasKeys(s.condition) }));
      this.boundary = boundary;
      this.cache = new Map();
    }
    evaluate(action, resource = '*') {
      const key = action.toLowerCase() + '\u0000' + resource;
      const hit = this.cache.get(key);
      if (hit) return hit;
      const grants = this.allows.filter((g) => stmtMatchesAction(g.statement, action) && stmtMatchesResource(g.statement, resource));
      const hard = [], cond = [], partial = [];
      for (const d of this.denies) {
        if (!stmtMatchesAction(d.statement, action) || !stmtMatchesResource(d.statement, resource)) continue;
        const coversAll = resource !== '*' || (stmtIsGlobal(d.statement) && !d.statement.not_resources.length);
        if (hasKeys(d.statement.condition)) cond.push(d); else if (coversAll) hard.push(d); else partial.push(d);
      }
      let boundaryBlocked = false;
      if (this.boundary && grants.length) {
        const b = new PermissionSet(this.boundary.statements.map((s) => [this.boundary, s]));
        boundaryBlocked = !b.evaluate(action, resource).allowed;
      }
      const dec = {
        action, resource, allowed: grants.length > 0 && !hard.length && !boundaryBlocked, grants,
        hard_denies: hard, conditional_denies: cond, partial_denies: partial, boundary_blocked: boundaryBlocked,
        get global_scope() { return grants.some((g) => stmtIsGlobal(g.statement)); },
        get conditional() { return grants.length > 0 && grants.every((g) => g.conditional); },
      };
      this.cache.set(key, dec);
      return dec;
    }
    isFullAdmin() {
      const d = this.evaluate(SENTINEL_ACTION);
      const probes = ['iam:AttachUserPolicy', 'iam:PassRole', 'sts:AssumeRole', 's3:GetObject', 'ec2:RunInstances'];
      return d.allowed && d.global_scope && probes.every((p) => this.evaluate(p).allowed) ? d : null;
    }
  }

  /* ------------------------------------------------------------------ context */
  const accountOf = (p) => { if (/^\d{12}$/.test(p)) return p; const m = /^arn:aws[\w-]*:(?:iam|sts)::(\d{12}):/.exec(p); return m ? m[1] : null; };
  function trustEntry(kind, value, account, external, statement, actions) {
    const e = { kind, value, account, external, statement, actions };
    e.conditionKeys = () => {
      const keys = new Set();
      for (const kv of Object.values(statement.condition || {})) if (kv && typeof kv === 'object' && !Array.isArray(kv)) Object.keys(kv).forEach((k) => keys.add(k.toLowerCase()));
      return keys;
    };
    e.conditionValues = (key) => {
      const out = [];
      for (const kv of Object.values(statement.condition || {})) {
        if (kv && typeof kv === 'object' && !Array.isArray(kv)) for (const [k, v] of Object.entries(kv)) if (k.toLowerCase() === key.toLowerCase()) out.push(...asList(v).map(String));
      }
      return out;
    };
    e.nodeId = kind === 'anyone' ? 'principal:anyone' : kind === 'service' ? `svc:${value}` : kind === 'federated' ? `fed:${value}` : kind === 'aws-account' ? `acct:${account}` : value;
    return e;
  }
  function parseTrust(role, accountId) {
    const entries = [];
    if (!role.trust) return entries;
    for (const st of role.trust.statements) {
      if (!st.isAllow) continue;
      const actions = st.actions.length ? st.actions : ['sts:AssumeRole'];
      if (!actions.some((a) => ASSUME_ACTIONS.some((x) => actionMatch(a, x)))) continue;
      if (st.not_principal !== undefined && st.not_principal !== null) { entries.push(trustEntry('not-principal', 'NotPrincipal', null, true, st, actions)); continue; }
      const pr = st.principal;
      const isObj = pr && typeof pr === 'object' && !Array.isArray(pr);
      if (pr === '*' || (isObj && asList(pr.AWS).includes('*'))) entries.push(trustEntry('anyone', '*', null, true, st, actions));
      if (!isObj) continue;
      for (const p of asList(pr.AWS)) {
        if (p === '*') continue;
        const acct = accountOf(p);
        const external = acct !== null && acct !== accountId;
        if (/^\d{12}$/.test(p) || String(p).endsWith(':root')) entries.push(trustEntry('aws-account', `arn:aws:iam::${acct}:root`, acct, external, st, actions));
        else entries.push(trustEntry('aws-principal', p, acct, external, st, actions));
      }
      for (const s of asList(pr.Service)) entries.push(trustEntry('service', s, null, false, st, actions));
      for (const f of asList(pr.Federated)) entries.push(trustEntry('federated', f, accountOf(f), false, st, actions));
    }
    return entries;
  }

  class Context {
    constructor(account, now, staleDays) {
      this.account = account; this.now = now; this.stale_days = staleDays;
      this.policies = account.policies; this.identities = account.identities;
      this.sources = new Map(); this.perms = new Map(); this.holders = new Map(); this.direct_holders = new Map();
      this.trusts = new Map(); this.admin = new Map(); this._assume = null; this._sens = new Map();
      const push = (m, k, v) => { if (!m.has(k)) m.set(k, []); m.get(k).push(v); };
      for (const ident of this.identities.values()) for (const pk of ident.policy_keys) push(this.direct_holders, pk, ident.arn);
      for (const ident of this.identities.values()) {
        const stmts = [];
        for (const pk of ident.policy_keys) {
          const pol = this.policies.get(pk);
          if (pol) { pol.statements.forEach((s) => stmts.push([pol, s, 'direct'])); push(this.holders, pk, ident.arn); }
        }
        for (const garn of ident.group_arns) {
          const g = this.identities.get(garn);
          for (const pk of g ? g.policy_keys : []) {
            const pol = this.policies.get(pk);
            if (!pol) continue;
            pol.statements.forEach((s) => stmts.push([pol, s, `group:${g.name}`]));
            if (!this.holders.has(pk)) this.holders.set(pk, []);
            if (!this.holders.get(pk).includes(ident.arn)) this.holders.get(pk).push(ident.arn);
          }
        }
        this.sources.set(ident.arn, stmts);
        const boundary = ident.boundary_arn ? this.policies.get(ident.boundary_arn) || null : null;
        const ps = new PermissionSet(stmts.map(([p, s]) => [p, s]), boundary);
        this.perms.set(ident.arn, ps);
        this.admin.set(ident.arn, ps.isFullAdmin());
        if (ident.kind === 'role') this.trusts.set(ident.arn, parseTrust(ident, account.account_id));
      }
    }
    principals() { return [...this.identities.values()].filter((i) => i.kind === 'user' || i.kind === 'role'); }
    isAdmin(arn) { return !!this.admin.get(arn); }
    daysSince(d) { return d ? Math.max(0, Math.floor((this.now - d) / 86400000)) : null; }
    sensitiveAllowed(arn) {
      if (this._sens.has(arn)) return this._sens.get(arn);
      const ps = this.perms.get(arn), out = {};
      for (const a of SENS_KEYS) if (ps.evaluate(a).allowed) (out[SENS[a]] = out[SENS[a]] || []).push(a);
      this._sens.set(arn, out);
      return out;
    }
    assumeEdges() {
      if (this._assume) return this._assume;
      const edges = [], acct = this.account.account_id;
      for (const role of this.account.roles()) {
        for (const t of this.trusts.get(role.arn) || []) {
          if (t.kind === 'aws-principal' && this.identities.has(t.value) && t.value !== role.arn) edges.push({ source: t.value, role: role.arn, via: 'trust-direct' });
          else if ((t.kind === 'aws-account' && t.account === acct) || t.kind === 'anyone') {
            for (const p of this.principals()) {
              if (p.arn === role.arn) continue;
              if (this.perms.get(p.arn).evaluate('sts:AssumeRole', role.arn).allowed) edges.push({ source: p.arn, role: role.arn, via: t.kind !== 'anyone' ? 'trust-account' : 'trust-anyone' });
            }
          }
        }
      }
      const seen = new Map();
      for (const e of edges) { const k = e.source + '\u0000' + e.role; if (!seen.has(k)) seen.set(k, e); }
      this._assume = [...seen.values()];
      return this._assume;
    }
    canAssume(p, r) { return this.assumeEdges().some((e) => e.source === p && e.role === r); }
  }

  /* ------------------------------------------------------------------ detectors */
  function strongCondition(cond) {
    const keys = [];
    for (const kv of Object.values(cond || {})) {
      if (kv && typeof kv === 'object' && !Array.isArray(kv)) {
        for (const k of Object.keys(kv)) { const l = k.toLowerCase(); if (STRONG_KEYS.has(l) || l.startsWith('aws:resourcetag') || l.startsWith('aws:principaltag')) keys.push(k); }
      }
    }
    return keys;
  }
  const BROAD_READ_ACTIONS = 50, BROAD_READ_SERVICES = 10;

  function scanPolicy(policy, holders, permsets, accountId, suppressed) {
    const findings = [];
    const names = holders.map((h) => h.name), arns = holders.map((h) => h.arn);
    const awsManaged = policy.kind === 'aws-managed';
    const base = (rule, title, sev, cat, st, desc, attack, rec, offending, mitre) => {
      const f = finding({ rule_id: rule, title, severity: sev, category: cat, description: desc, attack_scenario: attack, recommendation: rec,
        identity_arns: [...arns], identity_names: [...names], policy_name: policy.name, policy_arn: policy.arn, policy_key: policy.key,
        policy_kind: policy.kind, sid: st.sid || null, statement_index: st.index, effect: st.effect, actions: st.actionDisplay(),
        resources: st.resourceDisplay(), condition: hasKeys(st.condition) ? st.condition : null, offending_actions: offending, mitre });
      const strong = strongCondition(st.condition);
      if (strong.length) {
        f.severity = downgrade(f.severity); f.exploitability = 'conditional';
        f.notes.push(`Allow is constrained by condition key(s) ${strong.join(', ')} - severity lowered one level.`);
      } else if (hasKeys(st.condition)) {
        f.notes.push('Statement has a Condition block, but none of its keys meaningfully restrict who/where (no MFA, org, IP, VPC or account pinning).');
      }
      if (!holders.length) {
        f.severity = downgrade(f.severity);
        f.notes.push('Policy is not attached to any identity in this export (latent risk if attached later).');
        f.exploitability = 'latent';
      }
      if (awsManaged && rule !== 'ADMIN-001') f.notes.push('AWS-managed policy: you cannot edit it - replace it with a scoped customer-managed copy (generated below).');
      return f;
    };
    const denyFilter = (st, actions) => {
      if (!permsets.length) return [actions, []];
      const keep = [], blocked = [];
      for (const a of actions) {
        let probe = isWildcard(a) ? a.replace(/\*/g, 'Zz') : a;
        if (a === '*') probe = SENTINEL_ACTION;
        if (permsets.every((ps) => { const d = ps.evaluate(probe); return !d.allowed && d.hard_denies.length; })) blocked.push(a); else keep.push(a);
      }
      if (blocked.length && suppressed) suppressed.push({ policy: policy.name, sid: st.label, actions: blocked, identities: names, reason: 'Explicit unconditional Deny overrides this Allow for every holder.' });
      return [keep, blocked];
    };

    if (awsManaged && C.BROAD_MANAGED_POLICIES[policy.name] && policy.name !== 'AdministratorAccess') {
      const [sev, why] = C.BROAD_MANAGED_POLICIES[policy.name];
      const st0 = policy.statements[0] || parseStatement({ Effect: 'Allow' }, 0);
      const allowedAny = permsets.length ? permsets.some((ps) => ps.evaluate('s3:GetObject').allowed || ps.evaluate('ec2:RunInstances').allowed || ps.evaluate('iam:CreateUser').allowed) : true;
      if (allowedAny) {
        findings.push(base('ADMIN-002', `Overly broad AWS managed policy '${policy.name}' attached`, sev, 'Excessive Privilege', st0, `${policy.name}: ${why}`,
          "Any compromise of a holder's credentials (phished console password, leaked access key, SSRF on a workload) immediately yields account-wide data access and destructive capability.",
          `Detach ${policy.name}; attach a customer-managed policy listing only the services and resources the workload uses (use IAM Access Analyzer policy generation from CloudTrail activity).`,
          st0.actionDisplay(), ['T1078.004', 'T1098']));
      }
      return findings;
    }

    for (const st of policy.statements) {
      if (!st.isAllow) continue;
      const glob = stmtIsGlobal(st);
      const [actions] = denyFilter(st, st.actions);
      if (st.not_actions.length) {
        const excludesIam = st.not_actions.some((p) => actionMatch(p, 'iam:CreateUser'));
        let sev = excludesIam ? 'HIGH' : 'CRITICAL';
        if (!glob) sev = downgrade(sev);
        findings.push(base('WILD-004', 'Allow with NotAction grants everything except a short deny-list', sev, 'Wildcard Permission', st,
          `Statement allows every AWS action except ${st.not_actions.join(', ')} - new AWS services and APIs are granted automatically.`,
          'The holder can use any service not on the exclusion list (data exfiltration, crypto-mining, destruction). ' + (excludesIam ? '' : 'IAM is not excluded, so this is equivalent to full administrator.'),
          'Replace NotAction with an explicit Action allow-list of required APIs.', st.not_actions.map((a) => `NotAction: ${a}`), ['T1078.004']));
        continue;
      }
      if (st.not_resources.length && actions.length) {
        findings.push(base('WILD-005', 'Allow with NotResource applies to (almost) every resource', 'MEDIUM', 'Wildcard Permission', st,
          `Statement applies to every resource except ${st.not_resources.join(', ')}.`,
          'Resources created in the future are covered automatically; the carve-out is easy to bypass.',
          'Use an explicit Resource allow-list.', st.not_resources.map((r) => `NotResource: ${r}`), ['T1078.004']));
      }
      if (!actions.length) continue;
      if (actions.includes('*')) {
        let f;
        if (glob) {
          const via = awsManaged ? ` via AWS managed policy ${policy.name}` : '';
          f = base('ADMIN-001', `Full administrator access (Action "*" on Resource "*")${via}`, 'CRITICAL', 'Excessive Privilege', st,
            'The statement grants every action on every resource in the account. Holders can create users and keys, rewrite any policy, read all data, disable CloudTrail/GuardDuty and delete resources.',
            'Credential theft of this identity = full account takeover. An attacker typically creates a backdoor user or access key (persistence), disables logging (defense evasion) and exfiltrates S3/RDS/Secrets data.',
            'Remove standing admin. Use role-based, MFA-gated, time-bound elevation (IAM Identity Center permission set or an assumable break-glass role) and protect security tooling with explicit Deny.',
            ['*'], ['T1078.004', 'T1098', 'T1562.008']);
        } else {
          f = base('WILD-001', 'Wildcard action "*" on scoped resources', 'HIGH', 'Wildcard Permission', st, `Every API is allowed on ${st.resources.join(', ')}.`,
            'All current and future destructive / permission-changing APIs are allowed on the matching resources.', 'List the exact actions required.', ['*'], ['T1078.004']);
        }
        findings.push(f);
        continue;
      }
      const svcWild = actions.filter((a) => a.endsWith(':*'));
      if (svcWild.length) {
        let sev = maxSev(svcWild.map((a) => { const s = a.split(':')[0].toLowerCase(); return CRITICAL_SERVICES.has(s) ? 'CRITICAL' : HIGH_RISK_SERVICES.has(s) ? 'HIGH' : 'MEDIUM'; }));
        if (!glob) sev = downgrade(sev);
        const covered = sorted(SENS_KEYS.filter((s) => svcWild.some((a) => actionMatch(a, s))));
        findings.push(base('WILD-002', `Service-wide wildcard ${svcWild.join(', ')} on ${glob ? 'all resources' : 'scoped resources'}`, sev, 'Wildcard Permission', st,
          `${svcWild.join(', ')} grants every current and future API of the service, including ${covered.length} known-sensitive action(s) such as ${covered.slice(0, 6).join(', ') || 'n/a'}.`,
          svcAttack(svcWild), 'Replace the service wildcard with the specific read/write actions the workload needs and scope Resource to named ARNs.',
          svcWild, svcWild.some((a) => a.toLowerCase().startsWith('s3:')) ? ['T1530', 'T1485'] : ['T1078.004']));
      }
      const partial = actions.filter((a) => isWildcard(a) && !a.endsWith(':*'));
      const coveredBy = new Map();
      for (const a of partial) { const hits = SENS_KEYS.filter((s) => actionMatch(a, s)); if (hits.length) coveredBy.set(a, hits); }
      if (coveredBy.size) {
        const cats = new Set([...coveredBy.values()].flat().map((s) => SENS[s]));
        let sev = ['privilege-escalation', 'credential-access', 'permissions-management', 'defense-evasion'].some((c) => cats.has(c)) ? 'HIGH' : 'MEDIUM';
        if (!glob) sev = downgrade(sev);
        if (awsManaged) sev = downgrade(sev);
        findings.push(base('WILD-003', 'Wildcard action pattern expands to sensitive APIs', sev, 'Wildcard Permission', st,
          'Patterns ' + [...coveredBy].map(([p, h]) => `${p} → ${h.slice(0, 4).join(', ')}${h.length > 4 ? '…' : ''}`).join('; '),
          'Verb wildcards silently include high-impact APIs (and any API AWS adds later with the same prefix).',
          'Enumerate exact actions or add an explicit Deny for the sensitive matches.', [...coveredBy.keys()], ['T1078.004']));
      }
      if (glob) {
        const sens = new Map();
        for (const a of actions.filter((x) => !isWildcard(x))) { const k = SENS_BY_LOWER.get(a.toLowerCase()); if (k) sens.set(a, SENS[k]); }
        if (sens.size) {
          let sev = maxSev([...sens.values()].map((c) => C.CATEGORIES[c].severity));
          if (awsManaged) sev = downgrade(sev);
          const cats = sorted(uniq([...sens.values()].map((c) => C.CATEGORIES[c].label)));
          const keys = [...sens.keys()];
          findings.push(base('RES-001', `Sensitive action(s) allowed on Resource "*" (${cats.join(', ')})`, sev, 'Unscoped Resource', st,
            `${sens.size} sensitive action(s) apply to every resource: ${keys.slice(0, 12).join(', ')}${sens.size > 12 ? ' …' : ''}.`,
            resAttack(keys), 'Scope Resource to the specific ARNs (bucket, function, parameter path, role) and add guardrail conditions (aws:ResourceAccount, iam:PassedToService, aws:MultiFactorAuthPresent).',
            keys, sorted(uniq([...sens.values()].flatMap(catMitre)))));
        }
      }
      const services = new Set(actions.filter((a) => a.includes(':')).map((a) => a.split(':')[0]));
      if (glob && (actions.length >= BROAD_READ_ACTIONS || services.size >= BROAD_READ_SERVICES)) {
        findings.push(base('READ-001', `Very broad permission surface: ${actions.length} actions across ${services.size} services on "*"`, 'LOW', 'Excessive Privilege', st,
          `A single statement grants ${actions.length} actions across ${services.size} services on all resources (mostly read/list).`,
          'Broad read access enables full reconnaissance of the account (T1580) and reading of operational data such as logs and templates.',
          'Confirm the identity really needs account-wide visibility; otherwise restrict to the services in use.', [], ['T1580']));
      }
    }
    return findings;
  }
  function svcAttack(svcWild) {
    const s = new Set(svcWild.map((a) => a.split(':')[0].toLowerCase()));
    if (s.has('s3')) return 'The holder can read and download every object in every bucket (data exfiltration), make buckets public via s3:PutBucketPolicy / PutBucketAcl, and destroy data with s3:DeleteBucket / DeleteObject (ransomware pattern).';
    if (['iam', 'sts', 'organizations'].some((x) => s.has(x))) return 'IAM control is equivalent to administrator: the holder can attach AdministratorAccess to itself.';
    if (s.has('ec2')) return 'Can launch instances with any instance profile, open security groups, snapshot and share volumes.';
    if (s.has('lambda')) return 'Can replace function code and inherit every Lambda execution role.';
    return 'All current and future APIs of the service are allowed.';
  }
  function resAttack(keys) {
    const acts = new Set(keys.map((a) => a.toLowerCase())), parts = [], any = (xs) => xs.some((x) => acts.has(x));
    if (acts.has('iam:passrole')) parts.push('iam:PassRole on "*" lets the holder hand ANY role (including admin roles) to an AWS service it controls.');
    if (any(['ssm:getparameter', 'ssm:getparameters', 'ssm:getparametersbypath', 'secretsmanager:getsecretvalue'])) parts.push('Every parameter/secret in the account is readable - including database passwords and API tokens of other apps.');
    if (any(['lambda:createfunction', 'ec2:runinstances', 'ssm:sendcommand'])) parts.push('Code-execution APIs on "*" allow running attacker-controlled code inside the account.');
    if (any(['logs:getlogevents', 'logs:filterlogevents'])) parts.push('All CloudWatch log data is readable (logs often contain tokens, PII and request payloads).');
    if (acts.has('eks:accesskubernetesapi')) parts.push('Kubernetes API access on every EKS cluster (subject to cluster access entries).');
    return parts.join(' ') || 'Sensitive actions apply to every resource in the account instead of the specific resources required.';
  }
  const catMitre = (c) => ({ 'privilege-escalation': ['T1098'], 'credential-access': ['T1555.006'], 'defense-evasion': ['T1562.008'], 'code-execution': ['T1648'],
    'data-destruction': ['T1485'], 'data-read': ['T1530'], 'data-write': ['T1530'], 'permissions-management': ['T1098'] }[c] || []);

  function detectExcessive(ctx, suppressed) {
    const out = [];
    for (const [key, pol] of ctx.policies) {
      const holders = (ctx.holders.get(key) || []).filter((a) => ctx.identities.has(a)).map((a) => ctx.identities.get(a));
      if (!holders.length && pol.kind === 'aws-managed') continue;
      out.push(...scanPolicy(pol, holders, holders.map((h) => ctx.perms.get(h.arn)), ctx.account.account_id, suppressed));
    }
    return out;
  }

  function detectTrust(ctx, positives, roles) {
    const out = [], acct = ctx.account.account_id;
    for (const role of roles || ctx.account.roles()) {
      const admin = ctx.isAdmin(role.arn);
      for (const t of ctx.trusts.get(role.arn) || []) {
        const keys = t.conditionKeys(), st = t.statement;
        const mk = (rule, title, sev, desc, attack, rec, mitre, expl = 'confirmed') => {
          const f = finding({ rule_id: rule, title, severity: admin && sev !== 'CRITICAL' && ['TRUST-002', 'TRUST-004', 'TRUST-006'].includes(rule) ? upgrade(sev) : sev,
            category: 'Risky Trust', description: desc, attack_scenario: attack, recommendation: rec, identity_arns: [role.arn], identity_names: [role.name],
            policy_name: `${role.name} (AssumeRolePolicyDocument)`, policy_key: `trust:${role.arn}`, policy_kind: 'trust', sid: st.sid || null,
            statement_index: st.index, effect: st.effect, actions: t.actions, resources: [`Principal: ${t.value}`], condition: hasKeys(st.condition) ? st.condition : null,
            offending_actions: t.actions, mitre, exploitability: expl });
          if (admin) f.notes.push('The role is administrator-equivalent, which raises the impact of this trust.');
          return f;
        };
        if (t.kind === 'not-principal') {
          out.push(mk('TRUST-007', 'Trust policy uses Allow + NotPrincipal', 'CRITICAL', 'Allow with NotPrincipal trusts every principal in every AWS account except the listed ones.',
            'Any AWS customer can assume the role.', 'Replace NotPrincipal with an explicit Principal.', ['T1199']));
        } else if (t.kind === 'anyone') {
          const guards = sorted(['aws:principalorgid', 'aws:principalarn', 'aws:sourceaccount', 'sts:externalid', 'aws:principalaccount', 'aws:sourceip'].filter((k) => keys.has(k)));
          if (guards.length) {
            out.push(mk('TRUST-001', 'Wildcard principal ("*") in trust policy - constrained by conditions', 'MEDIUM', `Principal is "*" but the trust requires ${guards.join(', ')}.`,
              'Safety rests entirely on the condition values; a typo or broad value re-opens the role to the internet.', 'Name the trusted principals explicitly in addition to the condition.', ['T1199'], 'conditional'));
          } else {
            out.push(mk('TRUST-001', 'Role assumable by ANY AWS principal ("Principal": "*")', 'CRITICAL', 'The trust policy allows every IAM principal in every AWS account to call sts:AssumeRole on this role.',
              'An attacker with any AWS account (free tier) runs `aws sts assume-role --role-arn ' + role.arn + "` and receives this role's credentials.",
              'Replace "*" with the specific trusted account/role ARNs and add aws:PrincipalOrgID.', ['T1199', 'T1078.004']));
          }
        } else if ((t.kind === 'aws-account' || t.kind === 'aws-principal') && t.external) {
          if (keys.has('sts:externalid')) {
            out.push(mk('TRUST-003', `Cross-account trust to external account ${t.account} (ExternalId enforced)`, 'LOW', `Role trusts ${t.value} and requires sts:ExternalId.`,
              "Third-party access is legitimate but must be reviewed periodically; the external party's security is now part of yours.",
              'Verify the vendor relationship is still required and the ExternalId is unique per customer.', ['T1199'], 'conditional'));
            positives.push({ control: 'ExternalId on cross-account trust', identity: role.name, detail: `${t.value} must present sts:ExternalId` });
          } else {
            out.push(mk('TRUST-002', `Cross-account trust to external account ${t.account} without sts:ExternalId`, keys.has('aws:principalorgid') ? 'MEDIUM' : 'HIGH',
              `Role trusts ${t.value} (account ${t.account}, outside this account) with no sts:ExternalId condition.`,
              'Confused-deputy: any principal the external account allows (or a third-party SaaS acting for another customer) can assume the role. Compromise of the external account = compromise of this role.',
              'Add Condition StringEquals sts:ExternalId (unique per customer) and narrow the principal to a specific role ARN.', ['T1199']));
          }
        } else if (t.kind === 'aws-account' && t.account === acct) {
          out.push(mk('TRUST-004', 'Role trusts its own account root - any principal with sts:AssumeRole can assume it', 'LOW',
            `Trust delegates to arn:aws:iam::${acct}:root; every user/role whose identity policy allows sts:AssumeRole on this role can become it.`,
            'Lateral movement hub: a broad `sts:AssumeRole` on "*" anywhere in the account becomes a path to this role.',
            'Trust specific role ARNs instead of the account root, or add aws:PrincipalArn / aws:PrincipalTag conditions.', ['T1078.004']));
        } else if (t.kind === 'federated') {
          out.push(...federated(t, role, mk));
        } else if (t.kind === 'service') {
          if (DEPUTY_SAFE.has(t.value)) continue;
          const g = sorted(['aws:sourceaccount', 'aws:sourcearn', 'aws:sourceorgid'].filter((k) => keys.has(k)));
          if (g.length) positives.push({ control: 'Confused-deputy protection on service trust', identity: role.name, detail: `${t.value} restricted by ${g.join(', ')}` });
          else {
            out.push(mk('TRUST-006', `Service trust (${t.value}) without aws:SourceAccount / aws:SourceArn`, 'LOW', `${t.value} can assume the role on behalf of any customer resource.`,
              "Cross-service confused deputy: another AWS customer's resource in the same service may cause the service to act with this role.",
              'Add Condition StringEquals aws:SourceAccount and ArnLike aws:SourceArn.', ['T1199']));
          }
        }
      }
    }
    return out;
  }
  function federated(t, role, mk) {
    const out = [];
    const prov = t.value.includes('oidc-provider/') ? t.value.split('oidc-provider/').pop() : t.value;
    const keys = t.conditionKeys();
    if (t.value.includes('saml-provider/')) {
      if (!keys.has('saml:aud')) out.push(mk('TRUST-005', 'SAML federation trust without SAML:aud condition', 'MEDIUM', `Role trusts SAML provider ${t.value} without pinning SAML:aud.`,
        'Assertions intended for other service providers may be replayed.', 'Add StringEquals SAML:aud = https://signin.aws.amazon.com/saml.', ['T1199']));
      return out;
    }
    const host = prov.split('/')[0], subKey = `${prov}:sub`.toLowerCase(), audKey = `${prov}:aud`.toLowerCase();
    if (C.OIDC_SUBJECT_KEYS[host] || C.OIDC_SUBJECT_KEYS[prov]) {
      if (!keys.has(subKey)) {
        out.push(mk('TRUST-005', `OIDC trust to ${host} without subject (sub) condition`, 'CRITICAL',
          `Any identity issued by ${host} can assume this role - e.g. ANY GitHub repository in the world for GitHub Actions.`,
          `An attacker creates their own repo/pipeline, requests an OIDC token for audience sts.amazonaws.com and calls AssumeRoleWithWebIdentity on ${role.arn}.`,
          `Add StringLike ${prov}:sub restricted to your org/repo/branch and StringEquals ${prov}:aud = sts.amazonaws.com.`, ['T1199', 'T1078.004']));
      } else {
        const vals = t.conditionValues(`${prov}:sub`);
        if (vals.some((v) => ['*', 'repo:*'].includes(v.trim()) || (v.endsWith(':*') && !v.includes('/')))) {
          out.push(mk('TRUST-005', `OIDC trust to ${host} with overly broad subject pattern`, 'HIGH', `Subject condition ${pyList(vals)} matches identities outside your organization.`,
            'Foreign pipelines may match the pattern.', 'Pin the subject to org/repo and branch or environment.', ['T1199']));
        }
      }
    } else if (prov.includes('cognito-identity.amazonaws.com')) {
      if (!keys.has('cognito-identity.amazonaws.com:aud')) out.push(mk('TRUST-005', 'Cognito identity-pool trust without aud condition', 'HIGH', 'Identities from ANY Cognito identity pool can assume the role.',
        'Attacker uses their own identity pool.', 'Add StringEquals cognito-identity.amazonaws.com:aud = <IDENTITY_POOL_ID> and amr = authenticated.', ['T1199']));
    } else if (!keys.has(audKey) && !keys.has(subKey)) {
      out.push(mk('TRUST-005', `OIDC trust to ${prov} without aud/sub conditions`, 'HIGH', `Role trusts web identities from ${prov} without restricting audience or subject.`,
        'Any token minted by the provider for any client can be exchanged for role credentials.', `Add ${prov}:aud and ${prov}:sub conditions.`, ['T1199']));
    }
    return out;
  }
  const pyList = (xs) => '[' + xs.map((x) => `'${x}'`).join(', ') + ']';

  function detectEscalation(ctx) {
    const findings = [], edges = [];
    const adminRoles = new Set(ctx.account.roles().filter((r) => ctx.isAdmin(r.arn)).map((r) => r.arn));
    for (const p of ctx.principals()) {
      if (ctx.isAdmin(p.arn)) continue;
      const ps = ctx.perms.get(p.arn);
      for (const m of C.ESCALATION_METHODS) {
        const decisions = [];
        let ok = true;
        for (const group of m.requires) {
          const hit = group.map((a) => ps.evaluate(a)).find((d) => d.allowed);
          if (!hit) { ok = false; break; }
          decisions.push(hit);
        }
        if (!ok) continue;
        const res = evaluateMethod(ctx, p, m, ps, adminRoles);
        if (!res) continue;
        let [sev, expl, targets, toAdmin, notes] = res;
        let missing = [];
        if (m.completion.length && !m.completion.some((a) => ps.evaluate(a).allowed)) {
          missing = [...m.completion]; expl = 'latent';
          if (sev === 'CRITICAL') sev = downgrade(sev);
          notes.push(`No trigger permission (${m.completion.join(' / ')}) found - the chain is one permission away from executable, or relies on an existing event source / another principal to invoke it.`);
        }
        if (decisions.some((d) => d.conditional)) { sev = downgrade(sev); expl = 'conditional'; notes.push('At least one required permission is conditional.'); }
        const ev = decisions.flatMap((d) => d.grants), g0 = ev[0];
        const f = finding({ rule_id: m.id, title: `Privilege escalation: ${m.name}`, severity: sev, category: 'Privilege Escalation',
          description: m.description + ` Required permissions present: ${decisions.map((d) => d.action).join(', ')}.`,
          attack_scenario: escalationStory(m, p, targets, toAdmin), recommendation: escalationFix(m),
          identity_arns: [p.arn], identity_names: [p.name], policy_name: sorted(uniq(ev.map((g) => g.policy.name))).join(', '),
          policy_arn: g0.policy.arn, policy_key: g0.policy.key, policy_kind: g0.policy.kind, sid: g0.statement.sid || null,
          statement_index: g0.statement.index, effect: 'Allow', actions: sorted(uniq(ev.flatMap((g) => g.statement.actionDisplay()))),
          resources: sorted(uniq(ev.flatMap((g) => g.statement.resourceDisplay()))), condition: hasKeys(g0.statement.condition) ? g0.statement.condition : null,
          offending_actions: [...decisions.map((d) => d.action), ...missing.slice(0, 1).map((a) => `(missing) ${a}`)], exploitability: expl, mitre: [...m.mitre], notes });
        findings.push(f);
        edges.push({ source: p.arn, method: m.id, name: m.name, targets, to_admin: toAdmin, exploitability: expl, severity: sev, finding: f });
      }
    }
    return [findings, edges];
  }
  function evaluateMethod(ctx, p, m, ps, adminRoles) {
    const notes = [], primary = m.requires[0][0];
    if (m.target === 'passrole') {
      const svc = m.pass_to_service, candidates = [];
      for (const r of ctx.account.roles()) {
        if (!ps.evaluate('iam:PassRole', r.arn).allowed) continue;
        if ((ctx.trusts.get(r.arn) || []).some((t) => t.kind === 'service' && t.value === svc)) candidates.push(r.arn);
      }
      const pr = ps.evaluate('iam:PassRole');
      if (pr.grants.some((g) => JSON.stringify(g.statement.condition).toLowerCase().includes('iam:passedtoservice'))) notes.push('iam:PassRole is limited by iam:PassedToService.');
      if (candidates.some((c) => adminRoles.has(c))) return ['CRITICAL', 'confirmed', candidates, true, notes];
      if (candidates.length) {
        notes.push(`Passable roles trusted by ${svc}: ${candidates.map(shortArn).join(', ')} (none admin-equivalent).`);
        return ['HIGH', 'confirmed', candidates, false, notes];
      }
      if (pr.global_scope) {
        notes.push(`No role in this export currently trusts ${svc}; PassRole on "*" means the escalation becomes immediate the moment any privileged role trusting ${svc} exists (common for Lambda/EC2 execution roles).`);
        return ['HIGH', 'latent', [], false, notes];
      }
      return null;
    }
    if (m.target === 'self') {
      let targets = [];
      if (['iam:AttachUserPolicy', 'iam:PutUserPolicy', 'iam:DeleteUserPermissionsBoundary'].includes(primary) && p.kind === 'user') targets = [p.arn];
      else if (['iam:AttachGroupPolicy', 'iam:PutGroupPolicy'].includes(primary)) targets = [...p.group_arns];
      else if (primary === 'iam:DeleteRolePermissionsBoundary' && p.kind === 'role') targets = [p.arn];
      else if (['iam:CreatePolicyVersion', 'iam:SetDefaultPolicyVersion'].includes(primary)) {
        targets = sorted(uniq(ctx.sources.get(p.arn).filter(([pol]) => pol.kind === 'customer-managed' && pol.arn).map(([pol]) => pol.arn)));
      } else if (primary === 'lambda:UpdateFunctionCode') {
        notes.push('Lambda function inventory is not part of an IAM export; impact depends on the execution roles of existing functions.');
        return ['HIGH', 'conditional', [], false, notes];
      }
      const hits = targets.filter((t) => ps.evaluate(primary, t).allowed);
      if (hits.length) return ['CRITICAL', 'confirmed', hits, true, notes];
      if (ps.evaluate(primary).allowed && ps.evaluate(primary).global_scope) {
        notes.push("Not directly applicable to its own identity, but can modify other principals' permissions.");
        return ['HIGH', 'latent', [], false, notes];
      }
      return null;
    }
    if (m.target === 'roles') {
      const roles = ctx.account.roles().filter((r) => ps.evaluate(primary, r.arn).allowed && r.arn !== p.arn).map((r) => r.arn);
      if (!roles.length) return null;
      if (primary === 'iam:UpdateAssumeRolePolicy') {
        const toAdmin = roles.filter((r) => adminRoles.has(r));
        return ['CRITICAL', 'confirmed', roles, toAdmin.length > 0, notes];
      }
      const assumable = roles.filter((r) => ctx.canAssume(p.arn, r));
      if (assumable.length) return ['CRITICAL', 'confirmed', assumable, true, notes];
      notes.push('Can grant admin to roles but cannot currently assume them; any principal/workload using those roles becomes admin.');
      return ['HIGH', 'latent', roles, false, notes];
    }
    if (m.target === 'users') {
      const users = ctx.account.users().filter((u) => u.arn !== p.arn && ps.evaluate(primary, u.arn).allowed).map((u) => u.arn);
      if (!users.length) return null;
      const admins = users.filter((u) => ctx.isAdmin(u));
      return [admins.length ? 'CRITICAL' : 'HIGH', 'confirmed', users, admins.length > 0, notes];
    }
    if (m.target === 'groups') {
      if (p.kind !== 'user') return null;
      const groups = ctx.account.groups().filter((g) => ps.evaluate(primary, g.arn).allowed && !p.group_arns.includes(g.arn)).map((g) => g.arn);
      if (!groups.length) {
        if (ps.evaluate(primary).global_scope) return ['HIGH', 'latent', [], false, ['No other groups exist yet; any future privileged group is joinable.']];
        return null;
      }
      const admins = groups.filter((g) => ctx.isAdmin(g));
      return [admins.length ? 'CRITICAL' : 'HIGH', 'confirmed', groups, admins.length > 0, notes];
    }
    if (m.target === 'instances') {
      const roles = ctx.account.roles().filter((r) => r.instance_profiles.length).map((r) => r.arn);
      if (!roles.length) return ['MEDIUM', 'latent', [], false, ['No instance profiles found in export.']];
      const admins = roles.filter((r) => adminRoles.has(r));
      notes.push('EC2 inventory is not part of an IAM export; assumes instances using these instance profiles are SSM-managed.');
      return [admins.length ? 'CRITICAL' : 'HIGH', 'conditional', roles, admins.length > 0, notes];
    }
    return null;
  }
  function escalationStory(m, p, targets, toAdmin) {
    const tn = targets.slice(0, 4).map(shortArn).join(', ') || 'a privileged role/policy';
    if (m.id === 'PRIV-015') return `1) ${p.name} calls lambda:CreateFunction with --role pointing at ${tn} (allowed by iam:PassRole on that ARN). 2) The function code reads AWS_ACCESS_KEY_ID/SECRET/SESSION_TOKEN from its environment or calls IAM directly. 3) Once invoked, the attacker operates with the execution role's privileges` + (toAdmin ? ' - full administrator.' : '.');
    if (m.id === 'PRIV-014') return `1) ${p.name} runs ec2:RunInstances with an instance profile for ${tn}. 2) User-data or SSH retrieves credentials from IMDS (169.254.169.254). 3) Attacker acts as that role` + (toAdmin ? ' (administrator).' : '.');
    if (m.target === 'self') return `${p.name} uses ${m.requires[0][0]} against ${tn} to grant itself Action:* on Resource:* - instant administrator.`;
    if (m.target === 'users') return `${p.name} uses ${m.requires[0][0]} on ${tn} and then authenticates as that user` + (toAdmin ? ' (an administrator).' : '.');
    if (m.target === 'roles') return `${p.name} modifies ${tn} (${m.requires[0][0]}) and assumes it with the new permissions.`;
    return m.description;
  }
  function escalationFix(m) {
    if (m.target === 'passrole') return `Scope iam:PassRole to the exact execution role ARN(s) and add Condition StringEquals iam:PassedToService = ${m.pass_to_service}; scope the compute action to a function/instance naming prefix.`;
    if (m.target === 'self') return `Remove ${m.requires[0][0]} or scope it away from the identity's own ARN and policies; enforce a permissions boundary.`;
    return `Remove ${m.requires[0][0]} or restrict Resource to specific, non-privileged targets; enforce permissions boundaries.`;
  }

  function detectStale(ctx) {
    const out = [], n = ctx.stale_days, noTelUsers = [], noTelRoles = [];
    const mk = (rule, title, sev, ident, desc, attack, rec, mitre = ['T1078.004']) => finding({ rule_id: rule, title, severity: sev, category: 'Stale / Unused Identity',
      description: desc, attack_scenario: attack, recommendation: rec, identity_arns: [ident.arn], identity_names: [ident.name], mitre: [...mitre] });
    for (const ident of ctx.principals()) {
      const privileged = ctx.isAdmin(ident.arn) || !!(ctx.sensitiveAllowed(ident.arn)['privilege-escalation'] || []).length;
      const created = ctx.daysSince(ident.create_date);
      const sv = privileged ? 'HIGH' : 'MEDIUM';
      if (ident.kind === 'role') {
        if (ident.path.startsWith('/aws-service-role/')) continue;
        if (!ident.telemetry.role_last_used) { noTelRoles.push(ident.name); continue; }
        const days = ctx.daysSince(ident.last_used);
        if (days === null && (created || 0) > n) {
          out.push(mk('STALE-001', `Role never used (${created} days since creation)`, sv, ident, `RoleLastUsed is empty and the role was created ${created} days ago.`,
            'Unused roles keep their trust relationships and permissions alive - a forgotten door for attackers.', 'Delete the role or remove its policies after confirming with the owner.'));
        } else if (days !== null && days > n) {
          out.push(mk('STALE-001', `Role unused for ${days} days`, sv, ident, `Last used ${ymd(ident.last_used)} in ${ident.last_used_region || 'unknown region'} (${days} days > ${n} day threshold).`,
            'Dormant privileged roles are rarely monitored; their use by an attacker is less likely to be noticed.', 'Remove or deactivate the role; if still needed, document an owner and review date.'));
        }
      } else {
        if (!(ident.telemetry.password_last_used || ident.telemetry.credential_report)) { noTelUsers.push(ident.name); continue; }
        if (ident.password_enabled !== false && ident.password_last_used) {
          const d = ctx.daysSince(ident.password_last_used);
          if (d !== null && d > n) out.push(mk('STALE-002', `Console password unused for ${d} days`, sv, ident, `PasswordLastUsed ${ymd(ident.password_last_used)} (${d} days).`,
            'Dormant console credentials are prime targets for password spraying; nobody notices the login.', 'Delete the login profile (aws iam delete-login-profile) or disable the user.'));
        }
        if (ident.password_enabled && ident.mfa_active === false) {
          out.push(mk('STALE-004', 'Console user without MFA', sv, ident, 'Credential report shows password_enabled=true and mfa_active=false.',
            'A phished or reused password alone grants console access.', 'Enforce MFA (deny-without-MFA policy) and register a device.'));
        }
        for (const k of ident.access_keys) {
          if (!k.active) continue;
          const used = ctx.daysSince(k.last_used), rotated = ctx.daysSince(k.last_rotated);
          if (used === null && (rotated || 0) > n) {
            out.push(mk('STALE-003', `Active access key never used (${rotated} days old)`, sv, ident, `${k.key_id} is active, created ${rotated} days ago and never used.`,
              'Unused long-lived keys are pure risk: if leaked (git, CI logs) they work and nobody will miss them.', 'Deactivate and delete the key.', ['T1078.004', 'T1098.001']));
          } else if (used !== null && used > n) {
            out.push(mk('STALE-003', `Access key unused for ${used} days`, sv, ident, `${k.key_id} last used ${used} days ago.`, 'Dormant keys extend the attack surface.',
              'Deactivate, then delete after a grace period.', ['T1078.004', 'T1098.001']));
          }
          if (rotated !== null && rotated > n && used !== null && used <= n) {
            out.push(mk('STALE-005', `Access key not rotated for ${rotated} days`, privileged ? 'MEDIUM' : 'LOW', ident, `${k.key_id} was last rotated ${rotated} days ago (> ${n}).`,
              'Old keys have had more opportunities to leak.', 'Rotate the key or migrate to short-lived role credentials (IAM Identity Center / OIDC).', ['T1098.001']));
          }
        }
      }
    }
    if (noTelUsers.length || noTelRoles.length) {
      const who = [];
      if (noTelUsers.length) who.push(`${noTelUsers.length} user(s): ${noTelUsers.join(', ')}`);
      if (noTelRoles.length) who.push(`${noTelRoles.length} role(s): ${noTelRoles.join(', ')}`);
      out.push(finding({ rule_id: 'TELEM-001', title: 'Usage telemetry absent - dormancy cannot be assessed for some identities', severity: 'INFO', category: 'Stale / Unused Identity',
        description: 'The export has no PasswordLastUsed / credential report data for ' + who.join('; ') + '. get-account-authorization-details does not include user login or access-key activity.',
        attack_scenario: 'Unused credentials cannot be distinguished from active ones without telemetry.',
        recommendation: 'Run `python cli.py collect` (adds the IAM credential report) or merge `aws iam get-credential-report` output into the export under the key "CredentialReport".',
        identity_names: [...noTelUsers, ...noTelRoles], exploitability: 'informational' }));
    }
    return out;
  }

  function detectHygiene(ctx, prior) {
    const out = [];
    const risky = new Set(prior.filter((f) => RANK[f.severity] >= 3).flatMap((f) => f.identity_arns));
    for (const u of ctx.account.users()) {
      const inl = u.policy_keys.filter((k) => k.startsWith('inline:') && ctx.policies.has(k)).map((k) => ctx.policies.get(k));
      if (inl.length) {
        out.push(finding({ rule_id: 'HYG-001', title: 'Permissions granted through inline user policy', severity: 'LOW', category: 'Hygiene',
          description: `${u.name} has inline policies: ${inl.map((p) => p.name).join(', ')}. Inline user policies are invisible in policy inventories, cannot be reused or versioned, and bypass group-based access reviews.`,
          attack_scenario: 'Attackers favour inline policies for persistence because they are easy to overlook.',
          recommendation: 'Move permissions to a versioned customer-managed policy attached to a group or role.',
          identity_arns: [u.arn], identity_names: [u.name], policy_name: inl.map((p) => p.name).join(', '), policy_key: inl[0].key, policy_kind: 'inline', mitre: ['T1098'], exploitability: 'informational' }));
      }
    }
    for (const p of ctx.principals()) {
      const age = ctx.daysSince(p.create_date);
      if (age !== null && age <= 7 && (ctx.isAdmin(p.arn) || risky.has(p.arn)) && !isServiceRole(p)) {
        out.push(finding({ rule_id: 'HYG-002', title: `Recently created privileged ${p.kind} (created ${age === 0 ? '< 24 hours' : `${age} day(s)`} ago)`, severity: 'MEDIUM', category: 'Hygiene',
          description: `${p.name} was created ${ymdhm(p.create_date)} UTC and already holds high-risk permissions.`,
          attack_scenario: 'Creating a new privileged IAM user/role is a classic persistence technique after initial compromise (T1136.003). Confirm it maps to an approved change ticket.',
          recommendation: 'Verify the creator in CloudTrail (CreateUser/CreateRole events) and the business justification.',
          identity_arns: [p.arn], identity_names: [p.name], mitre: ['T1136.003'], exploitability: 'informational' }));
      }
      if (p.kind === 'user' && ctx.isAdmin(p.arn)) {
        out.push(finding({ rule_id: 'HYG-003', title: 'Administrator is a long-lived IAM user', severity: 'HIGH', category: 'Hygiene',
          description: `${p.name} is an IAM user with full administrator rights. IAM users carry long-lived credentials (password / access keys).`,
          attack_scenario: 'Leaked access keys of an admin IAM user never expire; MFA cannot be enforced on API keys without explicit conditions.',
          recommendation: "Use IAM Identity Center or an assumable admin role with MFA and short sessions; remove the user's direct admin policy.",
          identity_arns: [p.arn], identity_names: [p.name], mitre: ['T1078.004'] }));
      }
    }
    return out;
  }

  /* ------------------------------------------------------------------ directed graph (networkx-compatible ordering) */
  class DiGraph {
    constructor() { this.nodes = new Map(); this.succ = new Map(); this.pred = new Map(); }
    has(n) { return this.nodes.has(n); }
    addNode(n, attrs = {}) {
      if (!this.nodes.has(n)) { this.nodes.set(n, {}); this.succ.set(n, new Map()); this.pred.set(n, new Map()); }
      Object.assign(this.nodes.get(n), attrs);
    }
    addEdge(u, v, attrs = {}) {
      this.addNode(u); this.addNode(v);
      const ex = this.succ.get(u).get(v);
      if (ex) Object.assign(ex, attrs);
      else { const d = { ...attrs }; this.succ.get(u).set(v, d); this.pred.get(v).set(u, d); }
    }
    hasEdge(u, v) { return this.succ.has(u) && this.succ.get(u).has(v); }
    edge(u, v) { return this.succ.get(u).get(v); }
    *edges() { for (const [u, nb] of this.succ) for (const [v, d] of nb) yield [u, v, d]; }
    outDegree(n) { return this.succ.get(n).size; }
  }
  function traversable(G) {
    const H = new DiGraph();
    for (const [n, d] of G.nodes) H.addNode(n, d);
    for (const [u, v, d] of G.edges()) if (!d.inert) H.addEdge(u, v, d);
    return H;
  }
  function descendants(H, s, allow) {
    const seen = new Set(), q = [s];
    while (q.length) { const u = q.shift(); for (const v of H.succ.get(u).keys()) if (!seen.has(v) && (!allow || allow(v))) { seen.add(v); q.push(v); } }
    seen.delete(s);
    return seen;
  }
  function shortestPath(H, source, target) { // networkx bidirectional BFS (same tie-breaking)
    if (source === target) return [source];
    const pred = new Map([[source, null]]), succ = new Map([[target, null]]);
    let ff = [source], rf = [target], w = null;
    outer: while (ff.length && rf.length) {
      if (ff.length <= rf.length) {
        const level = ff; ff = [];
        for (const v of level) for (const x of H.succ.get(v).keys()) {
          if (!pred.has(x)) { ff.push(x); pred.set(x, v); }
          if (succ.has(x)) { w = x; break outer; }
        }
      } else {
        const level = rf; rf = [];
        for (const v of level) for (const x of H.pred.get(v).keys()) {
          if (!succ.has(x)) { succ.set(x, v); rf.push(x); }
          if (pred.has(x)) { w = x; break outer; }
        }
      }
    }
    if (w === null) return null;
    const path = [];
    for (let x = w; x !== null; x = pred.get(x)) path.push(x);
    path.reverse();
    for (let x = succ.get(w); x !== null; x = succ.get(x)) path.push(x);
    return path;
  }

  const CROWN = 'crown:admin';
  const PATH_EDGE_ACTIONS = new Set(['sts:AssumeRole', 'sts:AssumeRoleWithWebIdentity', 'iam:PassRole']);
  const BROAD_SERVICE_COLLAPSE = 12;
  const TRAVERSAL_SOURCES = new Set(['user', 'external', 'anyone', 'federated', 'service']);
  const HIGH_VALUE_CATS = ['credential-access', 'data-read', 'data-write', 'data-destruction', 'privilege-escalation', 'code-execution', 'permissions-management', 'defense-evasion'];
  const HVC = new Set(HIGH_VALUE_CATS);
  const PASS_METHODS = new Set(['PRIV-014', 'PRIV-015', 'PRIV-017', 'PRIV-018', 'PRIV-019', 'PRIV-020', 'PRIV-021']);
  const blockedFor = (action, permsets) => { const pr = probeAction(action); return permsets.every((ps) => { const d = ps.evaluate(pr); return !d.allowed && d.hard_denies.length > 0; }); };
  const shortLabel = (arn) => { if (arn === '*') return '*'; const t = arn.split(':').pop(); return t.length < 40 ? t : t.slice(0, 37) + '…'; };

  function buildGraph(ctx, escalations, findings) {
    const G = new DiGraph(), acct = ctx.account.account_id;
    const sevIdent = {}, sevPol = {};
    for (const f of findings) {
      for (const a of f.identity_arns) if (RANK[f.severity] > RANK[sevIdent[a] || 'INFO']) sevIdent[a] = f.severity;
      if (f.policy_key && RANK[f.severity] > RANK[sevPol[f.policy_key] || 'INFO']) sevPol[f.policy_key] = f.severity;
    }
    const riskOf = (s) => (s === 'CRITICAL' ? 'critical' : s === 'HIGH' || s === 'MEDIUM' ? 'warning' : 'normal');
    G.addNode(CROWN, { label: 'FULL ACCOUNT CONTROL', type: 'crown', risk: 'critical', tier: 7, detail: { description: `Administrator-equivalent control of AWS account ${acct}` } });
    for (const ident of ctx.identities.values()) {
      const sev = sevIdent[ident.arn] || 'INFO';
      G.addNode(ident.arn, { label: ident.name, type: ident.kind, risk: ctx.isAdmin(ident.arn) ? 'critical' : riskOf(sev), tier: { user: 1, group: 2, role: 3 }[ident.kind], arn: ident.arn, severity: sev });
    }
    for (const ident of ctx.account.users()) for (const g of ident.group_arns) G.addEdge(ident.arn, g, { type: 'member_of', label: 'member of' });
    const used = new Set([...ctx.identities.values()].flatMap((i) => i.policy_keys));
    for (const pk of used) {
      const pol = ctx.policies.get(pk);
      if (!pol) continue;
      G.addNode(pk, { label: pol.name, type: 'policy', kind: pol.kind, risk: riskOf(sevPol[pk] || 'INFO'), tier: 4, arn: pol.arn, severity: sevPol[pk] || 'INFO' });
      const holderPs = (ctx.holders.get(pk) || []).filter((a) => ctx.perms.has(a)).map((a) => ctx.perms.get(a));
      for (const st of pol.statements) {
        if (!st.isAllow) { G.nodes.get(pk).has_deny = true; continue; }
        const glob = stmtIsGlobal(st);
        const extra = { conditional: strongCondition(st.condition).length > 0 };
        if (st.actions.length && holderPs.length && st.actions.every((a) => blockedFor(a, holderPs))) Object.assign(extra, { blocked: true, inert: true });
        if ((st.actions.includes('*') && glob) || (st.not_actions.length && !st.not_actions.some((p) => actionMatch(p, 'iam:CreateUser')) && glob)) {
          G.addEdge(pk, CROWN, { type: 'grants', label: `${st.label}: Action * / Resource *`, actions: ['*'], sid: st.label, cats: sorted(HIGH_VALUE_CATS), tcats: [], ...extra });
          continue;
        }
        if (st.not_actions.length) {
          const rid = `res:notaction:${pk}:${st.index}`;
          G.addNode(rid, { label: `All services except ${st.not_actions.join(', ').slice(0, 40)}`, type: 'resource', risk: 'warning', tier: 6, sensitive: true, cats: sorted(HIGH_VALUE_CATS), services: ['*'], global_scope: glob });
          G.addEdge(pk, rid, { type: 'grants', label: `${st.label}: NotAction`, actions: st.not_actions.map((a) => `NotAction:${a}`), sid: st.label, cats: sorted(HIGH_VALUE_CATS), tcats: sorted(HIGH_VALUE_CATS), ...extra });
          continue;
        }
        const bySvc = new Map();
        for (const a of st.actions) { const s = a.includes(':') ? a.split(':')[0] : a; if (!bySvc.has(s)) bySvc.set(s, []); bySvc.get(s).push(a); }
        const rd = st.resourceDisplay();
        const resLabel = rd.slice(0, 2).map(shortLabel).join(', ') + (rd.length > 2 ? '…' : '');
        const groups = bySvc.size > BROAD_SERVICE_COLLAPSE ? [['broad', [...bySvc.values()].flat()]] : [...bySvc];
        for (const [svc, acts] of groups) {
          const aidx = actionIndex(acts), hitKeys = SENS_KEYS.filter((s) => aidx.test(s));
          const cats = sorted(uniq(hitKeys.map((s) => SENS[s])));
          let rid, label;
          if (svc === 'broad') { rid = `res:broad:${pk}:${st.index}`; label = `${bySvc.size} services (${acts.length} actions) · ${resLabel}`; }
          else { rid = `res:${svc}:${sorted(rd).join('|')}`; label = `${svc} · ${resLabel}`; }
          if (!G.has(rid)) G.addNode(rid, { label, type: 'resource', risk: 'resource', tier: 6, sensitive: cats.length > 0, cats, services: svc === 'broad' ? sorted([...bySvc.keys()]) : [svc], global_scope: glob, resources: rd });
          else { const nd = G.nodes.get(rid); nd.cats = sorted(uniq([...nd.cats, ...cats])); nd.sensitive = nd.cats.length > 0; }
          const tcats = sorted(uniq(hitKeys.filter((s) => !PATH_EDGE_ACTIONS.has(s)).map((s) => SENS[s])));
          const ordered = [...acts.filter(isSensitivePattern), ...acts.filter((a) => !isSensitivePattern(a))];
          const elabel = `${st.label}: ${ordered.slice(0, 3).join(', ')}${acts.length > 3 ? '…' : ''}`;
          if (G.hasEdge(pk, rid)) {
            const ed = G.edge(pk, rid);
            ed.cats = sorted(uniq([...ed.cats, ...cats]));
            if (!extra.blocked) ed.tcats = sorted(uniq([...ed.tcats, ...tcats]));
            ed.actions = [...ed.actions, ...acts].slice(0, 50);
            if (!extra.blocked) { delete ed.blocked; delete ed.inert; }
          } else {
            G.addEdge(pk, rid, { type: 'grants', label: elabel, actions: acts.slice(0, 50), sid: st.label, cats, tcats: extra.blocked ? [] : tcats, ...extra });
          }
        }
      }
    }
    for (const ident of ctx.identities.values()) for (const pk of ident.policy_keys) if (G.has(pk)) G.addEdge(ident.arn, pk, { type: 'has_policy', label: pk.startsWith('inline:') ? 'inline' : 'attached' });
    for (const role of ctx.account.roles()) {
      for (const t of ctx.trusts.get(role.arn) || []) {
        const nid = t.nodeId;
        if (!G.has(nid)) {
          if (t.kind === 'anyone') G.addNode(nid, { label: 'ANY AWS PRINCIPAL (*)', type: 'anyone', risk: 'critical', tier: 0 });
          else if (t.kind === 'service') G.addNode(nid, { label: t.value, type: 'service', risk: 'normal', tier: 0 });
          else if (t.kind === 'federated') G.addNode(nid, { label: t.value.split('/').pop(), type: 'federated', risk: 'warning', tier: 0, arn: t.value });
          else if (t.kind === 'aws-account') { const ext = t.account !== acct; G.addNode(nid, { label: `${ext ? 'External' : 'This'} account ${t.account}`, type: ext ? 'external' : 'account', risk: ext ? 'warning' : 'normal', tier: 0, account: t.account }); }
          else G.addNode(nid, { label: shortLabel(t.value), type: t.external ? 'external' : 'principal', risk: t.external ? 'warning' : 'normal', tier: 0, arn: t.value });
        }
        if (!(t.kind === 'aws-account' && t.account === acct)) G.addEdge(nid, role.arn, { type: 'trusts', label: 'can assume (trust)', sid: t.statement.label, conditional: hasKeys(t.statement.condition) });
        else G.addEdge(nid, role.arn, { type: 'trusts', label: 'trusts account root', sid: t.statement.label, inert: true });
      }
    }
    for (const e of ctx.assumeEdges()) G.addEdge(e.source, e.role, { type: 'can_assume', label: 'sts:AssumeRole' });
    for (const esc of escalations) {
      const eid = `esc:${esc.method}:${esc.source}`, latent = esc.exploitability === 'latent';
      G.addNode(eid, { label: esc.name, type: 'escalation', risk: esc.severity === 'CRITICAL' ? 'critical' : 'warning', tier: 5, latent, method: esc.method, severity: esc.severity, exploitability: esc.exploitability });
      G.addEdge(esc.source, eid, { type: 'escalates', label: esc.method, latent });
      for (const t of esc.targets) if (G.has(t)) G.addEdge(eid, t, { type: 'escalates', label: PASS_METHODS.has(esc.method) ? 'pass role' : 'modify', latent });
      if (esc.to_admin && !esc.targets.some((t) => ctx.isAdmin(t))) G.addEdge(eid, CROWN, { type: 'escalates', label: 'grants self admin', latent });
    }
    return G;
  }
  function edgeSeverity(cats, glob) {
    const c = cats.filter((x) => HVC.has(x));
    if (!c.length) return null;
    let sev = maxSev(c.map((x) => C.CATEGORIES[x].severity));
    if (glob && (c.includes('data-destruction') || c.includes('data-write')) && c.includes('data-read')) sev = 'HIGH';
    return sev;
  }
  function stableSort(xs, cmp) { return xs.map((x, i) => [x, i]).sort((a, b) => cmp(a[0], b[0]) || a[1] - b[1]).map((x) => x[0]); }

  function findAttackPaths(G, maxPerSource = 4) {
    const H = traversable(G);
    const sources = [...H.nodes].filter(([, d]) => TRAVERSAL_SOURCES.has(d.type)).map(([n]) => n);
    const grantTargets = [...H.edges()].filter(([, v, d]) => d.type === 'grants' && v !== CROWN && edgeSeverity(d.tcats || [], !!H.nodes.get(v).global_scope));
    const latentEsc = [...H.nodes].filter(([n, d]) => d.type === 'escalation' && d.latent && H.outDegree(n) === 0).map(([n]) => n);
    const paths = [];
    const mk = (s, nodes, sev, target) => {
      const edges = nodes.slice(1).map((v, i) => [nodes[i], v]);
      const latent = nodes.some((n) => H.nodes.get(n).latent);
      if (latent && sev === 'CRITICAL') sev = 'HIGH';
      const stype = H.nodes.get(s).type;
      const firstCond = edges.length > 0 && !!H.edge(...edges[0]).conditional;
      if (['anyone', 'external', 'federated'].includes(stype) && !firstCond) sev = upgrade(sev);
      else if (stype === 'service') sev = downgrade(sev);
      if (edges.some((e) => H.edge(...e).type === 'grants' && H.edge(...e).conditional)) sev = downgrade(sev);
      const etypes = edges.map((e) => H.edge(...e).type);
      return {
        source: s, target, nodes, edges: edges.map(([u, v]) => `${u}->${v}`), hops: edges.length, severity: sev, exploitability: latent ? 'latent' : 'confirmed',
        multi_hop: etypes.some((x) => ['member_of', 'can_assume', 'escalates', 'trusts'].includes(x)),
        source_label: H.nodes.get(s).label, target_label: H.nodes.get(target).label,
        steps: nodes.map((n, i) => ({ id: n, label: H.nodes.get(n).label, type: H.nodes.get(n).type, via: i ? H.edge(nodes[i - 1], n).label : null })),
      };
    };
    for (const s of sources) {
      const reach = descendants(H, s);
      if (reach.has(CROWN)) { paths.push(mk(s, shortestPath(H, s, CROWN), 'CRITICAL', CROWN)); continue; }
      let found = [];
      const seen = new Set();
      for (const [u, v, d] of grantTargets) {
        if (!reach.has(u) || seen.has(v)) continue;
        const sev = edgeSeverity(d.tcats, !!H.nodes.get(v).global_scope);
        found.push(mk(s, [...shortestPath(H, s, u), v], sev, v));
        seen.add(v);
      }
      for (const e of latentEsc) if (reach.has(e)) found.push(mk(s, shortestPath(H, s, e), 'HIGH', e));
      found = stableSort(found, (a, b) => (RANK[b.severity] - RANK[a.severity]) || (a.hops - b.hops));
      paths.push(...found.slice(0, maxPerSource));
    }
    const out = stableSort(paths, (a, b) => (RANK[b.severity] - RANK[a.severity]) || (b.hops - a.hops));
    out.forEach((p, i) => {
      p.id = `PATH-${String(i + 1).padStart(3, '0')}`;
      p.narrative = p.steps.map((st) => (!st.via ? `${st.label}` : `[${st.via}] ${st.label}`)).join(' → ');
    });
    return out;
  }
  function pathFindings(paths) {
    return paths.filter((p) => p.multi_hop && RANK[p.severity] >= 3 && p.hops >= 2).map((p) => finding({
      rule_id: 'PATH-001', title: `Multi-hop attack path: ${p.source_label} → ${p.target_label} (${p.hops} hops)`, severity: p.severity, category: 'Attack Path',
      description: 'Graph traversal found an indirect route: ' + p.narrative,
      attack_scenario: "Each hop is individually 'reasonable'; chained together they give the source principal the target capability.",
      recommendation: 'Break the weakest link: narrow the trust/assume permission, remove the escalation primitive, or scope the final grant.',
      identity_arns: p.source.startsWith('arn:') ? [p.source] : [], identity_names: [p.source_label], exploitability: p.exploitability,
      mitre: ['T1078.004', 'T1098.003'], notes: [`Path id ${p.id}`] }));
  }

  function blastRadius(ctx, H, arn, findings) {
    const ident = ctx.identities.get(arn);
    const reach = H.has(arn) ? descendants(H, arn) : new Set();
    const adminDirect = ctx.isAdmin(arn);
    const adminPath = !adminDirect && reach.has(CROWN) && !H.nodes.get(arn).latent && descendants(H, arn, (n) => !H.nodes.get(n).latent).has(CROWN);
    const roles = [...reach].filter((n) => H.nodes.get(n).type === 'role');
    const cats = {};
    for (const who of [arn, ...roles]) for (const [c, acts] of Object.entries(ctx.sensitiveAllowed(who))) { cats[c] = cats[c] || new Set(); acts.forEach((a) => cats[c].add(a)); }
    const services = new Set(Object.values(cats).flatMap((s) => [...s]).map((a) => a.split(':')[0]));
    const factors = [];
    if (adminDirect) factors.push(['Administrator privileges', 80, 'Action * on Resource * (direct)']);
    else if (adminPath) factors.push(['Administrator via attack path', 75, 'Reaches FULL ACCOUNT CONTROL through graph traversal']);
    else {
      const pts = Math.min(50, Object.keys(cats).reduce((a, c) => a + C.CATEGORIES[c].weight, 0));
      if (pts) factors.push(['Sensitive capabilities', pts, sorted(Object.keys(cats)).map((c) => C.CATEGORIES[c].label).join(', ')]);
      const b = Math.min(10, 2 * services.size);
      if (b) factors.push(['Sensitive service breadth', b, `${services.size} services: ${sorted([...services]).slice(0, 8).join(', ')}`]);
    }
    const mine = findings.filter((f) => f.identity_arns.includes(arn));
    const rules = new Set(mine.map((f) => f.rule_id));
    const esc = mine.filter((f) => f.category === 'Privilege Escalation');
    if (esc.length && !adminDirect && !adminPath) {
      const latent = esc.every((f) => f.exploitability === 'latent');
      factors.push(['Privilege escalation primitive', latent ? 8 : 12, sorted(uniq(esc.map((f) => f.rule_id))).join(', ')]);
    }
    if (ident.kind === 'role') {
      let exp = 0; const why = [];
      const weights = { 'TRUST-001': 20, 'TRUST-007': 20, 'TRUST-002': 15, 'TRUST-005': 15, 'TRUST-003': 5 };
      for (const f of mine) {
        let w = weights[f.rule_id];
        if (w) { if (f.rule_id === 'TRUST-001' && f.severity !== 'CRITICAL') w = 10; exp = Math.max(exp, w); why.push(f.title); }
      }
      if (exp) factors.push(['Cross-account / external exposure', exp, why.slice(0, 3).join('; ')]);
    } else if (ident.kind === 'user' && (ident.policy_keys.length || ident.group_arns.length)) factors.push(['Long-lived user credentials', 5, 'IAM user (password / access keys)']);
    if (['ADMIN-001', 'WILD-002', 'RES-001', 'WILD-004'].some((r) => rules.has(r)) && !adminDirect) factors.push(['Wildcard resource scope', 10, 'Sensitive actions on Resource "*"']);
    else if (adminDirect) factors.push(['Wildcard resource scope', 10, 'Resource "*"']);
    if (['HYG-002', 'STALE-001', 'STALE-002', 'STALE-003'].some((r) => rules.has(r))) factors.push(['Identity hygiene', 5, 'recently created privileged / dormant credentials']);
    const score = Math.min(100, factors.reduce((a, f) => a + f[1], 0));
    const level = score >= 80 ? 'CRITICAL' : score >= 55 ? 'HIGH' : score >= 30 ? 'MEDIUM' : 'LOW';
    return {
      score, level, factors: factors.map(([factor, points, detail]) => ({ factor, points, detail })),
      reachable_roles: roles.map((r) => H.nodes.get(r).label), sensitive_services: sorted([...services]),
      capabilities: Object.fromEntries(Object.entries(cats).map(([c, v]) => [C.CATEGORIES[c].label, sorted([...v]).slice(0, 25)])),
      admin: adminDirect || adminPath, admin_via_path: adminPath,
    };
  }
  function toCytoscape(G, paths) {
    const pn = {}, pe = {};
    for (const p of paths) { p.nodes.forEach((n) => (pn[n] = pn[n] || []).push(p.id)); p.edges.forEach((e) => (pe[e] = pe[e] || []).push(p.id)); }
    const nodes = [...G.nodes].map(([n, d]) => { const data = { ...d }; delete data.detail; return { data: { ...data, id: n, paths: pn[n] || [] } }; });
    const edges = [...G.edges()].map(([u, v, d], i) => ({ data: { ...d, id: `e${i}`, source: u, target: v, paths: pe[`${u}->${v}`] || [] } }));
    return { nodes, edges };
  }

  /* ------------------------------------------------------------------ remediation */
  const PLACEHOLDER_RX = /<[A-Z0-9_\-]+>/g;
  const templates = (svc, acct) => (C.RESOURCE_TEMPLATES[svc] || [`arn:aws:${svc}:<REGION>:{acct}:<${svc.toUpperCase().replace(/-/g, '_')}_RESOURCE>`]).map((x) => x.replace('{acct}', acct));
  function sidOf(base, suffix) {
    const pretty = suffix.split(/[-_\s]+/).map((p) => p.slice(0, 1).toUpperCase() + p.slice(1)).join('');
    return ((base || '') + pretty).replace(/[^A-Za-z0-9]/g, '').slice(0, 100) || 'Scoped';
  }
  function mergeCond(cond, add) {
    const out = clone(cond || {});
    for (const [op, kv] of Object.entries(add)) out[op] = Object.assign(out[op] || {}, kv);
    return out;
  }
  function passedServices(ctx, holders) {
    const s = new Set();
    for (const h of holders) for (const [, st] of ctx.sources.get(h.arn) || []) for (const a of st.actions) {
      const pre = a.split(':')[0].toLowerCase();
      if (C.SERVICE_PRINCIPAL_FOR_ACTION_PREFIX[pre] && pre !== 'iam') s.add(C.SERVICE_PRINCIPAL_FOR_ACTION_PREFIX[pre]);
    }
    return sorted([...s]);
  }
  function synthesizePolicy(ctx, policy, holders) {
    const acct = ctx.account.account_id, human = holders.some((h) => h.kind === 'user');
    const changes = [], stmts = [], denyCarve = [], passed = passedServices(ctx, holders);
    for (const st of policy.statements) {
      const raw = clone(st.raw);
      if (!st.isAllow) { stmts.push(raw); continue; }
      const glob = stmtIsGlobal(st);
      if (st.actions.includes('*') && glob) {
        if (human) {
          stmts.push({ Sid: 'AdminOnlyWithRecentMFA', Effect: 'Allow', Action: '*', Resource: '*', Condition: { Bool: { 'aws:MultiFactorAuthPresent': 'true' }, NumericLessThan: { 'aws:MultiFactorAuthAge': '3600' } } });
          changes.push('Admin access now requires an MFA-authenticated session younger than 1 hour (blocks leaked access keys).');
        } else {
          stmts.push({ Sid: 'ScopedAdmin', Effect: 'Allow', Action: '*', Resource: '*', Condition: { StringEquals: { 'aws:RequestedRegion': ['<PRIMARY_REGION>'] } } });
          changes.push('Admin access restricted to the approved region(s).');
        }
        stmts.push({ Sid: 'ProtectSecurityTooling', Effect: 'Deny', Action: [...C.ADMIN_PROTECTION_DENY], Resource: '*' });
        stmts.push({ Sid: 'DenyPrivilegedIdentityCreation', Effect: 'Deny', Action: ['iam:CreateUser', 'iam:CreateAccessKey', 'iam:CreateLoginProfile'], Resource: '*', Condition: { BoolIfExists: { 'aws:MultiFactorAuthPresent': 'false' } } });
        changes.push('Explicit Deny protects CloudTrail, GuardDuty, Config, Security Hub and Access Analyzer from tampering.');
        changes.push('Preferred end-state: delete standing admin; grant an assumable break-glass role / IAM Identity Center permission set.');
        continue;
      }
      if (st.not_actions.length) {
        stmts.push({ Sid: sidOf(st.sid, 'ReadOnlyBaseline'), Effect: 'Allow', Action: ['ec2:Describe*', 's3:ListAllMyBuckets', 's3:GetBucketLocation', 'lambda:List*', 'cloudwatch:Get*', 'cloudwatch:List*', 'cloudwatch:Describe*',
          'logs:Describe*', 'dynamodb:List*', 'dynamodb:Describe*', 'rds:Describe*', 'cloudformation:Describe*', 'cloudformation:List*'], Resource: '*' });
        stmts.push({ Sid: sidOf(st.sid, 'RequiredWrites'), Effect: 'Allow', Action: ['<SERVICE>:<ACTION>'], Resource: [`arn:aws:<SERVICE>:<REGION>:${acct}:<RESOURCE>`], Condition: { StringEquals: { 'aws:ResourceAccount': acct } } });
        stmts.push({ Sid: 'ProtectSecurityTooling', Effect: 'Deny', Action: [...C.ADMIN_PROTECTION_DENY], Resource: '*' });
        changes.push(`NotAction (${st.not_actions.join(', ')}) replaced by an explicit read-only baseline + an allow-list for required writes.`);
        continue;
      }
      const keepOrig = [], keepStar = [], scoped = new Map();
      const addScoped = (svc, xs) => { if (!scoped.has(svc)) scoped.set(svc, []); scoped.get(svc).push(...xs); };
      for (const a of st.actions) {
        const i = a.indexOf(':'), svc = i >= 0 ? a.slice(0, i) : a, verb = i >= 0 ? a.slice(i + 1) : '', sl = svc.toLowerCase();
        if (verb === '*') {
          const wl = C.SERVICE_WORKLOAD_ACTIONS[sl];
          if (wl) {
            if (glob) keepStar.push(...(wl.list || []));
            addScoped(sl, [...(wl.bucket || []), ...(wl.object || [])]);
            changes.push(`${a} replaced by ${(wl.list || []).length + (wl.bucket || []).length + (wl.object || []).length} day-to-day ${svc} actions; admin/destructive APIs (policy, ACL, delete, encryption config) removed.`);
          } else {
            keepStar.push(`${svc}:Describe*`, `${svc}:List*`, `${svc}:Get*`);
            changes.push(`${a} reduced to read-only (${svc}:Describe*/List*/Get*) - add specific write actions if required.`);
          }
        } else if (isWildcard(a)) {
          const hits = SENS_KEYS.filter((s) => actionMatch(a, s));
          keepOrig.push(a);
          if (hits.length) { denyCarve.push(...hits); changes.push(`${a} kept but its sensitive expansions (${hits.slice(0, 4).join(', ')}${hits.length > 4 ? '…' : ''}) are explicitly denied.`); }
        } else if (glob && SENS_LOWER.has(a.toLowerCase()) && !STAR_ONLY.has(a.toLowerCase())) addScoped(sl, [a]);
        else keepOrig.push(a);
      }
      if (keepOrig.length || keepStar.length) {
        const s = clone(raw);
        s.Action = [...keepOrig, ...keepStar.filter((x) => !keepOrig.includes(x))];
        delete s.NotAction;
        stmts.push(s);
      }
      for (let [svc, acts] of scoped) {
        acts = uniq(acts);
        if (svc === 'iam' && acts.some((x) => x.toLowerCase() === 'iam:passrole')) {
          const rest = acts.filter((x) => x.toLowerCase() !== 'iam:passrole');
          const pr = { Sid: sidOf(st.sid, 'PassOnlyApprovedRole'), Effect: 'Allow', Action: 'iam:PassRole', Resource: [`arn:aws:iam::${acct}:role/<APPROVED_EXECUTION_ROLE>`] };
          if (passed.length) {
            pr.Condition = { StringEquals: { 'iam:PassedToService': passed.length > 1 ? passed : passed[0] } };
            changes.push(`iam:PassRole scoped to one execution role and limited to iam:PassedToService = ${passed.join(', ')}.`);
          } else changes.push('iam:PassRole scoped to a single approved role ARN.');
          stmts.push(pr);
          if (!rest.length) continue;
          acts = rest;
        }
        let cond = mergeCond(st.condition, { StringEquals: { 'aws:ResourceAccount': acct } });
        if (human && acts.some((x) => ['privilege-escalation', 'permissions-management'].includes(SENS[x]))) cond = mergeCond(cond, { Bool: { 'aws:MultiFactorAuthPresent': 'true' } });
        let res = templates(svc, acct);
        if (svc === 'lambda' && passed.length === 1 && passed[0] === 'lambda.amazonaws.com') res = [`arn:aws:lambda:<REGION>:${acct}:function:${policy.name.toLowerCase().replace(/[^a-z0-9-]/g, '-')}-*`];
        stmts.push({ Sid: sidOf(st.sid, `Scoped-${svc}`), Effect: 'Allow', Action: acts, Resource: res, Condition: cond });
        changes.push(`${acts.slice(0, 5).join(', ')}${acts.length > 5 ? '…' : ''} moved from Resource "*" to ${res.join(', ')} with aws:ResourceAccount guardrail.`);
      }
    }
    if (denyCarve.length) stmts.push({ Sid: 'DenySensitiveWildcardExpansions', Effect: 'Deny', Action: sorted(uniq(denyCarve)), Resource: '*' });
    if (policy.kind === 'aws-managed') changes.unshift(`AWS-managed policies cannot be edited: this is a customer-managed replacement for ${policy.name}.`);
    return [{ Version: policy.document.Version || '2012-10-17', Statement: stmts }, uniq(changes)];
  }
  function synthesizeTrust(ctx, role) {
    const acct = ctx.account.account_id;
    const doc = clone(role.trust ? role.trust.document : { Version: '2012-10-17', Statement: [] });
    const changes = [], stmts = asList(doc.Statement), entries = parseTrust(role, acct);
    stmts.forEach((raw, i) => {
      const mine = entries.filter((e) => e.statement.index === i);
      if (!mine.length) return;
      let cond = raw.Condition || {};
      for (const e of mine) {
        const keys = e.conditionKeys();
        if (e.kind === 'not-principal') {
          delete raw.NotPrincipal; raw.Principal = { AWS: 'arn:aws:iam::<TRUSTED_ACCOUNT_ID>:role/<TRUSTED_ROLE>' };
          changes.push('NotPrincipal replaced with an explicit trusted role ARN.');
        } else if (e.kind === 'anyone') {
          raw.Principal = { AWS: 'arn:aws:iam::<TRUSTED_ACCOUNT_ID>:role/<TRUSTED_ROLE>' };
          cond = mergeCond(cond, { StringEquals: { 'aws:PrincipalOrgID': '<o-ORGANIZATION_ID>' } });
          changes.push('Wildcard principal "*" replaced with an explicit role ARN and pinned to your AWS Organization (aws:PrincipalOrgID).');
        } else if ((e.kind === 'aws-account' || e.kind === 'aws-principal') && e.external && !keys.has('sts:externalid')) {
          const ext = uuid5Url(role.arn + e.value);
          cond = mergeCond(cond, { StringEquals: { 'sts:ExternalId': ext } });
          changes.push(`Added sts:ExternalId = ${ext} for ${e.value} (share it with the third party out-of-band).`);
          if (e.kind === 'aws-account') {
            raw.Principal = { AWS: `arn:aws:iam::${e.account}:role/<VENDOR_INTEGRATION_ROLE>` };
            changes.push(`Account root of ${e.account} narrowed to a single vendor integration role.`);
          }
        } else if (e.kind === 'aws-account' && e.account === acct && ctx.isAdmin(role.arn)) {
          raw.Principal = { AWS: `arn:aws:iam::${acct}:role/<APPROVED_ADMIN_CALLER>` };
          cond = mergeCond(cond, { Bool: { 'aws:MultiFactorAuthPresent': 'true' } });
          changes.push('Own-account root trust narrowed to one approved caller with MFA.');
        } else if (e.kind === 'federated') {
          const prov = e.value.split('oidc-provider/').pop(), host = prov.split('/')[0];
          if (C.OIDC_SUBJECT_KEYS[host] && !keys.has(`${prov}:sub`.toLowerCase())) {
            const [k, v] = C.OIDC_SUBJECT_KEYS[host];
            cond = mergeCond(cond, { StringEquals: { [`${prov}:aud`]: 'sts.amazonaws.com' }, StringLike: { [k]: v } });
            changes.push(`OIDC trust pinned to audience sts.amazonaws.com and subject ${v}.`);
          } else if (prov.includes('cognito-identity') && !keys.has('cognito-identity.amazonaws.com:aud')) {
            cond = mergeCond(cond, { StringEquals: { 'cognito-identity.amazonaws.com:aud': '<IDENTITY_POOL_ID>' }, 'ForAnyValue:StringLike': { 'cognito-identity.amazonaws.com:amr': 'authenticated' } });
            changes.push('Cognito trust pinned to one identity pool (authenticated users only).');
          } else if (e.value.includes('saml-provider/') && !keys.has('saml:aud')) {
            cond = mergeCond(cond, { StringEquals: { 'SAML:aud': 'https://signin.aws.amazon.com/saml' } });
            changes.push('SAML trust pinned to the AWS sign-in audience.');
          }
        } else if (e.kind === 'service' && !keys.has('aws:sourceaccount') && !keys.has('aws:sourcearn')) {
          if (!DEPUTY_SAFE.has(e.value)) {
            cond = mergeCond(cond, { StringEquals: { 'aws:SourceAccount': acct } });
            changes.push(`Added aws:SourceAccount = ${acct} to ${e.value} trust (confused-deputy protection).`);
          }
        }
      }
      if (hasKeys(cond)) raw.Condition = cond;
    });
    doc.Statement = stmts;
    return [doc, uniq(changes)];
  }

  // difflib.SequenceMatcher (autojunk=False, no junk) so diffs match the Python engine line-for-line.
  function opcodes(a, b) {
    const b2j = new Map();
    b.forEach((x, j) => { if (!b2j.has(x)) b2j.set(x, []); b2j.get(x).push(j); });
    const longest = (alo, ahi, blo, bhi) => {
      let bi = alo, bj = blo, bs = 0, j2len = new Map();
      for (let i = alo; i < ahi; i++) {
        const nj = new Map();
        for (const j of b2j.get(a[i]) || []) {
          if (j < blo) continue;
          if (j >= bhi) break;
          const k = (j2len.get(j - 1) || 0) + 1;
          nj.set(j, k);
          if (k > bs) { bi = i - k + 1; bj = j - k + 1; bs = k; }
        }
        j2len = nj;
      }
      while (bi > alo && bj > blo && a[bi - 1] === b[bj - 1]) { bi--; bj--; bs++; }
      while (bi + bs < ahi && bj + bs < bhi && a[bi + bs] === b[bj + bs]) bs++;
      return [bi, bj, bs];
    };
    const queue = [[0, a.length, 0, b.length]], blocks = [];
    while (queue.length) {
      const [alo, ahi, blo, bhi] = queue.pop();
      const [i, j, k] = longest(alo, ahi, blo, bhi);
      if (k) {
        blocks.push([i, j, k]);
        if (alo < i && blo < j) queue.push([alo, i, blo, j]);
        if (i + k < ahi && j + k < bhi) queue.push([i + k, ahi, j + k, bhi]);
      }
    }
    blocks.sort((x, y) => x[0] - y[0] || x[1] - y[1] || x[2] - y[2]);
    const merged = [];
    let [i1, j1, k1] = [0, 0, 0];
    for (const [i2, j2, k2] of blocks) {
      if (i1 + k1 === i2 && j1 + k1 === j2) k1 += k2;
      else { if (k1) merged.push([i1, j1, k1]); [i1, j1, k1] = [i2, j2, k2]; }
    }
    if (k1) merged.push([i1, j1, k1]);
    merged.push([a.length, b.length, 0]);
    const ops = [];
    let i = 0, j = 0;
    for (const [ai, bj, size] of merged) {
      const tag = i < ai && j < bj ? 'replace' : i < ai ? 'delete' : j < bj ? 'insert' : '';
      if (tag) ops.push([tag, i, ai, j, bj]);
      i = ai + size; j = bj + size;
      if (size) ops.push(['equal', ai, i, bj, j]);
    }
    return ops;
  }
  function unifiedDiff(a, b, from, to, n) {
    let codes = opcodes(a, b);
    if (!codes.length) codes = [['equal', 0, 1, 0, 1]];
    codes = codes.map((c) => [...c]);
    if (codes[0][0] === 'equal') { const [t, i1, i2, j1, j2] = codes[0]; codes[0] = [t, Math.max(i1, i2 - n), i2, Math.max(j1, j2 - n), j2]; }
    const L = codes.length - 1;
    if (codes[L][0] === 'equal') { const [t, i1, i2, j1, j2] = codes[L]; codes[L] = [t, i1, Math.min(i2, i1 + n), j1, Math.min(j2, j1 + n)]; }
    const groups = []; let group = [];
    for (let [t, i1, i2, j1, j2] of codes) {
      if (t === 'equal' && i2 - i1 > 2 * n) {
        group.push([t, i1, Math.min(i2, i1 + n), j1, Math.min(j2, j1 + n)]);
        groups.push(group); group = [];
        i1 = Math.max(i1, i2 - n); j1 = Math.max(j1, j2 - n);
      }
      group.push([t, i1, i2, j1, j2]);
    }
    if (group.length && !(group.length === 1 && group[0][0] === 'equal')) groups.push(group);
    const rng = (s, e) => { let beg = s + 1; const len = e - s; if (len === 1) return `${beg}`; if (!len) beg -= 1; return `${beg},${len}`; };
    const out = [];
    groups.forEach((g, gi) => {
      if (gi === 0) out.push(`--- ${from}`, `+++ ${to}`);
      out.push(`@@ -${rng(g[0][1], g[g.length - 1][2])} +${rng(g[0][3], g[g.length - 1][4])} @@`);
      for (const [t, i1, i2, j1, j2] of g) {
        if (t === 'equal') { a.slice(i1, i2).forEach((x) => out.push(' ' + x)); continue; }
        if (t === 'replace' || t === 'delete') a.slice(i1, i2).forEach((x) => out.push('-' + x));
        if (t === 'replace' || t === 'insert') b.slice(j1, j2).forEach((x) => out.push('+' + x));
      }
    });
    return out.join('\n');
  }
  const pyJson = (o) => JSON.stringify(o, null, 2);
  function sideBySide(a, b) {
    const left = pyJson(a).split('\n'), right = pyJson(b).split('\n'), rows = [];
    for (const [tag, i1, i2, j1, j2] of opcodes(left, right)) {
      if (tag === 'equal') { for (let k = 0; k < i2 - i1; k++) rows.push({ t: 'eq', l: left[i1 + k], r: right[j1 + k], ln: i1 + k + 1, rn: j1 + k + 1 }); continue; }
      const n = Math.max(i2 - i1, j2 - j1);
      for (let k = 0; k < n; k++) {
        const li = i1 + k, ri = j1 + k, hasL = li < i2, hasR = ri < j2;
        const t = (hasL && hasR) || tag !== 'replace' ? { replace: 'chg', delete: 'del', insert: 'add' }[tag] : hasL ? 'del' : 'add';
        rows.push({ t, l: hasL ? left[li] : null, r: hasR ? right[ri] : null, ln: hasL ? li + 1 : null, rn: hasR ? ri + 1 : null });
      }
    }
    return { rows, unified: unifiedDiff(left, right, 'original.json', 'least-privilege.json', 2),
      added: rows.filter((r) => r.t === 'add' || r.t === 'chg').length, removed: rows.filter((r) => r.t === 'del' || r.t === 'chg').length };
  }
  const slug = (s) => s.replace(/[^A-Za-z0-9_.-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 80);
  function cliCommands(policy, holders, role, fname, acct) {
    const v = [`aws accessanalyzer validate-policy --policy-type ${role ? 'RESOURCE_POLICY' : 'IDENTITY_POLICY'} --policy-document file://${fname}`];
    if (role) return [...v, `aws iam update-assume-role-policy --role-name ${role.name} --policy-document file://${fname}`];
    const flag = { user: '--user-name', role: '--role-name', group: '--group-name' };
    if (policy.kind === 'inline') {
      const owner = holders.find((h) => h.arn === policy.owner_arn) || holders[0];
      if (!owner) return v;
      return [...v, `aws iam put-${owner.kind}-policy ${flag[owner.kind]} ${owner.name} --policy-name ${policy.name} --policy-document file://${fname}`];
    }
    if (policy.kind === 'customer-managed') {
      return [...v, `aws iam list-policy-versions --policy-arn ${policy.arn}  # delete the oldest non-default version if 5 exist`,
        `aws iam create-policy-version --policy-arn ${policy.arn} --policy-document file://${fname} --set-as-default`];
    }
    const nn = `${policy.name}-LeastPrivilege`, cmds = [...v, `aws iam create-policy --policy-name ${nn} --policy-document file://${fname}`];
    for (const h of holders) {
      if (!h.policy_keys.includes(policy.key)) continue;
      cmds.push(`aws iam attach-${h.kind}-policy ${flag[h.kind]} ${h.name} --policy-arn arn:aws:iam::${acct}:policy/${nn}`);
      cmds.push(`aws iam detach-${h.kind}-policy ${flag[h.kind]} ${h.name} --policy-arn ${policy.arn}`);
    }
    return cmds;
  }
  const verdict = (before, residual) => {
    const b = Math.max(0, ...before.map((f) => RANK[f.severity])), a = Math.max(0, ...residual.map((f) => RANK[f.severity]));
    return { before: BY_RANK[b], after: residual.length ? BY_RANK[a] : 'NONE', residual: residual.map((f) => `${f.severity} ${f.rule_id}: ${f.title}`), improved: a < b || !residual.length };
  };
  function verifyPolicy(ctx, policy, proposed, holders, before) {
    const test = policyFromDocument(policy.key + ':proposed', policy.name, policy.kind === 'aws-managed' ? 'customer-managed' : policy.kind, proposed, { arn: policy.arn });
    const ps = new PermissionSet(test.statements.map((s) => [test, s]));
    return verdict(before, scanPolicy(test, holders, [ps], ctx.account.account_id, null));
  }
  function verifyTrust(ctx, role, proposed, before) {
    const trial = { ...role, trust: policyFromDocument(`trust:${role.arn}`, `${role.name} trust policy`, 'trust', proposed, { owner_arn: role.arn }) };
    const saved = ctx.trusts.get(role.arn) || [];
    ctx.trusts.set(role.arn, parseTrust(trial, ctx.account.account_id));
    try { return verdict(before, detectTrust(ctx, [], [trial]).filter((f) => f.severity !== 'INFO')); }
    finally { ctx.trusts.set(role.arn, saved); }
  }
  function buildRemediations(ctx, findings) {
    const byPolicy = new Map();
    for (const f of findings) if (f.policy_key && f.rule_id !== 'HYG-001') { if (!byPolicy.has(f.policy_key)) byPolicy.set(f.policy_key, []); byPolicy.get(f.policy_key).push(f); }
    const out = [], acct = ctx.account.account_id;
    for (const [key, fs] of byPolicy) {
      if (Math.max(...fs.map((f) => RANK[f.severity])) < RANK.MEDIUM && !key.startsWith('trust:')) continue;
      const rid = `REM-${String(out.length + 1).padStart(3, '0')}`;
      let original, proposed, changes, fname, cmds, verification, title, holderNames, pkind;
      if (key.startsWith('trust:')) {
        const role = ctx.identities.get(key.slice(6));
        if (!role || !role.trust) continue;
        original = role.trust.document;
        [proposed, changes] = synthesizeTrust(ctx, role);
        if (!changes.length) continue;
        fname = `remediation/${slug(role.name)}-trust.json`;
        cmds = cliCommands(null, [role], role, fname, acct);
        verification = verifyTrust(ctx, role, proposed, fs);
        title = `${role.name} trust policy`; holderNames = [role.name]; pkind = 'trust';
      } else {
        const pol = ctx.policies.get(key);
        if (!pol) continue;
        const pick = (m) => (m.get(key) || []).filter((a) => ctx.identities.has(a)).map((a) => ctx.identities.get(a));
        const holders = pick(ctx.direct_holders), effective = pick(ctx.holders);
        original = pol.document;
        [proposed, changes] = synthesizePolicy(ctx, pol, effective.length ? effective : holders);
        if (!changes.length) continue;
        fname = `remediation/${slug(pol.name)}-least-privilege.json`;
        cmds = cliCommands(pol, holders, null, fname, acct);
        verification = verifyPolicy(ctx, pol, proposed, effective.length ? effective : holders, fs);
        title = pol.name; holderNames = holders.map((h) => h.name); pkind = pol.kind;
      }
      const placeholders = sorted(uniq(JSON.stringify(proposed).match(PLACEHOLDER_RX) || []));
      const diff = sideBySide(original, proposed);
      fs.forEach((f) => (f.remediation_id = rid));
      out.push({ id: rid, policy_key: key, policy_name: title, policy_kind: pkind, applies_to: holderNames, finding_ids: fs.map((f) => f.id),
        max_severity: maxSev(fs.map((f) => f.severity)), original, proposed, changes, placeholders, file_name: fname, cli: cmds, diff, verification });
    }
    return out;
  }

  /* ------------------------------------------------------------------ uuid5 (sha1) for deterministic ExternalIds */
  function sha1(bytes) {
    const ml = bytes.length * 8, withPad = new Uint8Array(((bytes.length + 9 + 63) >> 6) << 6);
    withPad.set(bytes); withPad[bytes.length] = 0x80;
    const dv = new DataView(withPad.buffer);
    dv.setUint32(withPad.length - 4, ml >>> 0); dv.setUint32(withPad.length - 8, Math.floor(ml / 2 ** 32));
    let [h0, h1, h2, h3, h4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
    const w = new Uint32Array(80), rotl = (x, n) => (x << n) | (x >>> (32 - n));
    for (let off = 0; off < withPad.length; off += 64) {
      for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
      for (let i = 16; i < 80; i++) w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
      let [a, b, c, d, e] = [h0, h1, h2, h3, h4];
      for (let i = 0; i < 80; i++) {
        const [f, k] = i < 20 ? [(b & c) | (~b & d), 0x5a827999] : i < 40 ? [b ^ c ^ d, 0x6ed9eba1] : i < 60 ? [(b & c) | (b & d) | (c & d), 0x8f1bbcdc] : [b ^ c ^ d, 0xca62c1d6];
        const t = (rotl(a, 5) + f + e + k + w[i]) >>> 0;
        e = d; d = c; c = rotl(b, 30) >>> 0; b = a; a = t;
      }
      h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0; h4 = (h4 + e) >>> 0;
    }
    const out = new Uint8Array(20), odv = new DataView(out.buffer);
    [h0, h1, h2, h3, h4].forEach((h, i) => odv.setUint32(i * 4, h));
    return out;
  }
  function uuid5Url(name) {
    const ns = '6ba7b8119dad11d180b400c04fd430c8'.match(/../g).map((h) => parseInt(h, 16));
    const nb = new TextEncoder().encode(name), buf = new Uint8Array(16 + nb.length);
    buf.set(ns); buf.set(nb, 16);
    const h = sha1(buf).slice(0, 16);
    h[6] = (h[6] & 0x0f) | 0x50; h[8] = (h[8] & 0x3f) | 0x80;
    const x = [...h].map((v) => v.toString(16).padStart(2, '0')).join('');
    return `${x.slice(0, 8)}-${x.slice(8, 12)}-${x.slice(12, 16)}-${x.slice(16, 20)}-${x.slice(20)}`;
  }
  function shortHash(s) { // FNV-1a x2 -> 12 hex chars (analysis id only)
    let h1 = 0x811c9dc5, h2 = 0x01000193;
    for (let i = 0; i < s.length; i++) { const c = s.charCodeAt(i); h1 = Math.imul(h1 ^ c, 16777619) >>> 0; h2 = Math.imul(h2 ^ c, 2246822519) >>> 0; }
    return (h1.toString(16).padStart(8, '0') + h2.toString(16).padStart(8, '0')).slice(0, 12);
  }

  /* ------------------------------------------------------------------ engine */
  const SEV_PENALTY = { CRITICAL: 15, HIGH: 7, MEDIUM: 3, LOW: 1, INFO: 0 };
  const grade = (s) => (s >= 90 ? 'A' : s >= 80 ? 'B' : s >= 70 ? 'C' : s >= 60 ? 'D' : 'F');
  const cmpStr = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

  function analyzeAccount(account, opts = {}) {
    const now = opts.now ? new Date(opts.now) : new Date(), staleDays = opts.staleDays ?? 90;
    const ctx = new Context(account, now, staleDays);
    const suppressed = [], positives = [];
    let findings = [...detectExcessive(ctx, suppressed), ...detectTrust(ctx, positives)];
    const [escF, escE] = detectEscalation(ctx);
    findings.push(...escF, ...detectStale(ctx));
    findings.push(...detectHygiene(ctx, findings));
    const G = buildGraph(ctx, escE, findings);
    const paths = findAttackPaths(G);
    findings.push(...pathFindings(paths));
    findings = stableSort(findings, (a, b) => (RANK[b.severity] - RANK[a.severity]) || cmpStr(a.rule_id, b.rule_id) || cmpStr(a.identity_names.join(','), b.identity_names.join(',')));
    findings.forEach((f, i) => (f.id = `F-${String(i + 1).padStart(3, '0')}`));
    const remediations = buildRemediations(ctx, findings);
    for (const s of suppressed) positives.push({ control: 'Explicit Deny guardrail respected', identity: s.identities.join(', '), detail: `${s.policy} / ${s.sid}: ${s.actions.join(', ')} neutralised by Deny` });

    const H = traversable(G);
    let identities = [...ctx.identities.values()].map((ident) => ({
      arn: ident.arn, name: ident.name, kind: ident.kind, path: ident.path, created: isoPy(ident.create_date), last_used: isoPy(ident.last_used),
      last_used_region: ident.last_used_region, last_used_days: ctx.daysSince(ident.last_used), password_last_used: isoPy(ident.password_last_used),
      telemetry: sorted(Object.keys(ident.telemetry).filter((k) => ident.telemetry[k])),
      groups: ident.group_arns.filter((g) => ctx.identities.has(g)).map((g) => ctx.identities.get(g).name),
      members: ident.member_arns.filter((m) => ctx.identities.has(m)).map((m) => ctx.identities.get(m).name),
      policies: ident.policy_keys.filter((k) => ctx.policies.has(k)).map((k) => ctx.policies.get(k).name),
      instance_profiles: ident.instance_profiles, admin: ctx.isAdmin(ident.arn), blast: blastRadius(ctx, H, ident.arn, findings),
      statements: (ctx.sources.get(ident.arn) || []).map(([pol, st, via]) => ({ policy: pol.name, policy_kind: pol.kind, via, sid: st.label, effect: st.effect,
        actions: st.actionDisplay().slice(0, 40), action_count: (st.actions.length ? st.actions : st.not_actions).length, resources: st.resourceDisplay(),
        condition: hasKeys(st.condition) ? st.condition : null })),
      trust: (ctx.trusts.get(ident.arn) || []).map((t) => ({ kind: t.kind, principal: t.value, external: t.external, conditions: hasKeys(t.statement.condition) ? t.statement.condition : null, actions: t.actions })),
      findings: findings.filter((f) => f.identity_arns.includes(ident.arn)).map((f) => f.id),
    }));
    identities = stableSort(identities, (a, b) => b.blast.score - a.blast.score);

    const sevCounts = {};
    findings.forEach((f) => (sevCounts[f.severity] = (sevCounts[f.severity] || 0) + 1));
    let score = Math.max(0, 100 - findings.reduce((a, f) => a + SEV_PENALTY[f.severity], 0));
    if (sevCounts.CRITICAL) score = Math.min(score, sevCounts.CRITICAL < 3 ? 64 : 49);
    const attachedAllow = [];
    for (const [key, holders] of ctx.holders) {
      const pol = ctx.policies.get(key);
      if (pol && holders.length) pol.statements.filter((s) => s.isAllow).forEach((s) => attachedAllow.push([key, s.index]));
    }
    const excRules = new Set(['ADMIN-001', 'ADMIN-002', 'WILD-001', 'WILD-002', 'WILD-003', 'WILD-004', 'WILD-005', 'RES-001', 'READ-001']);
    const excessive = new Set(findings.filter((f) => excRules.has(f.rule_id)).map((f) => `${f.policy_key}\u0000${f.statement_index}`));
    const excessiveStmts = attachedAllow.filter(([k, i]) => excessive.has(`${k}\u0000${i}`) || excessive.has(`${k}\u0000null`)).length;
    const ratio = attachedAllow.length ? Math.round((excessiveStmts / attachedAllow.length) * 1000) / 1000 : 0;
    const principals = identities.filter((i) => i.kind === 'user' || i.kind === 'role');
    const byCat = {};
    findings.forEach((f) => (byCat[f.category] = (byCat[f.category] || 0) + 1));
    const fingerprint = JSON.stringify([sorted([...ctx.identities.keys()]), sorted([...ctx.policies.keys()]).map((k) => ctx.policies.get(k).document)]);
    const policiesOut = {};
    for (const [k, p] of ctx.policies) {
      if (!(ctx.holders.has(k) || ctx.direct_holders.has(k) || p.kind === 'customer-managed')) continue;
      const names = (m) => (m.get(k) || []).filter((a) => ctx.identities.has(a)).map((a) => ctx.identities.get(a).name);
      policiesOut[k] = { name: p.name, kind: p.kind, arn: p.arn, document: p.document, synthesized: p.synthesized, attached_to: names(ctx.direct_holders), effective_for: names(ctx.holders) };
    }
    return {
      meta: { tool: 'IAM Sentinel', version: C.VERSION, source: account.source, account_id: account.account_id, analyzed_at: isoPy(now),
        stale_threshold_days: staleDays, analysis_id: shortHash(fingerprint + isoPy(now)), warnings: account.warnings, engine: 'browser' },
      summary: {
        grade: grade(score), score, total_identities: ctx.identities.size, users: account.users().length, groups: account.groups().length, roles: account.roles().length,
        policies: new Set([...ctx.identities.values()].flatMap((i) => i.policy_keys)).size, findings_total: findings.length,
        findings_by_severity: Object.fromEntries(SEVERITIES.map((s) => [s, sevCounts[s] || 0])), findings_by_category: byCat,
        attack_paths: paths.length, critical_attack_paths: paths.filter((p) => p.severity === 'CRITICAL').length, multi_hop_paths: paths.filter((p) => p.multi_hop).length,
        excess_permission_ratio: ratio, excess_detail: `${excessiveStmts} of ${attachedAllow.length} attached Allow statements are wildcard/over-broad`,
        admin_identities: identities.filter((i) => i.admin).map((i) => i.name),
        avg_blast_radius: principals.length ? Math.round((principals.reduce((a, i) => a + i.blast.score, 0) / principals.length) * 10) / 10 : 0,
        max_blast_radius: Math.max(0, ...principals.map((i) => i.blast.score)),
        telemetry: { credential_report: account.has_credential_report, role_last_used: account.roles().filter((r) => r.telemetry.role_last_used).length,
          users_with_activity: account.users().filter((u) => Object.keys(u.telemetry).length).length, users_total: account.users().length },
        positive_controls: positives.length,
      },
      findings, attack_paths: paths, identities, remediations, positive_controls: positives, policies: policiesOut, graph: toCytoscape(G, paths),
      mitre: Object.fromEntries(Object.entries(C.MITRE_NAMES).filter(([k]) => findings.some((f) => f.mitre.includes(k)))),
    };
  }
  const analyze = (data, opts = {}) => analyzeAccount(normalize(data, opts.source || 'upload'), opts);

  /* ------------------------------------------------------------------ report exporters (ports of iamsentinel/reports.py) */
  const VIEW_KEYS = new Set(['findingById', 'identityByArn', 'remById']);
  const pure = (r) => Object.fromEntries(Object.entries(r).filter(([k]) => !VIEW_KEYS.has(k)));
  const pct = (x) => `${Math.round(x * 100)}%`;
  const SARIF_LEVEL = { CRITICAL: 'error', HIGH: 'error', MEDIUM: 'warning', LOW: 'note', INFO: 'note' };
  const SEC_SCORE = { CRITICAL: '9.5', HIGH: '8.0', MEDIUM: '5.5', LOW: '3.0', INFO: '0.0' };
  function toJson(r) { const o = pure(r); delete o.graph; return JSON.stringify(o, null, 2); }
  function toSarif(r) {
    const rules = new Map(), results = [], src = r.meta.source;
    for (const f of r.findings) {
      if (!rules.has(f.rule_id)) rules.set(f.rule_id, { id: f.rule_id, name: f.rule_id.replace(/-/g, ''), shortDescription: { text: f.title.slice(0, 120) },
        fullDescription: { text: f.description.slice(0, 1000) }, help: { text: f.recommendation },
        properties: { tags: ['security', 'iam', f.category, ...f.mitre], 'security-severity': SEC_SCORE[f.severity] } });
      const loc = [f.identity_names.slice(0, 3).join(', '), f.policy_name, f.sid].filter(Boolean).join(' / ');
      results.push({ ruleId: f.rule_id, level: SARIF_LEVEL[f.severity],
        message: { text: `[${f.severity}] ${f.title} — ${f.identity_names.slice(0, 5).join(', ')}. ${f.recommendation}` },
        locations: [{ physicalLocation: { artifactLocation: { uri: src } }, logicalLocations: [{ name: loc || 'account', fullyQualifiedName: f.identity_arns[0] || '', kind: 'resource' }] }],
        partialFingerprints: { 'iamSentinel/v1': `${f.rule_id}|${sorted(f.identity_arns).join(',')}|${f.policy_key}|${f.statement_index}` },
        properties: { severity: f.severity, exploitability: f.exploitability, actions: f.offending_actions, resources: f.resources, remediation: f.remediation_id } });
    }
    return JSON.stringify({ $schema: 'https://json.schemastore.org/sarif-2.1.0.json', version: '2.1.0',
      runs: [{ tool: { driver: { name: 'IAM Sentinel', version: C.VERSION, informationUri: 'https://github.com/', rules: [...rules.values()] } }, results,
        properties: { grade: r.summary.grade, score: r.summary.score, account: r.meta.account_id } }] }, null, 2);
  }
  const mdEsc = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');
  function toMarkdown(r) {
    const m = r.meta, s = r.summary;
    const L = [`# IAM Sentinel Audit Report — account \`${m.account_id}\``, '', `*Source:* \`${m.source}\` · *Analyzed:* ${m.analyzed_at} · *Tool:* IAM Sentinel ${m.version}`, '',
      '## Executive summary', '', '| Security grade | Score | Identities | Findings | Critical attack paths | Excess permission ratio |', '|---|---|---|---|---|---|',
      `| **${s.grade}** | ${s.score}/100 | ${s.total_identities} (${s.users} users, ${s.groups} groups, ${s.roles} roles) | ${s.findings_total} | ${s.critical_attack_paths} | ${pct(s.excess_permission_ratio)} (${s.excess_detail}) |`, '',
      '**Findings by severity:** ' + Object.entries(s.findings_by_severity).map(([k, v]) => `${k}: ${v}`).join(', '), '',
      `**Administrator-equivalent identities:** ${s.admin_identities.join(', ') || 'none'}`, ''];
    const tel = s.telemetry;
    if (!tel.credential_report && tel.users_with_activity < tel.users_total) L.push('> ⚠️ User activity telemetry (credential report / PasswordLastUsed) is absent — dormant-user checks were limited.', '');
    L.push('## Identity blast radius', '', '| Identity | Type | Blast radius | Level | Top factors |', '|---|---|---|---|---|');
    for (const i of r.identities) L.push(`| ${i.name} | ${i.kind} | ${i.blast.score} | ${i.blast.level} | ${mdEsc(i.blast.factors.slice(0, 3).map((x) => `${x.factor} (+${x.points})`).join('; '))} |`);
    L.push('', '## Attack paths', '');
    for (const p of r.attack_paths) L.push(`- **${p.id} [${p.severity}${p.exploitability === 'latent' ? ' · latent' : ''}]** ${mdEsc(p.narrative)}`);
    L.push('', '## Findings', '', '| ID | Severity | Rule | Title | Identity | Policy / Sid |', '|---|---|---|---|---|---|');
    for (const f of r.findings) {
      const sid = f.sid || (f.statement_index !== null ? `Statement[${f.statement_index}]` : '-');
      L.push(`| ${f.id} | ${f.severity} | ${f.rule_id} | ${mdEsc(f.title)} | ${mdEsc(f.identity_names.slice(0, 4).join(', '))} | ${mdEsc(f.policy_name || '-')} / ${mdEsc(sid)} |`);
    }
    L.push('', '## Finding details', '');
    for (const f of r.findings) {
      L.push(`### ${f.id} · ${f.severity} · ${f.title}`, '', `- **Rule:** \`${f.rule_id}\` (${f.category}) · **Exploitability:** ${f.exploitability}` + (f.mitre.length ? ` · **MITRE ATT&CK:** ${f.mitre.join(', ')}` : ''),
        `- **Identities:** ${f.identity_names.join(', ') || '-'}`);
      if (f.policy_name) L.push(`- **Policy:** ${f.policy_name} (${f.policy_kind}) ${f.policy_arn || ''} · **Sid:** ${f.sid || '(none)'} · **Effect:** ${f.effect}`);
      if (f.offending_actions.length) L.push(`- **Offending actions:** \`${f.offending_actions.slice(0, 20).join(', ')}\``);
      if (f.resources.length) L.push(`- **Resource:** \`${f.resources.slice(0, 5).join(', ')}\``);
      if (f.condition) L.push(`- **Condition:** \`${JSON.stringify(f.condition)}\``);
      L.push(`- **Risk:** ${f.description}`, `- **Attack path:** ${f.attack_scenario}`, `- **Fix:** ${f.recommendation}`);
      f.notes.forEach((n) => L.push(`- *Note:* ${n}`));
      if (f.remediation_id) L.push(`- **Remediation:** ${f.remediation_id}`);
      L.push('');
    }
    L.push('## Least-privilege remediations', '');
    for (const x of r.remediations) {
      const v = x.verification, js = JSON.stringify(x.proposed);
      L.push(`### ${x.id} · ${x.policy_name} (${x.policy_kind}) → applies to ${x.applies_to.join(', ')}`, '', `Residual risk after fix: **${v.before} → ${v.after}**`, '', ...x.changes.map((c) => `- ${c}`));
      if (x.placeholders.length) L.push('', `Fill in placeholders before applying: ${x.placeholders.map((p) => `\`${p}\``).join(', ')}`);
      L.push('', '```json', js.length < 12000 ? JSON.stringify(x.proposed, null, 2) : js.slice(0, 12000) + ' …(truncated, see JSON export)', '```', '', '```diff', x.diff.unified.slice(0, 8000), '```', '', 'Apply:', '', '```bash', ...x.cli, '```', '');
    }
    if (r.positive_controls.length) L.push('## Positive controls observed', '', ...r.positive_controls.map((p) => `- **${p.control}** — ${p.identity}: ${p.detail}`), '');
    if (m.warnings.length) L.push('## Ingestion warnings', '', ...m.warnings.map((w) => `- ${w}`), '');
    return L.join('\n');
  }
  const CSS = ':root{--bg:#0b1020;--panel:#121a2f;--line:#24304f;--ink:#e6ebf5;--muted:#93a0bd;--crit:#ef4444;--high:#f97316;--med:#eab308;--low:#3b82f6;--info:#64748b;--ok:#22c55e}' +
    '@media print{:root{--bg:#fff;--panel:#fff;--line:#ddd;--ink:#111;--muted:#555}}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.55 -apple-system,Segoe UI,Inter,Roboto,sans-serif}' +
    'main{max-width:1100px;margin:0 auto;padding:32px 20px}h1{font-size:26px;margin:0 0 4px}h2{margin-top:36px;border-bottom:1px solid var(--line);padding-bottom:6px}.muted{color:var(--muted)}' +
    '.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin:18px 0}.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px}.big{font-size:30px;font-weight:700}' +
    '.grade{font-size:56px;font-weight:800;line-height:1}.sev{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:700;color:#fff}.CRITICAL{background:var(--crit)}.HIGH{background:var(--high)}' +
    '.MEDIUM{background:var(--med);color:#111}.LOW{background:var(--low)}.INFO{background:var(--info)}table{width:100%;border-collapse:collapse;margin:10px 0}td,th{border-bottom:1px solid var(--line);padding:7px 8px;text-align:left;vertical-align:top}' +
    'th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase}code,pre{font-family:ui-monospace,Consolas,monospace;font-size:12px}pre{background:#070b16;color:#d6deeb;padding:12px;border-radius:8px;overflow:auto;max-height:420px}' +
    'details{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:10px 14px;margin:8px 0}summary{cursor:pointer;font-weight:600}.bar{height:8px;background:var(--line);border-radius:4px;overflow:hidden}.bar>i{display:block;height:100%}' +
    '.diff{display:grid;grid-template-columns:1fr 1fr;gap:8px}.add{background:rgba(34,197,94,.15)}.del{background:rgba(239,68,68,.15)}.chg{background:rgba(234,179,8,.15)}';
  const he = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#x27;' }[c]));
  function toHtml(r) {
    const m = r.meta, s = r.summary;
    const gcol = { A: 'var(--ok)', B: 'var(--ok)', C: 'var(--med)', D: 'var(--high)', F: 'var(--crit)' }[s.grade];
    const H = [`<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>IAM Sentinel Report</title><style>${CSS}</style></head><body><main>`,
      `<h1>IAM Sentinel — Cloud Identity Audit</h1><div class=muted>Account <b>${he(m.account_id)}</b> · source ${he(m.source)} · analyzed ${he(m.analyzed_at.slice(0, 19))} UTC · v${he(m.version)}</div>`, '<div class=grid>',
      `<div class=card><div class=muted>Security grade</div><div class=grade style='color:${gcol}'>${s.grade}</div><div class=muted>${s.score}/100</div></div>`,
      `<div class=card><div class=muted>Identities</div><div class=big>${s.total_identities}</div><div class=muted>${s.users} users · ${s.groups} groups · ${s.roles} roles</div></div>`,
      `<div class=card><div class=muted>Critical attack paths</div><div class=big style='color:var(--crit)'>${s.critical_attack_paths}</div><div class=muted>${s.attack_paths} paths total</div></div>`,
      `<div class=card><div class=muted>Excess permission ratio</div><div class=big>${pct(s.excess_permission_ratio)}</div><div class=muted>${he(s.excess_detail)}</div></div>`,
      `<div class=card><div class=muted>Findings</div><div class=big>${s.findings_total}</div><div>` + Object.entries(s.findings_by_severity).map(([k, v]) => `<span class='sev ${k}'>${k[0]}:${v}</span>`).join(' ') + '</div></div>', '</div>',
      "<h2>Identity blast radius</h2><table><tr><th>Identity</th><th>Type</th><th style='width:35%'>Blast radius</th><th>Top factors</th></tr>"];
    for (const i of r.identities) {
      const b = i.blast, col = { CRITICAL: 'var(--crit)', HIGH: 'var(--high)', MEDIUM: 'var(--med)', LOW: 'var(--low)' }[b.level];
      H.push(`<tr><td><b>${he(i.name)}</b><div class=muted style='font-size:11px'>${he(i.arn)}</div></td><td>${i.kind}</td><td><div class=bar><i style='width:${b.score}%;background:${col}'></i></div>${b.score}/100 · ${b.level}</td>` +
        `<td>${he(b.factors.slice(0, 3).map((x) => `${x.factor} +${x.points}`).join('; '))}</td></tr>`);
    }
    H.push('</table><h2>Attack paths</h2><table><tr><th>ID</th><th>Severity</th><th>Path</th></tr>');
    for (const p of r.attack_paths) H.push(`<tr><td>${p.id}</td><td><span class='sev ${p.severity}'>${p.severity}</span>${p.exploitability === 'latent' ? ' <i class=muted>latent</i>' : ''}</td><td>${he(p.narrative)}</td></tr>`);
    H.push('</table><h2>Findings</h2>');
    for (const f of r.findings) {
      const ev = [];
      if (f.policy_name) {
        ev.push(`<tr><th>Policy</th><td>${he(f.policy_name)} <span class=muted>(${he(f.policy_kind)}) ${he(f.policy_arn || '')}</span></td></tr>`);
        ev.push(`<tr><th>Sid / Effect</th><td>${he(f.sid || '(none)')} / ${he(f.effect)}</td></tr>`);
      }
      if (f.offending_actions.length) ev.push(`<tr><th>Offending actions</th><td><code>${he(f.offending_actions.slice(0, 25).join(', '))}</code></td></tr>`);
      if (f.resources.length) ev.push(`<tr><th>Resource</th><td><code>${he(f.resources.slice(0, 6).join(', '))}</code></td></tr>`);
      if (f.condition) ev.push(`<tr><th>Condition</th><td><code>${he(JSON.stringify(f.condition))}</code></td></tr>`);
      H.push(`<details><summary><span class='sev ${f.severity}'>${f.severity}</span> ${he(f.id)} · ${he(f.title)} <span class=muted>— ${he(f.identity_names.slice(0, 4).join(', '))}</span></summary>` +
        `<table><tr><th style='width:160px'>Rule</th><td>${f.rule_id} · ${he(f.category)} · exploitability: ${f.exploitability}${f.mitre.length ? ' · MITRE ' + he(f.mitre.join(', ')) : ''}</td></tr>${ev.join('')}` +
        `<tr><th>Risk</th><td>${he(f.description)}</td></tr><tr><th>Attack path</th><td>${he(f.attack_scenario)}</td></tr>` +
        `<tr><th>Recommendation</th><td>${he(f.recommendation)}${f.notes.map((n) => '<div class=muted>• ' + he(n) + '</div>').join('')}${f.remediation_id ? ' <b>→ ' + f.remediation_id + '</b>' : ''}</td></tr></table></details>`);
    }
    H.push('<h2>Least-privilege remediations</h2>');
    for (const x of r.remediations) {
      const v = x.verification, rows = x.diff.rows, keep = new Set();
      rows.forEach((row, i) => { if (row.t !== 'eq') for (let k = Math.max(0, i - 2); k < Math.min(rows.length, i + 3); k++) keep.add(k); });
      const left = [], right = [];
      let last = -1;
      for (const i of [...keep].sort((a, b) => a - b)) {
        if (last !== -1 && i !== last + 1) { left.push('<span class=muted>  …</span>'); right.push('<span class=muted>  …</span>'); }
        const row = rows[i], cls = row.t !== 'eq' ? row.t : '';
        left.push(`<span class='${row.l !== null ? cls : ''}'>${he(row.l || '')}</span>`);
        right.push(`<span class='${row.r !== null ? cls : ''}'>${he(row.r || '')}</span>`);
        last = i;
      }
      H.push(`<details open><summary>${x.id} · ${he(x.policy_name)} <span class=muted>(${x.policy_kind}) → ${he(x.applies_to.join(', '))} · risk ${v.before} → ${v.after}</span></summary><ul>${x.changes.map((c) => '<li>' + he(c) + '</li>').join('')}</ul>` +
        (x.placeholders.length ? `<div class=muted>Placeholders to fill: ${he(x.placeholders.join(', '))}</div>` : '') +
        `<div class=diff><div><b>Original</b><pre>${left.slice(0, 400).join('\n')}</pre></div><div><b>Least privilege</b><pre>${right.slice(0, 400).join('\n')}</pre></div></div><b>Apply</b><pre>${he(x.cli.join('\n'))}</pre></details>`);
    }
    if (r.positive_controls.length) H.push('<h2>Positive controls</h2><ul>' + r.positive_controls.map((p) => `<li><b>${he(p.control)}</b> — ${he(p.identity)}: ${he(p.detail)}</li>`).join('') + '</ul>');
    H.push("<p class=muted style='margin-top:40px'>Generated by IAM Sentinel. Static analysis of an IAM export: SCPs, resource-based policies and session policies are not evaluated.</p></main></body></html>");
    return H.join('');
  }
  const EXPORTERS = { json: [toJson, 'application/json'], sarif: [toSarif, 'application/sarif+json'], md: [toMarkdown, 'text/markdown'], html: [toHtml, 'text/html'] };

  const api = { analyze, analyzeAccount, normalize, IAMParseError, EXPORTERS, version: C.VERSION };
  root.IAMSentinel = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : window);
