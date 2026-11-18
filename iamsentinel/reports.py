"""Report exporters: JSON, SARIF 2.1.0 (CI/CD + GitHub code scanning), Markdown and standalone HTML."""
from __future__ import annotations

import html
import json
from typing import Any

from . import __version__

SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
SEC_SCORE = {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.5", "LOW": "3.0", "INFO": "0.0"}


def to_json(result: dict) -> str:
    slim = {k: v for k, v in result.items() if k != "graph"}
    return json.dumps(slim, indent=2, default=str)


def to_sarif(result: dict) -> str:
    rules: dict[str, dict] = {}
    results = []
    src = result["meta"]["source"]
    for f in result["findings"]:
        rules.setdefault(f["rule_id"], {
            "id": f["rule_id"], "name": f["rule_id"].replace("-", ""),
            "shortDescription": {"text": f["title"][:120]},
            "fullDescription": {"text": f["description"][:1000]},
            "help": {"text": f["recommendation"]},
            "properties": {"tags": ["security", "iam", f["category"]] + f["mitre"], "security-severity": SEC_SCORE[f["severity"]]},
        })
        loc_name = " / ".join(x for x in [", ".join(f["identity_names"][:3]), f.get("policy_name"), f.get("sid")] if x)
        results.append({
            "ruleId": f["rule_id"], "level": SARIF_LEVEL[f["severity"]],
            "message": {"text": f"[{f['severity']}] {f['title']} — {', '.join(f['identity_names'][:5])}. {f['recommendation']}"},
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": src}},
                "logicalLocations": [{"name": loc_name or "account", "fullyQualifiedName": (f["identity_arns"] or [""])[0], "kind": "resource"}],
            }],
            "partialFingerprints": {"iamSentinel/v1": f"{f['rule_id']}|{','.join(sorted(f['identity_arns']))}|{f.get('policy_key')}|{f.get('statement_index')}"},
            "properties": {"severity": f["severity"], "exploitability": f["exploitability"], "actions": f["offending_actions"],
                           "resources": f["resources"], "remediation": f.get("remediation_id")},
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "IAM Sentinel", "version": __version__, "informationUri": "https://github.com/",
                                      "rules": list(rules.values())}},
                  "results": results,
                  "properties": {"grade": result["summary"]["grade"], "score": result["summary"]["score"],
                                 "account": result["meta"]["account_id"]}}],
    }
    return json.dumps(sarif, indent=2)


def _md_escape(s: Any) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ")


def to_markdown(result: dict) -> str:
    m, s = result["meta"], result["summary"]
    L = [f"# IAM Sentinel Audit Report — account `{m['account_id']}`", "",
         f"*Source:* `{m['source']}` · *Analyzed:* {m['analyzed_at']} · *Tool:* IAM Sentinel {m['version']}", "",
         "## Executive summary", "",
         f"| Security grade | Score | Identities | Findings | Critical attack paths | Excess permission ratio |",
         f"|---|---|---|---|---|---|",
         f"| **{s['grade']}** | {s['score']}/100 | {s['total_identities']} ({s['users']} users, {s['groups']} groups, {s['roles']} roles) | "
         f"{s['findings_total']} | {s['critical_attack_paths']} | {s['excess_permission_ratio']:.0%} ({s['excess_detail']}) |", "",
         "**Findings by severity:** " + ", ".join(f"{k}: {v}" for k, v in s["findings_by_severity"].items()), "",
         f"**Administrator-equivalent identities:** {', '.join(s['admin_identities']) or 'none'}", ""]
    tel = s["telemetry"]
    if not tel["credential_report"] and tel["users_with_activity"] < tel["users_total"]:
        L += ["> ⚠️ User activity telemetry (credential report / PasswordLastUsed) is absent — dormant-user checks were limited.", ""]
    L += ["## Identity blast radius", "", "| Identity | Type | Blast radius | Level | Top factors |", "|---|---|---|---|---|"]
    for i in result["identities"]:
        top = "; ".join(f"{x['factor']} (+{x['points']})" for x in i["blast"]["factors"][:3])
        L.append(f"| {i['name']} | {i['kind']} | {i['blast']['score']} | {i['blast']['level']} | {_md_escape(top)} |")
    L += ["", "## Attack paths", ""]
    for p in result["attack_paths"]:
        L.append(f"- **{p['id']} [{p['severity']}{' · latent' if p['exploitability'] == 'latent' else ''}]** {_md_escape(p['narrative'])}")
    L += ["", "## Findings", "", "| ID | Severity | Rule | Title | Identity | Policy / Sid |", "|---|---|---|---|---|---|"]
    for f in result["findings"]:
        idx = f.get("statement_index")
        sid = f.get("sid") or (f"Statement[{idx}]" if idx is not None else "-")
        L.append(f"| {f['id']} | {f['severity']} | {f['rule_id']} | {_md_escape(f['title'])} | {_md_escape(', '.join(f['identity_names'][:4]))} | "
                 f"{_md_escape(f.get('policy_name') or '-')} / {_md_escape(sid)} |")
    L += ["", "## Finding details", ""]
    for f in result["findings"]:
        L += [f"### {f['id']} · {f['severity']} · {f['title']}", "",
              f"- **Rule:** `{f['rule_id']}` ({f['category']}) · **Exploitability:** {f['exploitability']}"
              + (f" · **MITRE ATT&CK:** {', '.join(f['mitre'])}" if f["mitre"] else ""),
              f"- **Identities:** {', '.join(f['identity_names']) or '-'}"]
        if f.get("policy_name"):
            L.append(f"- **Policy:** {f['policy_name']} ({f.get('policy_kind')}) {f.get('policy_arn') or ''} · **Sid:** {f.get('sid') or '(none)'} · **Effect:** {f.get('effect')}")
        if f["offending_actions"]:
            L.append(f"- **Offending actions:** `{', '.join(f['offending_actions'][:20])}`")
        if f["resources"]:
            L.append(f"- **Resource:** `{', '.join(f['resources'][:5])}`")
        if f.get("condition"):
            L.append(f"- **Condition:** `{json.dumps(f['condition'])}`")
        L += [f"- **Risk:** {f['description']}", f"- **Attack path:** {f['attack_scenario']}", f"- **Fix:** {f['recommendation']}"]
        for n in f["notes"]:
            L.append(f"- *Note:* {n}")
        if f.get("remediation_id"):
            L.append(f"- **Remediation:** {f['remediation_id']}")
        L.append("")
    L += ["## Least-privilege remediations", ""]
    for r in result["remediations"]:
        v = r["verification"]
        L += [f"### {r['id']} · {r['policy_name']} ({r['policy_kind']}) → applies to {', '.join(r['applies_to'])}", "",
              f"Residual risk after fix: **{v['before']} → {v['after']}**", ""]
        L += [f"- {c}" for c in r["changes"]]
        if r["placeholders"]:
            L += ["", f"Fill in placeholders before applying: {', '.join(f'`{p}`' for p in r['placeholders'])}"]
        L += ["", "```json", json.dumps(r["proposed"], indent=2) if len(json.dumps(r["proposed"])) < 12000 else
              json.dumps(r["proposed"])[:12000] + " …(truncated, see JSON export)", "```", "", "```diff", r["diff"]["unified"][:8000], "```",
              "", "Apply:", "", "```bash", *[f"{c}" for c in r["cli"]], "```", ""]
    if result["positive_controls"]:
        L += ["## Positive controls observed", ""] + [f"- **{p['control']}** — {p['identity']}: {p['detail']}" for p in result["positive_controls"]] + [""]
    if m["warnings"]:
        L += ["## Ingestion warnings", ""] + [f"- {w}" for w in m["warnings"]] + [""]
    return "\n".join(L)


CSS = """
:root{--bg:#0b1020;--panel:#121a2f;--line:#24304f;--ink:#e6ebf5;--muted:#93a0bd;--crit:#ef4444;--high:#f97316;--med:#eab308;--low:#3b82f6;--info:#64748b;--ok:#22c55e}
@media print{:root{--bg:#fff;--panel:#fff;--line:#ddd;--ink:#111;--muted:#555}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.55 -apple-system,Segoe UI,Inter,Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:32px 20px}h1{font-size:26px;margin:0 0 4px}h2{margin-top:36px;border-bottom:1px solid var(--line);padding-bottom:6px}
.muted{color:var(--muted)}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin:18px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px}.big{font-size:30px;font-weight:700}
.grade{font-size:56px;font-weight:800;line-height:1}.sev{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:700;color:#fff}
.CRITICAL{background:var(--crit)}.HIGH{background:var(--high)}.MEDIUM{background:var(--med);color:#111}.LOW{background:var(--low)}.INFO{background:var(--info)}
table{width:100%;border-collapse:collapse;margin:10px 0}td,th{border-bottom:1px solid var(--line);padding:7px 8px;text-align:left;vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase}code,pre{font-family:ui-monospace,Consolas,monospace;font-size:12px}
pre{background:#070b16;color:#d6deeb;padding:12px;border-radius:8px;overflow:auto;max-height:420px}details{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:10px 14px;margin:8px 0}
summary{cursor:pointer;font-weight:600}.bar{height:8px;background:var(--line);border-radius:4px;overflow:hidden}.bar>i{display:block;height:100%}
.diff{display:grid;grid-template-columns:1fr 1fr;gap:8px}.add{background:rgba(34,197,94,.15)}.del{background:rgba(239,68,68,.15)}.chg{background:rgba(234,179,8,.15)}
"""


def to_html(result: dict) -> str:
    e = html.escape
    m, s = result["meta"], result["summary"]
    gcol = {"A": "var(--ok)", "B": "var(--ok)", "C": "var(--med)", "D": "var(--high)", "F": "var(--crit)"}[s["grade"]]
    H = [f"<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
         f"<title>IAM Sentinel Report</title><style>{CSS}</style></head><body><main>",
         f"<h1>IAM Sentinel — Cloud Identity Audit</h1><div class=muted>Account <b>{e(m['account_id'])}</b> · source {e(m['source'])} · "
         f"analyzed {e(m['analyzed_at'][:19])} UTC · v{e(m['version'])}</div>",
         "<div class=grid>",
         f"<div class=card><div class=muted>Security grade</div><div class=grade style='color:{gcol}'>{s['grade']}</div><div class=muted>{s['score']}/100</div></div>",
         f"<div class=card><div class=muted>Identities</div><div class=big>{s['total_identities']}</div><div class=muted>{s['users']} users · {s['groups']} groups · {s['roles']} roles</div></div>",
         f"<div class=card><div class=muted>Critical attack paths</div><div class=big style='color:var(--crit)'>{s['critical_attack_paths']}</div><div class=muted>{s['attack_paths']} paths total</div></div>",
         f"<div class=card><div class=muted>Excess permission ratio</div><div class=big>{s['excess_permission_ratio']:.0%}</div><div class=muted>{e(s['excess_detail'])}</div></div>",
         f"<div class=card><div class=muted>Findings</div><div class=big>{s['findings_total']}</div><div>"
         + " ".join(f"<span class='sev {k}'>{k[0]}:{v}</span>" for k, v in s["findings_by_severity"].items()) + "</div></div>",
         "</div>"]
    H += ["<h2>Identity blast radius</h2><table><tr><th>Identity</th><th>Type</th><th style='width:35%'>Blast radius</th><th>Top factors</th></tr>"]
    for i in result["identities"]:
        b = i["blast"]
        col = {"CRITICAL": "var(--crit)", "HIGH": "var(--high)", "MEDIUM": "var(--med)", "LOW": "var(--low)"}[b["level"]]
        H.append(f"<tr><td><b>{e(i['name'])}</b><div class=muted style='font-size:11px'>{e(i['arn'])}</div></td><td>{i['kind']}</td>"
                 f"<td><div class=bar><i style='width:{b['score']}%;background:{col}'></i></div>{b['score']}/100 · {b['level']}</td>"
                 f"<td>{e('; '.join(x['factor'] + ' +' + str(x['points']) for x in b['factors'][:3]))}</td></tr>")
    H.append("</table><h2>Attack paths</h2><table><tr><th>ID</th><th>Severity</th><th>Path</th></tr>")
    for p in result["attack_paths"]:
        H.append(f"<tr><td>{p['id']}</td><td><span class='sev {p['severity']}'>{p['severity']}</span>{' <i class=muted>latent</i>' if p['exploitability'] == 'latent' else ''}</td><td>{e(p['narrative'])}</td></tr>")
    H.append("</table><h2>Findings</h2>")
    for f in result["findings"]:
        ev = []
        if f.get("policy_name"):
            ev.append(f"<tr><th>Policy</th><td>{e(f['policy_name'])} <span class=muted>({e(str(f.get('policy_kind')))}) {e(f.get('policy_arn') or '')}</span></td></tr>")
            ev.append(f"<tr><th>Sid / Effect</th><td>{e(f.get('sid') or '(none)')} / {e(str(f.get('effect')))}</td></tr>")
        if f["offending_actions"]:
            ev.append(f"<tr><th>Offending actions</th><td><code>{e(', '.join(f['offending_actions'][:25]))}</code></td></tr>")
        if f["resources"]:
            ev.append(f"<tr><th>Resource</th><td><code>{e(', '.join(f['resources'][:6]))}</code></td></tr>")
        if f.get("condition"):
            ev.append(f"<tr><th>Condition</th><td><code>{e(json.dumps(f['condition']))}</code></td></tr>")
        H.append(f"<details><summary><span class='sev {f['severity']}'>{f['severity']}</span> {e(f['id'])} · {e(f['title'])} "
                 f"<span class=muted>— {e(', '.join(f['identity_names'][:4]))}</span></summary>"
                 f"<table><tr><th style='width:160px'>Rule</th><td>{f['rule_id']} · {e(f['category'])} · exploitability: {f['exploitability']}"
                 f"{' · MITRE ' + e(', '.join(f['mitre'])) if f['mitre'] else ''}</td></tr>{''.join(ev)}"
                 f"<tr><th>Risk</th><td>{e(f['description'])}</td></tr><tr><th>Attack path</th><td>{e(f['attack_scenario'])}</td></tr>"
                 f"<tr><th>Recommendation</th><td>{e(f['recommendation'])}{''.join('<div class=muted>• ' + e(n) + '</div>' for n in f['notes'])}"
                 f"{' <b>→ ' + f['remediation_id'] + '</b>' if f.get('remediation_id') else ''}</td></tr></table></details>")
    H.append("<h2>Least-privilege remediations</h2>")
    for r in result["remediations"]:
        v = r["verification"]
        rows = r["diff"]["rows"]
        changed = [i for i, x in enumerate(rows) if x["t"] != "eq"]
        keep = set()
        for i in changed:
            keep.update(range(max(0, i - 2), min(len(rows), i + 3)))
        left, right, last = [], [], -1
        for i in sorted(keep):
            if last != -1 and i != last + 1:
                left.append("<span class=muted>  …</span>"); right.append("<span class=muted>  …</span>")
            x = rows[i]
            cls = x["t"] if x["t"] != "eq" else ""
            left.append(f"<span class='{cls if x['l'] is not None else ''}'>{e(x['l'] or '')}</span>")
            right.append(f"<span class='{cls if x['r'] is not None else ''}'>{e(x['r'] or '')}</span>")
            last = i
        H.append(f"<details open><summary>{r['id']} · {e(r['policy_name'])} <span class=muted>({r['policy_kind']}) → {e(', '.join(r['applies_to']))} · "
                 f"risk {v['before']} → {v['after']}</span></summary><ul>{''.join('<li>' + e(c) + '</li>' for c in r['changes'])}</ul>"
                 + (f"<div class=muted>Placeholders to fill: {e(', '.join(r['placeholders']))}</div>" if r["placeholders"] else "")
                 + f"<div class=diff><div><b>Original</b><pre>{chr(10).join(left[:400])}</pre></div><div><b>Least privilege</b><pre>{chr(10).join(right[:400])}</pre></div></div>"
                 f"<b>Apply</b><pre>{e(chr(10).join(r['cli']))}</pre></details>")
    if result["positive_controls"]:
        H.append("<h2>Positive controls</h2><ul>" + "".join(f"<li><b>{e(p['control'])}</b> — {e(p['identity'])}: {e(p['detail'])}</li>" for p in result["positive_controls"]) + "</ul>")
    H.append("<p class=muted style='margin-top:40px'>Generated by IAM Sentinel. Static analysis of an IAM export: SCPs, resource-based policies and session policies are not evaluated.</p></main></body></html>")
    return "".join(H)


EXPORTERS = {"json": (to_json, "application/json"), "sarif": (to_sarif, "application/sarif+json"),
             "md": (to_markdown, "text/markdown"), "html": (to_html, "text/html")}
