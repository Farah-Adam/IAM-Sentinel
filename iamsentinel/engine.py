"""Orchestrates ingestion -> detection -> graph -> scoring -> remediation into one JSON-serialisable result."""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Optional

from . import __version__
from . import detectors as D
from .catalog import MITRE_NAMES
from .context import Context
from .graph import CROWN, blast_radius, build_graph, find_attack_paths, path_findings, to_cytoscape
from .loader import normalize
from .models import SEVERITIES, SEVERITY_RANK, Account, Finding
from .policy_eval import statement_is_global
from .remediation import build_remediations

SEV_PENALTY = {"CRITICAL": 15, "HIGH": 7, "MEDIUM": 3, "LOW": 1, "INFO": 0}


def _grade(score: int) -> str:
    return "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"


def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if dt else None


def analyze_account(account: Account, now: Optional[datetime] = None, stale_days: int = 90) -> dict[str, Any]:
    ctx = Context(account, now=now, stale_days=stale_days)
    suppressed: list[dict] = []
    positives: list[dict] = []

    findings: list[Finding] = []
    findings += D.detect_excessive(ctx, suppressed)
    findings += D.detect_trust(ctx, positives)
    esc_findings, esc_edges = D.detect_escalation(ctx)
    findings += esc_findings
    findings += D.detect_stale(ctx)
    findings += D.detect_hygiene(ctx, findings)

    G = build_graph(ctx, esc_edges, findings)
    paths = find_attack_paths(G)
    findings += path_findings(paths)

    findings.sort(key=lambda f: (-SEVERITY_RANK[f.severity], f.rule_id, ",".join(f.identity_names)))
    for i, f in enumerate(findings, 1):
        f.id = f"F-{i:03d}"
    remediations = build_remediations(ctx, findings)

    # positive controls (deny guardrails, conditional admin, ...)
    for s in suppressed:
        positives.append({"control": "Explicit Deny guardrail respected", "identity": ", ".join(s["identities"]),
                          "detail": f"{s['policy']} / {s['sid']}: {', '.join(s['actions'])} neutralised by Deny"})

    # ---- identities -----------------------------------------------------------------
    identities = []
    for ident in ctx.identities.values():
        blast = blast_radius(ctx, G, ident.arn, findings)
        stmts = []
        for pol, st, via in ctx.sources.get(ident.arn, []):
            stmts.append({"policy": pol.name, "policy_kind": pol.kind, "via": via, "sid": st.label, "effect": st.effect,
                          "actions": st.action_display()[:40], "action_count": len(st.actions or st.not_actions),
                          "resources": st.resource_display(), "condition": st.condition or None})
        trust = [{"kind": t.kind, "principal": t.value, "external": t.external, "conditions": t.statement.condition or None,
                  "actions": t.actions} for t in ctx.trusts.get(ident.arn, [])]
        identities.append({
            "arn": ident.arn, "name": ident.name, "kind": ident.kind, "path": ident.path,
            "created": _iso(ident.create_date), "last_used": _iso(ident.last_used), "last_used_region": ident.last_used_region,
            "last_used_days": ctx.days_since(ident.last_used), "password_last_used": _iso(ident.password_last_used),
            "telemetry": sorted(k for k, v in ident.telemetry.items() if v),
            "groups": [ctx.identities[g].name for g in ident.group_arns if g in ctx.identities],
            "members": [ctx.identities[m].name for m in ident.member_arns if m in ctx.identities],
            "policies": [ctx.policies[k].name for k in ident.policy_keys if k in ctx.policies],
            "instance_profiles": ident.instance_profiles, "admin": ctx.is_admin(ident.arn), "blast": blast,
            "statements": stmts, "trust": trust, "findings": [f.id for f in findings if ident.arn in f.identity_arns],
        })
    identities.sort(key=lambda x: -x["blast"]["score"])

    # ---- metrics ------------------------------------------------------------------------
    sev_counts = Counter(f.severity for f in findings)
    penalty = sum(SEV_PENALTY[f.severity] for f in findings)
    score = max(0, 100 - penalty)
    if sev_counts["CRITICAL"]:
        score = min(score, 64 if sev_counts["CRITICAL"] < 3 else 49)
    attached_allow = []
    for key, holders in ctx.holders.items():
        pol = ctx.policies.get(key)
        if pol and holders:
            attached_allow += [(key, s.index) for s in pol.statements if s.is_allow]
    excessive_rules = {"ADMIN-001", "ADMIN-002", "WILD-001", "WILD-002", "WILD-003", "WILD-004", "WILD-005", "RES-001", "READ-001"}
    excessive = {(f.policy_key, f.statement_index) for f in findings if f.rule_id in excessive_rules}
    excessive_stmts = len([x for x in attached_allow if x in excessive or (x[0], None) in excessive])
    ratio = round(excessive_stmts / len(attached_allow), 3) if attached_allow else 0.0
    critical_paths = [p for p in paths if p["severity"] == "CRITICAL"]
    principals = [i for i in identities if i["kind"] in ("user", "role")]

    fingerprint = json.dumps([sorted(ctx.identities), {k: p.document for k, p in sorted(ctx.policies.items())}], sort_keys=True, default=str)
    data_sha = hashlib.sha256((fingerprint + ctx.now.isoformat()).encode()).hexdigest()[:12]
    result = {
        "meta": {"tool": "IAM Sentinel", "version": __version__, "source": account.source, "account_id": account.account_id,
                 "analyzed_at": ctx.now.isoformat(), "stale_threshold_days": stale_days, "analysis_id": data_sha,
                 "warnings": account.warnings},
        "summary": {
            "grade": _grade(score), "score": score, "total_identities": len(ctx.identities),
            "users": len(account.users()), "groups": len(account.groups()), "roles": len(account.roles()),
            "policies": len({k for i in ctx.identities.values() for k in i.policy_keys}),
            "findings_total": len(findings), "findings_by_severity": {s: sev_counts.get(s, 0) for s in SEVERITIES},
            "findings_by_category": dict(Counter(f.category for f in findings)),
            "attack_paths": len(paths), "critical_attack_paths": len(critical_paths),
            "multi_hop_paths": len([p for p in paths if p["multi_hop"]]),
            "excess_permission_ratio": ratio,
            "excess_detail": f"{excessive_stmts} of {len(attached_allow)} attached Allow statements are wildcard/over-broad",
            "admin_identities": [i["name"] for i in identities if i["admin"]],
            "avg_blast_radius": round(sum(i["blast"]["score"] for i in principals) / len(principals), 1) if principals else 0,
            "max_blast_radius": max((i["blast"]["score"] for i in principals), default=0),
            "telemetry": {
                "credential_report": account.has_credential_report,
                "role_last_used": sum(1 for r in account.roles() if r.telemetry.get("role_last_used")),
                "users_with_activity": sum(1 for u in account.users() if u.telemetry),
                "users_total": len(account.users()),
            },
            "positive_controls": len(positives),
        },
        "findings": [f.to_dict() for f in findings],
        "attack_paths": paths,
        "identities": identities,
        "remediations": remediations,
        "positive_controls": positives,
        "policies": {k: {"name": p.name, "kind": p.kind, "arn": p.arn, "document": p.document, "synthesized": p.synthesized,
                         "attached_to": [ctx.identities[a].name for a in ctx.direct_holders.get(k, []) if a in ctx.identities],
                         "effective_for": [ctx.identities[a].name for a in ctx.holders.get(k, []) if a in ctx.identities]}
                     for k, p in ctx.policies.items() if k in ctx.holders or k in ctx.direct_holders or p.kind == "customer-managed"},
        "graph": to_cytoscape(G, paths),
        "mitre": {k: v for k, v in MITRE_NAMES.items() if any(k in f.mitre for f in findings)},
    }
    return result


def analyze(data: Any, source: str = "upload", now: Optional[datetime] = None, stale_days: int = 90) -> dict[str, Any]:
    return analyze_account(normalize(data, source), now=now, stale_days=stale_days)
