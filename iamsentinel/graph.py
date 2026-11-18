"""Identity -> Policy -> Resource / Trust attack graph (networkx), multi-hop attack paths and blast radius."""
from __future__ import annotations

from collections import defaultdict
from typing import Optional

import networkx as nx

from .catalog import CATEGORIES, SENSITIVE_ACTIONS
from .context import Context
from .models import SEVERITY_RANK, Finding, downgrade, upgrade
from .detectors import _strong_condition
from .policy_eval import PermissionSet, action_match, probe_action, statement_is_global

CROWN = "crown:admin"
# Actions modelled as dedicated graph edges (can_assume / escalates) rather than as resource targets.
PATH_EDGE_ACTIONS = {"sts:AssumeRole", "sts:AssumeRoleWithWebIdentity", "iam:PassRole"}


def _blocked(action: str, permsets: list[PermissionSet]) -> bool:
    probe = probe_action(action)
    return all(not ps.evaluate(probe).allowed and bool(ps.evaluate(probe).hard_denies) for ps in permsets)
BROAD_SERVICE_COLLAPSE = 12
TRAVERSAL_SOURCES = ("user", "external", "anyone", "federated", "service")
HIGH_VALUE_CATS = {"credential-access", "data-read", "data-write", "data-destruction", "privilege-escalation",
                   "code-execution", "permissions-management", "defense-evasion"}


def _short(arn: str) -> str:
    if arn == "*":
        return "*"
    tail = arn.split(":")[-1]
    return tail if len(tail) < 40 else tail[:37] + "…"


def build_graph(ctx: Context, escalations: list[dict], findings: list[Finding]) -> nx.DiGraph:
    G = nx.DiGraph()
    acct = ctx.account.account_id
    sev_by_ident: dict[str, str] = defaultdict(lambda: "INFO")
    for f in findings:
        for a in f.identity_arns:
            if SEVERITY_RANK[f.severity] > SEVERITY_RANK[sev_by_ident[a]]:
                sev_by_ident[a] = f.severity
    sev_by_policy: dict[str, str] = defaultdict(lambda: "INFO")
    for f in findings:
        if f.policy_key and SEVERITY_RANK[f.severity] > SEVERITY_RANK[sev_by_policy[f.policy_key]]:
            sev_by_policy[f.policy_key] = f.severity

    def risk_of(sev: str) -> str:
        return "critical" if sev == "CRITICAL" else "warning" if sev in ("HIGH", "MEDIUM") else "normal"

    G.add_node(CROWN, label="FULL ACCOUNT CONTROL", type="crown", risk="critical", tier=7,
               detail={"description": f"Administrator-equivalent control of AWS account {acct}"})

    # ---- identities ---------------------------------------------------------------
    for ident in ctx.identities.values():
        risk = "critical" if ctx.is_admin(ident.arn) else risk_of(sev_by_ident[ident.arn])
        G.add_node(ident.arn, label=ident.name, type=ident.kind, risk=risk, tier={"user": 1, "group": 2, "role": 3}[ident.kind],
                   arn=ident.arn, severity=sev_by_ident[ident.arn])
    for ident in ctx.account.users():
        for g in ident.group_arns:
            G.add_edge(ident.arn, g, type="member_of", label="member of")

    # ---- policies + resources ---------------------------------------------------------
    used_policies = {pk for ident in ctx.identities.values() for pk in ident.policy_keys}
    for pk in used_policies:
        pol = ctx.policies.get(pk)
        if not pol:
            continue
        G.add_node(pk, label=pol.name, type="policy", kind=pol.kind, risk=risk_of(sev_by_policy[pk]), tier=4, arn=pol.arn,
                   severity=sev_by_policy[pk])
        holder_ps = [ctx.perms[a] for a in ctx.holders.get(pk, []) if a in ctx.perms]
        for st in pol.statements:
            if not st.is_allow:
                G.nodes[pk]["has_deny"] = True
                continue
            glob = statement_is_global(st)
            extra: dict = {"conditional": bool(_strong_condition(st.condition))}
            if st.actions and holder_ps and all(_blocked(a, holder_ps) for a in st.actions):
                extra.update(blocked=True, inert=True)  # neutralised by explicit Deny for every holder
            if ("*" in st.actions and glob) or (st.not_actions and not any(action_match(p, "iam:CreateUser") for p in st.not_actions) and glob):
                G.add_edge(pk, CROWN, type="grants", label=f"{st.label}: Action * / Resource *", actions=["*"], sid=st.label,
                           cats=sorted(HIGH_VALUE_CATS), tcats=[], **extra)
                continue
            if st.not_actions:
                rid = f"res:notaction:{pk}:{st.index}"
                G.add_node(rid, label=f"All services except {', '.join(st.not_actions)[:40]}", type="resource", risk="warning", tier=6,
                           sensitive=True, cats=sorted(HIGH_VALUE_CATS), services=["*"], global_scope=glob)
                G.add_edge(pk, rid, type="grants", label=f"{st.label}: NotAction", actions=[f"NotAction:{a}" for a in st.not_actions],
                           sid=st.label, cats=sorted(HIGH_VALUE_CATS), tcats=sorted(HIGH_VALUE_CATS), **extra)
                continue
            by_svc: dict[str, list[str]] = defaultdict(list)
            for a in st.actions:
                by_svc[a.split(":")[0] if ":" in a else a].append(a)
            res_label = ", ".join(_short(r) for r in st.resource_display()[:2]) + ("…" if len(st.resource_display()) > 2 else "")
            groups = [("broad", [a for acts in by_svc.values() for a in acts])] if len(by_svc) > BROAD_SERVICE_COLLAPSE else list(by_svc.items())
            for svc, acts in groups:
                cats = sorted({SENSITIVE_ACTIONS[s] for s in SENSITIVE_ACTIONS for a in acts if action_match(a, s)})
                if svc == "broad":
                    rid = f"res:broad:{pk}:{st.index}"
                    label = f"{len(by_svc)} services ({len(acts)} actions) · {res_label}"
                else:
                    rid = f"res:{svc}:{'|'.join(sorted(st.resource_display()))}"
                    label = f"{svc} · {res_label}"
                if rid not in G:
                    G.add_node(rid, label=label, type="resource", risk="resource", tier=6, sensitive=bool(cats), cats=cats,
                               services=sorted(by_svc) if svc == "broad" else [svc], global_scope=glob, resources=st.resource_display())
                else:
                    G.nodes[rid]["cats"] = sorted(set(G.nodes[rid]["cats"]) | set(cats))
                    G.nodes[rid]["sensitive"] = bool(G.nodes[rid]["cats"])
                tcats = sorted({SENSITIVE_ACTIONS[s] for s in SENSITIVE_ACTIONS if s not in PATH_EDGE_ACTIONS
                                for a in acts if action_match(a, s)})
                ordered = sorted(acts, key=lambda a: not any(action_match(a, s) for s in SENSITIVE_ACTIONS))
                label = f"{st.label}: {', '.join(ordered[:3])}{'…' if len(acts) > 3 else ''}"
                if G.has_edge(pk, rid):  # several statements of one policy hitting the same resource
                    ed = G.edges[pk, rid]
                    ed["cats"] = sorted(set(ed["cats"]) | set(cats))
                    ed["tcats"] = sorted(set(ed["tcats"]) | set(tcats)) if not extra.get("blocked") else ed["tcats"]
                    ed["actions"] = (ed["actions"] + acts)[:50]
                    if not extra.get("blocked"):
                        ed.pop("blocked", None)
                        ed.pop("inert", None)
                else:
                    G.add_edge(pk, rid, type="grants", label=label, actions=acts[:50], sid=st.label, cats=cats,
                               tcats=[] if extra.get("blocked") else tcats, **extra)

    for ident in ctx.identities.values():
        for pk in ident.policy_keys:
            if pk in G:
                G.add_edge(ident.arn, pk, type="has_policy", label="inline" if pk.startswith("inline:") else "attached")

    # ---- trust relationships ----------------------------------------------------------
    for role in ctx.account.roles():
        for t in ctx.trusts.get(role.arn, []):
            nid = t.node_id
            if nid not in G:
                if t.kind == "anyone":
                    G.add_node(nid, label="ANY AWS PRINCIPAL (*)", type="anyone", risk="critical", tier=0)
                elif t.kind == "service":
                    G.add_node(nid, label=t.value, type="service", risk="normal", tier=0)
                elif t.kind == "federated":
                    G.add_node(nid, label=t.value.split("/")[-1], type="federated", risk="warning", tier=0, arn=t.value)
                elif t.kind == "aws-account":
                    ext = t.account != acct
                    G.add_node(nid, label=f"{'External' if ext else 'This'} account {t.account}", type="external" if ext else "account",
                               risk="warning" if ext else "normal", tier=0, account=t.account)
                else:
                    G.add_node(nid, label=_short(t.value), type="external" if t.external else "principal",
                               risk="warning" if t.external else "normal", tier=0, arn=t.value)
            if not (t.kind == "aws-account" and t.account == acct):
                G.add_edge(nid, role.arn, type="trusts", label="can assume (trust)", sid=t.statement.label,
                           conditional=bool(t.statement.condition))
            else:
                G.add_edge(nid, role.arn, type="trusts", label="trusts account root", sid=t.statement.label, inert=True)
    for e in ctx.assume_edges_cached:
        G.add_edge(e.source, e.role, type="can_assume", label="sts:AssumeRole")

    # ---- escalation edges ---------------------------------------------------------------
    for esc in escalations:
        eid = f"esc:{esc['method']}:{esc['source']}"
        latent = esc["exploitability"] == "latent"
        G.add_node(eid, label=esc["name"], type="escalation", risk="critical" if esc["severity"] == "CRITICAL" else "warning", tier=5,
                   latent=latent, method=esc["method"], severity=esc["severity"], exploitability=esc["exploitability"])
        G.add_edge(esc["source"], eid, type="escalates", label=esc["method"], latent=latent)
        for t in esc["targets"]:
            if t in G:
                G.add_edge(eid, t, type="escalates", label="pass role" if esc["method"] in ("PRIV-014", "PRIV-015", "PRIV-017", "PRIV-018", "PRIV-019", "PRIV-020", "PRIV-021") else "modify", latent=latent)
        if esc["to_admin"] and not any(ctx.is_admin(t) for t in esc["targets"]):
            G.add_edge(eid, CROWN, type="escalates", label="grants self admin", latent=latent)
    return G


def _traversable(G: nx.DiGraph) -> nx.DiGraph:
    H = nx.DiGraph()
    H.add_nodes_from(G.nodes(data=True))
    H.add_edges_from((u, v, d) for u, v, d in G.edges(data=True) if not d.get("inert"))
    return H


def _edge_severity(cats: set[str], global_scope: bool) -> Optional[str]:
    cats = cats & HIGH_VALUE_CATS
    if not cats:
        return None
    sev = max((CATEGORIES[c]["severity"] for c in cats), key=lambda s: SEVERITY_RANK[s])
    if global_scope and cats & {"data-destruction", "data-write"} and cats & {"data-read"}:
        sev = "HIGH"
    return sev


def find_attack_paths(G: nx.DiGraph, max_per_source: int = 4) -> list[dict]:
    """Shortest route from every entry point (user, external account, federated IdP, wildcard principal,
    AWS service) to (a) full account control, (b) each sensitive grant edge, (c) latent escalation primitives.
    If a source reaches full control, only that path is kept (everything else is implied)."""
    H = _traversable(G)
    sources = [n for n, d in H.nodes(data=True) if d.get("type") in TRAVERSAL_SOURCES]
    grant_targets = [(u, v, d) for u, v, d in H.edges(data=True)
                     if d.get("type") == "grants" and v != CROWN and _edge_severity(set(d.get("tcats", [])), H.nodes[v].get("global_scope", False))]
    latent_esc = [n for n, d in H.nodes(data=True) if d.get("type") == "escalation" and d.get("latent") and H.out_degree(n) == 0]
    paths: list[dict] = []

    def mk(s: str, nodes: list[str], sev: str, target: str) -> dict:
        edges = list(zip(nodes, nodes[1:]))
        latent = any(H.nodes[n].get("latent") for n in nodes)
        if latent and sev == "CRITICAL":
            sev = "HIGH"
        stype = H.nodes[s]["type"]
        first_conditional = bool(edges) and H.edges[edges[0]].get("conditional")
        if stype in ("anyone", "external", "federated") and not first_conditional:
            sev = upgrade(sev)
        elif stype == "service":
            sev = downgrade(sev)
        if any(H.edges[e].get("type") == "grants" and H.edges[e].get("conditional") for e in edges):
            sev = downgrade(sev)
        etypes = [H.edges[e]["type"] for e in edges]
        return {
            "source": s, "target": target, "nodes": nodes, "edges": [f"{u}->{v}" for u, v in edges], "hops": len(edges),
            "severity": sev, "exploitability": "latent" if latent else "confirmed",
            "multi_hop": any(x in ("member_of", "can_assume", "escalates", "trusts") for x in etypes),
            "source_label": H.nodes[s]["label"], "target_label": H.nodes[target]["label"],
            "steps": [{"id": n, "label": H.nodes[n]["label"], "type": H.nodes[n]["type"],
                       "via": H.edges[(nodes[i - 1], n)]["label"] if i else None} for i, n in enumerate(nodes)],
        }

    for s in sources:
        reach = nx.descendants(H, s)
        if CROWN in reach:
            paths.append(mk(s, nx.shortest_path(H, s, CROWN), "CRITICAL", CROWN))
            continue
        found = []
        seen_targets: set[str] = set()
        for u, v, d in grant_targets:
            if u not in reach or v in seen_targets:
                continue
            sev = _edge_severity(set(d["tcats"]), H.nodes[v].get("global_scope", False))
            found.append(mk(s, nx.shortest_path(H, s, u) + [v], sev, v))
            seen_targets.add(v)
        for e in latent_esc:
            if e in reach:
                found.append(mk(s, nx.shortest_path(H, s, e), "HIGH", e))
        found.sort(key=lambda p: (-SEVERITY_RANK[p["severity"]], p["hops"]))
        paths += found[:max_per_source]
    paths.sort(key=lambda p: (-SEVERITY_RANK[p["severity"]], -p["hops"]))
    for i, p in enumerate(paths, 1):
        p["id"] = f"PATH-{i:03d}"
        p["narrative"] = " → ".join(f"{st['label']}" if not st["via"] else f"[{st['via']}] {st['label']}" for st in p["steps"])
    return paths


def path_findings(paths: list[dict]) -> list[Finding]:
    out = []
    for p in paths:
        if not p["multi_hop"] or SEVERITY_RANK[p["severity"]] < 3 or p["hops"] < 2:
            continue
        out.append(Finding(
            rule_id="PATH-001", title=f"Multi-hop attack path: {p['source_label']} → {p['target_label']} ({p['hops']} hops)",
            severity=p["severity"], category="Attack Path",
            description="Graph traversal found an indirect route: " + p["narrative"],
            attack_scenario="Each hop is individually 'reasonable'; chained together they give the source principal the target capability.",
            recommendation="Break the weakest link: narrow the trust/assume permission, remove the escalation primitive, or scope the final grant.",
            identity_arns=[p["source"]] if p["source"].startswith("arn:") else [], identity_names=[p["source_label"]],
            exploitability=p["exploitability"], mitre=["T1078.004", "T1098.003"], notes=[f"Path id {p['id']}"]))
    return out


# ======================================================================================
# Blast radius
# ======================================================================================
def blast_radius(ctx: Context, G: nx.DiGraph, arn: str, findings: list[Finding]) -> dict:
    H = _traversable(G)
    ident = ctx.identities[arn]
    reach = nx.descendants(H, arn) if arn in H else set()
    confirmed = H.subgraph([n for n in H if not H.nodes[n].get("latent")])
    admin_direct = ctx.is_admin(arn)
    admin_path = (not admin_direct) and CROWN in reach and arn in confirmed and nx.has_path(confirmed, arn, CROWN)
    roles = [n for n in reach if H.nodes[n].get("type") == "role"]
    cats: dict[str, set[str]] = defaultdict(set)
    for who in [arn] + roles:
        for c, acts in ctx.sensitive_allowed(who).items():
            cats[c].update(acts)
    services = {a.split(":")[0] for acts in cats.values() for a in acts}
    factors = []
    if admin_direct:
        factors.append(("Administrator privileges", 80, "Action * on Resource * (direct)"))
    elif admin_path:
        factors.append(("Administrator via attack path", 75, "Reaches FULL ACCOUNT CONTROL through graph traversal"))
    else:
        pts = min(50, sum(CATEGORIES[c]["weight"] for c in cats))
        if pts:
            factors.append(("Sensitive capabilities", pts, ", ".join(CATEGORIES[c]["label"] for c in sorted(cats))))
        b = min(10, 2 * len(services))
        if b:
            factors.append(("Sensitive service breadth", b, f"{len(services)} services: {', '.join(sorted(services)[:8])}"))
    mine = [f for f in findings if arn in f.identity_arns]
    rules = {f.rule_id for f in mine}
    esc = [f for f in mine if f.category == "Privilege Escalation"]
    if esc and not admin_direct and not admin_path:
        latent = all(f.exploitability == "latent" for f in esc)
        factors.append(("Privilege escalation primitive", 8 if latent else 12, ", ".join(sorted({f.rule_id for f in esc}))))
    if ident.kind == "role":
        exp = 0
        why = []
        weights = {"TRUST-001": 20, "TRUST-007": 20, "TRUST-002": 15, "TRUST-005": 15, "TRUST-003": 5}
        for f in mine:
            w = weights.get(f.rule_id)
            if w:
                if f.rule_id == "TRUST-001" and f.severity != "CRITICAL":
                    w = 10
                exp = max(exp, w)
                why.append(f.title)
        if exp:
            factors.append(("Cross-account / external exposure", exp, "; ".join(why[:3])))
    elif ident.kind == "user" and (ident.policy_keys or ident.group_arns):
        factors.append(("Long-lived user credentials", 5, "IAM user (password / access keys)"))
    if rules & {"ADMIN-001", "WILD-002", "RES-001", "WILD-004"} and not admin_direct:
        factors.append(("Wildcard resource scope", 10, "Sensitive actions on Resource \"*\""))
    elif admin_direct:
        factors.append(("Wildcard resource scope", 10, "Resource \"*\""))
    if rules & {"HYG-002", "STALE-001", "STALE-002", "STALE-003"}:
        factors.append(("Identity hygiene", 5, "recently created privileged / dormant credentials"))
    score = min(100, sum(p for _, p, _ in factors))
    level = "CRITICAL" if score >= 80 else "HIGH" if score >= 55 else "MEDIUM" if score >= 30 else "LOW"
    return {
        "score": score, "level": level, "factors": [{"factor": a, "points": b, "detail": c} for a, b, c in factors],
        "reachable_roles": [H.nodes[r]["label"] for r in roles], "sensitive_services": sorted(services),
        "capabilities": {CATEGORIES[c]["label"]: sorted(v)[:25] for c, v in cats.items()},
        "admin": admin_direct or admin_path, "admin_via_path": admin_path,
    }


def to_cytoscape(G: nx.DiGraph, paths: list[dict]) -> dict:
    on_path_nodes: dict[str, list[str]] = defaultdict(list)
    on_path_edges: dict[str, list[str]] = defaultdict(list)
    for p in paths:
        for n in p["nodes"]:
            on_path_nodes[n].append(p["id"])
        for e in p["edges"]:
            on_path_edges[e].append(p["id"])
    nodes = []
    for n, d in G.nodes(data=True):
        data = {k: v for k, v in d.items() if k not in ("detail",)}
        data.update({"id": n, "paths": on_path_nodes.get(n, [])})
        nodes.append({"data": data})
    edges = []
    for i, (u, v, d) in enumerate(G.edges(data=True)):
        data = {k: v2 for k, v2 in d.items()}
        data.update({"id": f"e{i}", "source": u, "target": v, "paths": on_path_edges.get(f"{u}->{v}", [])})
        edges.append({"data": data})
    return {"nodes": nodes, "edges": edges}
