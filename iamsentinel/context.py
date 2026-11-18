"""Shared analysis context: effective permission sets, trust relationships, assume-role reachability."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from .catalog import SENSITIVE_ACTIONS
from .models import Account, Identity, Policy, Statement, as_list
from .policy_eval import Decision, PermissionSet, action_match

ASSUME_ACTIONS = ("sts:AssumeRole", "sts:AssumeRoleWithWebIdentity", "sts:AssumeRoleWithSAML")


@dataclass
class TrustEntry:
    """One principal that a role's trust policy allows to assume it."""

    kind: str  # anyone | aws-account | aws-principal | service | federated | not-principal
    value: str
    account: Optional[str]
    external: bool
    statement: Statement
    actions: list[str]

    @property
    def condition_keys(self) -> set[str]:
        keys: set[str] = set()
        for _op, kv in (self.statement.condition or {}).items():
            if isinstance(kv, dict):
                keys.update(k.lower() for k in kv)
        return keys

    def condition_values(self, key: str) -> list[str]:
        out: list[str] = []
        for _op, kv in (self.statement.condition or {}).items():
            if isinstance(kv, dict):
                for k, v in kv.items():
                    if k.lower() == key.lower():
                        out.extend(str(x) for x in as_list(v))
        return out

    @property
    def node_id(self) -> str:
        if self.kind == "anyone":
            return "principal:anyone"
        if self.kind == "service":
            return f"svc:{self.value}"
        if self.kind == "federated":
            return f"fed:{self.value}"
        if self.kind == "aws-account":
            return f"acct:{self.account}"
        return self.value  # aws-principal: user/role ARN


def _account_of(principal: str) -> Optional[str]:
    if re.fullmatch(r"\d{12}", principal):
        return principal
    m = re.match(r"arn:aws[\w-]*:(?:iam|sts)::(\d{12}):", principal)
    return m.group(1) if m else None


def parse_trust(role: Identity, account_id: str) -> list[TrustEntry]:
    entries: list[TrustEntry] = []
    if not role.trust:
        return entries
    for st in role.trust.statements:
        if not st.is_allow:
            continue
        actions = st.actions or ["sts:AssumeRole"]
        if not any(action_match(a, x) for a in actions for x in ASSUME_ACTIONS):
            continue
        if st.not_principal is not None:
            entries.append(TrustEntry("not-principal", "NotPrincipal", None, True, st, actions))
            continue
        pr = st.principal
        if pr == "*" or (isinstance(pr, dict) and "*" in as_list(pr.get("AWS"))):
            entries.append(TrustEntry("anyone", "*", None, True, st, actions))
        if not isinstance(pr, dict):
            continue
        for p in as_list(pr.get("AWS")):
            if p == "*":
                continue
            acct = _account_of(p)
            external = acct is not None and acct != account_id
            if re.fullmatch(r"\d{12}", p) or p.endswith(":root"):
                entries.append(TrustEntry("aws-account", f"arn:aws:iam::{acct}:root", acct, external, st, actions))
            else:
                entries.append(TrustEntry("aws-principal", p, acct, external, st, actions))
        for s in as_list(pr.get("Service")):
            entries.append(TrustEntry("service", s, None, False, st, actions))
        for f in as_list(pr.get("Federated")):
            entries.append(TrustEntry("federated", f, _account_of(f), False, st, actions))
    return entries


@dataclass
class AssumeEdge:
    source: str
    role: str
    via: str  # trust-direct | trust-account | trust-anyone
    decision: Optional[Decision] = None


class Context:
    def __init__(self, account: Account, now: Optional[datetime] = None, stale_days: int = 90):
        self.account = account
        self.now = now or datetime.now(timezone.utc)
        self.stale_days = stale_days
        self.policies = account.policies
        self.identities = account.identities
        self.sources: dict[str, list[tuple[Policy, Statement, str]]] = {}
        self.perms: dict[str, PermissionSet] = {}
        self.holders: dict[str, list[str]] = {}  # policy key -> principal ARNs that effectively receive it
        self.direct_holders: dict[str, list[str]] = {}  # policy key -> identities it is attached to
        self.trusts: dict[str, list[TrustEntry]] = {}
        self.admin: dict[str, Optional[Decision]] = {}
        self._build()

    # ------------------------------------------------------------------
    def _build(self) -> None:
        for ident in self.identities.values():
            for pk in ident.policy_keys:
                self.direct_holders.setdefault(pk, []).append(ident.arn)
        for ident in self.identities.values():
            stmts: list[tuple[Policy, Statement, str]] = []
            for pk in ident.policy_keys:
                pol = self.policies.get(pk)
                if pol:
                    stmts += [(pol, s, "direct") for s in pol.statements]
                    self.holders.setdefault(pk, []).append(ident.arn)
            for garn in ident.group_arns:
                g = self.identities.get(garn)
                for pk in g.policy_keys if g else []:
                    pol = self.policies.get(pk)
                    if pol:
                        stmts += [(pol, s, f"group:{g.name}") for s in pol.statements]
                        if ident.arn not in self.holders.setdefault(pk, []):
                            self.holders[pk].append(ident.arn)
            self.sources[ident.arn] = stmts
            boundary = self.policies.get(ident.boundary_arn) if ident.boundary_arn else None
            self.perms[ident.arn] = PermissionSet([(p, s) for p, s, _ in stmts], boundary)
            self.admin[ident.arn] = self.perms[ident.arn].is_full_admin()
            if ident.kind == "role":
                self.trusts[ident.arn] = parse_trust(ident, self.account.account_id)

    # ------------------------------------------------------------------
    def principals(self) -> list[Identity]:
        return [i for i in self.identities.values() if i.kind in ("user", "role")]

    def is_admin(self, arn: str) -> bool:
        return self.admin.get(arn) is not None

    def days_since(self, dt: Optional[datetime]) -> Optional[int]:
        if dt is None:
            return None
        return max(0, (self.now - dt).days)

    def sensitive_allowed(self, arn: str) -> dict[str, list[str]]:
        """category -> allowed sensitive actions (deny-aware)."""
        ps = self.perms[arn]
        out: dict[str, list[str]] = {}
        for action, cat in SENSITIVE_ACTIONS.items():
            if ps.evaluate(action).allowed:
                out.setdefault(cat, []).append(action)
        return out

    def assume_edges(self) -> list[AssumeEdge]:
        """Which in-account principals can assume which roles (trust AND identity policy)."""
        edges: list[AssumeEdge] = []
        acct = self.account.account_id
        for role in self.account.roles():
            for t in self.trusts.get(role.arn, []):
                if t.kind == "aws-principal" and t.value in self.identities and t.value != role.arn:
                    edges.append(AssumeEdge(t.value, role.arn, "trust-direct"))
                elif (t.kind == "aws-account" and t.account == acct) or t.kind == "anyone":
                    for p in self.principals():
                        if p.arn == role.arn:
                            continue
                        d = self.perms[p.arn].evaluate("sts:AssumeRole", role.arn)
                        if d.allowed:
                            edges.append(AssumeEdge(p.arn, role.arn, "trust-account" if t.kind != "anyone" else "trust-anyone", d))
        uniq: dict[tuple[str, str], AssumeEdge] = {}
        for e in edges:
            uniq.setdefault((e.source, e.role), e)
        return list(uniq.values())

    def can_assume(self, principal_arn: str, role_arn: str) -> bool:
        return any(e.source == principal_arn and e.role == role_arn for e in self.assume_edges_cached)

    @property
    def assume_edges_cached(self) -> list[AssumeEdge]:
        if not hasattr(self, "_assume_cache"):
            self._assume_cache = self.assume_edges()
        return self._assume_cache
