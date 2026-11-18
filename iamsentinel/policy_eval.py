"""Deny-aware effective-permission evaluation.

Implements the parts of the AWS policy evaluation logic that can be decided statically from an
IAM export:

* explicit Deny always wins over Allow (unconditional Deny = hard block, conditional Deny =
  guardrail that *may* block - reported, never silently ignored),
* `Action` / `NotAction` and `Resource` / `NotResource` with `*` and `?` wildcards,
* permissions boundaries (an action must be allowed by both identity policies and boundary),
* conditional Allows are tracked so detectors can lower severity / explain context.

Service control policies, session policies and resource-based policies are out of scope
(not contained in an IAM export) and are documented as limitations.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Iterable, Optional

from .models import Policy, Statement

SENTINEL_ACTION = "zzsentinelservice:ZzSentinelAction"  # only matched by a true "*" wildcard


@lru_cache(maxsize=8192)
def _compile(pattern: str, ci: bool) -> re.Pattern:
    rx = "^" + re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".") + "$"
    return re.compile(rx, re.IGNORECASE if ci else 0)


def action_match(pattern: str, action: str) -> bool:
    """IAM action names are case-insensitive."""
    return bool(_compile(pattern, True).match(action))


def resource_match(pattern: str, resource: str) -> bool:
    """ARNs are (mostly) case-sensitive."""
    return bool(_compile(pattern, False).match(resource))


def statement_matches_action(stmt: Statement, action: str) -> bool:
    if stmt.actions:
        return any(action_match(p, action) for p in stmt.actions)
    if stmt.not_actions:
        return not any(action_match(p, action) for p in stmt.not_actions)
    return False


def statement_matches_resource(stmt: Statement, resource: str) -> bool:
    """`resource == "*"` asks: does the statement apply to *some* resource."""
    if resource == "*":
        if stmt.resources:
            return True
        if stmt.not_resources:
            return "*" not in stmt.not_resources
        return True  # trust policies have no Resource
    if stmt.resources:
        return any(resource_match(p, resource) for p in stmt.resources)
    if stmt.not_resources:
        return not any(resource_match(p, resource) for p in stmt.not_resources)
    return True


def statement_is_global(stmt: Statement) -> bool:
    """True if the statement applies to every resource (Resource "*" or a NotResource carve-out)."""
    return "*" in stmt.resources or bool(stmt.not_resources)


def is_wildcard_action(a: str) -> bool:
    return "*" in a or "?" in a


def probe_action(a: str) -> str:
    """Concrete action name that a wildcard pattern covers but that only another wildcard would also cover.
    Used to ask "is this whole pattern neutralised by a Deny?"."""
    if a == "*":
        return SENTINEL_ACTION
    return a.replace("*", "Zz").replace("?", "Z")


@dataclass
class Grant:
    policy: Policy
    statement: Statement

    @property
    def conditional(self) -> bool:
        return bool(self.statement.condition)


@dataclass
class Decision:
    action: str
    resource: str
    allowed: bool
    grants: list[Grant] = field(default_factory=list)
    hard_denies: list[Grant] = field(default_factory=list)
    conditional_denies: list[Grant] = field(default_factory=list)
    partial_denies: list[Grant] = field(default_factory=list)
    boundary_blocked: bool = False

    @property
    def global_scope(self) -> bool:
        return any(statement_is_global(g.statement) for g in self.grants)

    @property
    def conditional(self) -> bool:
        """Every grant carries a condition -> access is contextual (MFA, source IP, ...)."""
        return bool(self.grants) and all(g.conditional for g in self.grants)

    @property
    def guarded(self) -> bool:
        return bool(self.conditional_denies or self.partial_denies)

    def scoped_resources(self) -> list[str]:
        out: list[str] = []
        for g in self.grants:
            for r in g.statement.resource_display():
                if r not in out:
                    out.append(r)
        return out


class PermissionSet:
    """All statements that apply to one principal, ready for repeated evaluation."""

    def __init__(self, statements: Iterable[tuple[Policy, Statement]], boundary: Optional[Policy] = None):
        self.statements = list(statements)
        self.allows = [Grant(p, s) for p, s in self.statements if s.is_allow]
        self.denies = [Grant(p, s) for p, s in self.statements if s.is_deny]
        self.boundary = boundary
        self._cache: dict[tuple[str, str], Decision] = {}

    def evaluate(self, action: str, resource: str = "*") -> Decision:
        key = (action.lower(), resource)
        if key in self._cache:
            return self._cache[key]
        grants = [g for g in self.allows
                  if statement_matches_action(g.statement, action) and statement_matches_resource(g.statement, resource)]
        hard, cond, partial = [], [], []
        for d in self.denies:
            if not statement_matches_action(d.statement, action):
                continue
            if not statement_matches_resource(d.statement, resource):
                continue
            covers_all = resource != "*" or statement_is_global(d.statement) and not d.statement.not_resources
            if d.statement.condition:
                cond.append(d)
            elif covers_all:
                hard.append(d)
            else:
                partial.append(d)
        boundary_blocked = False
        if self.boundary is not None and grants:
            b = PermissionSet([(self.boundary, s) for s in self.boundary.statements])
            bd = b.evaluate(action, resource)
            boundary_blocked = not bd.allowed
        allowed = bool(grants) and not hard and not boundary_blocked
        dec = Decision(action, resource, allowed, grants, hard, cond, partial, boundary_blocked)
        self._cache[key] = dec
        return dec

    def allows_any(self, actions: Iterable[str], resource: str = "*") -> list[Decision]:
        return [d for d in (self.evaluate(a, resource) for a in actions) if d.allowed]

    def is_full_admin(self) -> Optional[Decision]:
        """Action "*" on Resource "*" that survives Deny evaluation."""
        d = self.evaluate(SENTINEL_ACTION)
        probes = ["iam:AttachUserPolicy", "iam:PassRole", "sts:AssumeRole", "s3:GetObject", "ec2:RunInstances"]
        if d.allowed and d.global_scope and all(self.evaluate(p).allowed for p in probes):
            return d
        return None

    def allowed_action_patterns(self) -> list[str]:
        out: list[str] = []
        for g in self.allows:
            for a in g.statement.action_display():
                if a not in out:
                    out.append(a)
        return out
