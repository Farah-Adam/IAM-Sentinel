"""Normalized domain model for an IAM account snapshot."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Optional

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def downgrade(sev: str, levels: int = 1) -> str:
    rank = max(0, SEVERITY_RANK[sev] - levels)
    return {v: k for k, v in SEVERITY_RANK.items()}[rank]


def upgrade(sev: str, levels: int = 1) -> str:
    rank = min(4, SEVERITY_RANK[sev] + levels)
    return {v: k for k, v in SEVERITY_RANK.items()}[rank]


def as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


@dataclass
class Statement:
    """A single IAM policy statement, normalized so every field is a list/dict."""

    index: int
    sid: str
    effect: str
    actions: list[str]
    not_actions: list[str]
    resources: list[str]
    not_resources: list[str]
    condition: dict
    principal: Any
    not_principal: Any
    raw: dict

    @classmethod
    def parse(cls, raw: dict, index: int) -> "Statement":
        return cls(
            index=index,
            sid=str(raw.get("Sid") or ""),
            effect=str(raw.get("Effect", "Allow")),
            actions=[str(a) for a in as_list(raw.get("Action"))],
            not_actions=[str(a) for a in as_list(raw.get("NotAction"))],
            resources=[str(r) for r in as_list(raw.get("Resource"))],
            not_resources=[str(r) for r in as_list(raw.get("NotResource"))],
            condition=raw.get("Condition") or {},
            principal=raw.get("Principal"),
            not_principal=raw.get("NotPrincipal"),
            raw=raw,
        )

    @property
    def is_allow(self) -> bool:
        return self.effect.lower() == "allow"

    @property
    def is_deny(self) -> bool:
        return self.effect.lower() == "deny"

    @property
    def label(self) -> str:
        return self.sid if self.sid else f"Statement[{self.index}]"

    def action_display(self) -> list[str]:
        return self.actions if self.actions else [f"NotAction: {a}" for a in self.not_actions]

    def resource_display(self) -> list[str]:
        return self.resources if self.resources else [f"NotResource: {r}" for r in self.not_resources]


@dataclass
class Policy:
    key: str  # unique id across the snapshot
    name: str
    kind: str  # aws-managed | customer-managed | inline | trust
    document: dict
    statements: list[Statement]
    arn: Optional[str] = None
    owner_arn: Optional[str] = None  # inline / trust owner
    default_version: Optional[str] = None
    attachment_count: Optional[int] = None
    synthesized: bool = False  # document reconstructed from built-in knowledge base

    @classmethod
    def from_document(cls, key: str, name: str, kind: str, document: dict, **kw: Any) -> "Policy":
        stmts = [Statement.parse(s, i) for i, s in enumerate(as_list((document or {}).get("Statement")))]
        return cls(key=key, name=name, kind=kind, document=document or {}, statements=stmts, **kw)


@dataclass
class AccessKey:
    key_id: str
    active: bool
    last_rotated: Optional[datetime]
    last_used: Optional[datetime]


@dataclass
class Identity:
    arn: str
    name: str
    kind: str  # user | group | role
    id: str = ""
    path: str = "/"
    create_date: Optional[datetime] = None
    policy_keys: list[str] = field(default_factory=list)
    group_arns: list[str] = field(default_factory=list)
    member_arns: list[str] = field(default_factory=list)  # for groups
    trust: Optional[Policy] = None
    boundary_arn: Optional[str] = None
    last_used: Optional[datetime] = None
    last_used_region: Optional[str] = None
    password_last_used: Optional[datetime] = None
    password_enabled: Optional[bool] = None
    mfa_active: Optional[bool] = None
    access_keys: list[AccessKey] = field(default_factory=list)
    instance_profiles: list[str] = field(default_factory=list)
    tags: dict = field(default_factory=dict)
    telemetry: dict = field(default_factory=dict)  # which usage signals were present

    @property
    def is_service_role(self) -> bool:
        return self.kind == "role" and (self.path.startswith("/aws-service-role/") or self.path.startswith("/service-role/"))


@dataclass
class Account:
    account_id: str
    identities: dict[str, Identity]
    policies: dict[str, Policy]
    source: str
    generated_at: Optional[datetime] = None
    has_credential_report: bool = False
    warnings: list[str] = field(default_factory=list)

    def users(self) -> list[Identity]:
        return [i for i in self.identities.values() if i.kind == "user"]

    def groups(self) -> list[Identity]:
        return [i for i in self.identities.values() if i.kind == "group"]

    def roles(self) -> list[Identity]:
        return [i for i in self.identities.values() if i.kind == "role"]


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    category: str
    description: str
    attack_scenario: str
    recommendation: str
    identity_arns: list[str] = field(default_factory=list)
    identity_names: list[str] = field(default_factory=list)
    policy_name: Optional[str] = None
    policy_arn: Optional[str] = None
    policy_key: Optional[str] = None
    policy_kind: Optional[str] = None
    sid: Optional[str] = None
    statement_index: Optional[int] = None
    effect: Optional[str] = None
    actions: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    condition: Optional[dict] = None
    offending_actions: list[str] = field(default_factory=list)
    exploitability: str = "confirmed"  # confirmed | latent | conditional | informational
    mitre: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    remediation_id: Optional[str] = None
    id: str = ""

    def to_dict(self) -> dict:
        return asdict(self)
