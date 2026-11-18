"""Ingestion + normalization of AWS IAM exports.

Supported inputs
- `aws iam get-account-authorization-details` output (UserDetailList / GroupDetailList /
  RoleDetailList / Policies), including URL-encoded policy documents as returned by the raw API.
- Optional `CredentialReport` key: list of rows (dicts) or the raw CSV string / base64 content
  from `aws iam get-credential-report`.
- Optional `aws iam list-users` style `Users` list (adds PasswordLastUsed telemetry).
- A bare policy document ({"Version", "Statement"}) - wrapped in a synthetic identity so a
  single policy can be linted.
"""
from __future__ import annotations

import base64
import csv
import io
import json
import re
import urllib.parse
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .catalog import KNOWN_MANAGED_DOCUMENTS
from .models import AccessKey, Account, Identity, Policy, as_list


class IAMParseError(ValueError):
    pass


def parse_time(value: Any) -> Optional[datetime]:
    if value in (None, "", "N/A", "no_information", "not_supported"):
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    s = str(value).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _decode_document(doc: Any) -> dict:
    if isinstance(doc, dict):
        return doc
    if isinstance(doc, str):
        text = doc
        if text.lstrip().startswith("%7B") or "%22" in text:
            text = urllib.parse.unquote(text)
        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            raise IAMParseError(f"Policy document is not valid JSON: {e}") from e
    return {}


def _account_from_arn(arn: str) -> Optional[str]:
    m = re.match(r"arn:aws[\w-]*:iam::(\d{12}):", arn or "")
    return m.group(1) if m else None


def _parse_credential_report(raw: Any) -> list[dict]:
    if raw is None:
        return []
    if isinstance(raw, dict) and "Content" in raw:
        raw = base64.b64decode(raw["Content"]).decode("utf-8")
    if isinstance(raw, str):
        return list(csv.DictReader(io.StringIO(raw)))
    if isinstance(raw, list):
        return [r for r in raw if isinstance(r, dict)]
    return []


def load_json(path: str | Path) -> dict:
    p = Path(path)
    try:
        return json.loads(p.read_text(encoding="utf-8-sig"))
    except FileNotFoundError as e:
        raise IAMParseError(f"File not found: {p}") from e
    except json.JSONDecodeError as e:
        raise IAMParseError(f"{p.name} is not valid JSON: {e}") from e


def normalize(data: Any, source: str = "upload") -> Account:
    if not isinstance(data, dict):
        raise IAMParseError("Top-level JSON must be an object")

    warnings: list[str] = []
    if "Statement" in data and not any(k in data for k in ("UserDetailList", "RoleDetailList", "Policies")):
        data = {
            "UserDetailList": [{
                "UserName": "uploaded-policy-subject",
                "Arn": "arn:aws:iam::000000000000:user/uploaded-policy-subject",
                "UserPolicyList": [{"PolicyName": Path(source).stem or "uploaded-policy", "PolicyDocument": data}],
            }]
        }
        warnings.append("Input was a single policy document; it was analysed as an inline policy of a synthetic user.")

    known_keys = {"UserDetailList", "GroupDetailList", "RoleDetailList", "Policies", "Users", "CredentialReport"}
    if not known_keys & set(data):
        raise IAMParseError(
            "Unrecognised IAM export. Expected output of `aws iam get-account-authorization-details` "
            "(UserDetailList/GroupDetailList/RoleDetailList/Policies) or a policy document."
        )

    policies: dict[str, Policy] = {}
    identities: dict[str, Identity] = {}

    # ---- managed policies -----------------------------------------------------------
    for p in as_list(data.get("Policies")):
        arn = p.get("Arn", "")
        versions = as_list(p.get("PolicyVersionList"))
        default = next((v for v in versions if v.get("IsDefaultVersion")), versions[0] if versions else None)
        doc = _decode_document(default.get("Document")) if default else {}
        kind = "aws-managed" if ":aws:policy/" in arn else "customer-managed"
        policies[arn] = Policy.from_document(
            arn, p.get("PolicyName", arn.split("/")[-1]), kind, doc, arn=arn,
            default_version=p.get("DefaultVersionId"), attachment_count=p.get("AttachmentCount"),
        )

    def managed_ref(ref: dict) -> str:
        arn = ref.get("PolicyArn", "")
        if arn not in policies:
            name = ref.get("PolicyName") or arn.split("/")[-1]
            doc = KNOWN_MANAGED_DOCUMENTS.get(name) if ":aws:policy/" in arn else None
            policies[arn] = Policy.from_document(
                arn, name, "aws-managed" if ":aws:policy/" in arn else "customer-managed", doc or {},
                arn=arn, synthesized=doc is not None,
            )
            if doc is None:
                warnings.append(f"Managed policy {name} is referenced but its document is not in the export; it was not evaluated.")
        return arn

    def inline(owner_arn: str, owner_kind: str, items: Any) -> list[str]:
        keys = []
        for ip in as_list(items):
            name = ip.get("PolicyName", "inline")
            key = f"inline:{owner_arn}:{name}"
            policies[key] = Policy.from_document(key, name, "inline", _decode_document(ip.get("PolicyDocument")), owner_arn=owner_arn)
            keys.append(key)
        return keys

    # ---- groups ---------------------------------------------------------------------
    group_by_name: dict[str, str] = {}
    for g in as_list(data.get("GroupDetailList")):
        arn = g.get("Arn") or f"arn:aws:iam::000000000000:group/{g.get('GroupName')}"
        ident = Identity(arn=arn, name=g.get("GroupName", arn), kind="group", id=g.get("GroupId", ""),
                         path=g.get("Path", "/"), create_date=parse_time(g.get("CreateDate")))
        ident.policy_keys = inline(arn, "group", g.get("GroupPolicyList")) + [managed_ref(r) for r in as_list(g.get("AttachedManagedPolicies"))]
        identities[arn] = ident
        group_by_name[ident.name] = arn

    # ---- users ----------------------------------------------------------------------
    for u in as_list(data.get("UserDetailList")):
        arn = u.get("Arn") or f"arn:aws:iam::000000000000:user/{u.get('UserName')}"
        ident = Identity(arn=arn, name=u.get("UserName", arn), kind="user", id=u.get("UserId", ""),
                         path=u.get("Path", "/"), create_date=parse_time(u.get("CreateDate")),
                         tags={t.get("Key"): t.get("Value") for t in as_list(u.get("Tags"))},
                         boundary_arn=(u.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn"))
        ident.policy_keys = inline(arn, "user", u.get("UserPolicyList")) + [managed_ref(r) for r in as_list(u.get("AttachedManagedPolicies"))]
        for gname in as_list(u.get("GroupList")):
            garn = group_by_name.get(gname)
            if garn:
                ident.group_arns.append(garn)
                identities[garn].member_arns.append(arn)
            else:
                warnings.append(f"User {ident.name} is in group {gname}, which is missing from GroupDetailList.")
        if u.get("PasswordLastUsed"):
            ident.password_last_used = parse_time(u.get("PasswordLastUsed"))
            ident.telemetry["password_last_used"] = True
        identities[arn] = ident

    # ---- roles ----------------------------------------------------------------------
    for r in as_list(data.get("RoleDetailList")):
        arn = r.get("Arn") or f"arn:aws:iam::000000000000:role/{r.get('RoleName')}"
        ident = Identity(arn=arn, name=r.get("RoleName", arn), kind="role", id=r.get("RoleId", ""),
                         path=r.get("Path", "/"), create_date=parse_time(r.get("CreateDate")),
                         tags={t.get("Key"): t.get("Value") for t in as_list(r.get("Tags"))},
                         boundary_arn=(r.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn"))
        ident.policy_keys = inline(arn, "role", r.get("RolePolicyList")) + [managed_ref(x) for x in as_list(r.get("AttachedManagedPolicies"))]
        trust_doc = _decode_document(r.get("AssumeRolePolicyDocument"))
        ident.trust = Policy.from_document(f"trust:{arn}", f"{ident.name} trust policy", "trust", trust_doc, owner_arn=arn)
        ident.instance_profiles = [ip.get("InstanceProfileName", "") for ip in as_list(r.get("InstanceProfileList"))]
        if "RoleLastUsed" in r:
            ident.telemetry["role_last_used"] = True
            ident.last_used = parse_time((r.get("RoleLastUsed") or {}).get("LastUsedDate"))
            ident.last_used_region = (r.get("RoleLastUsed") or {}).get("Region")
        identities[arn] = ident

    # ---- optional list-users telemetry --------------------------------------------------
    by_name = {i.name: i for i in identities.values() if i.kind == "user"}
    for u in as_list(data.get("Users")):
        ident = by_name.get(u.get("UserName"))
        if ident and u.get("PasswordLastUsed"):
            ident.password_last_used = parse_time(u["PasswordLastUsed"])
            ident.telemetry["password_last_used"] = True

    # ---- optional credential report -----------------------------------------------------
    rows = _parse_credential_report(data.get("CredentialReport"))
    for row in rows:
        ident = by_name.get(row.get("user"))
        if not ident:
            continue
        ident.telemetry["credential_report"] = True
        ident.password_enabled = str(row.get("password_enabled", "")).lower() == "true"
        ident.mfa_active = str(row.get("mfa_active", "")).lower() == "true"
        if row.get("password_last_used") not in (None, "", "N/A", "no_information"):
            ident.password_last_used = parse_time(row.get("password_last_used"))
        for n in ("1", "2"):
            if str(row.get(f"access_key_{n}_active", "")).lower() in ("true", "false") and row.get(f"access_key_{n}_last_rotated") not in (None, "", "N/A"):
                ident.access_keys.append(AccessKey(
                    key_id=f"access_key_{n}",
                    active=str(row.get(f"access_key_{n}_active")).lower() == "true",
                    last_rotated=parse_time(row.get(f"access_key_{n}_last_rotated")),
                    last_used=parse_time(row.get(f"access_key_{n}_last_used_date")),
                ))

    # ---- account id -----------------------------------------------------------------
    counts = Counter(a for a in (_account_from_arn(i.arn) for i in identities.values()) if a)
    for p in policies.values():
        a = _account_from_arn(p.arn or "")
        if a:
            counts[a] += 1
    account_id = counts.most_common(1)[0][0] if counts else "000000000000"

    return Account(account_id=account_id, identities=identities, policies=policies, source=source,
                   has_credential_report=bool(rows), warnings=warnings)


def load_account(path: str | Path) -> Account:
    return normalize(load_json(path), source=str(Path(path).name))
