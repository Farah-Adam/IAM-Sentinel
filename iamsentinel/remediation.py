"""Smart least-privilege policy synthesizer.

For every flagged policy it produces a narrowed JSON replacement, a side-by-side diff, the list of
placeholders an operator must fill in, ready-to-run AWS CLI commands - and it *verifies itself* by
re-running the detectors on the proposed document and reporting residual risk.
"""
from __future__ import annotations

import copy
import difflib
import json
import re
import uuid
from collections import defaultdict
from typing import Any

from .catalog import (
    ADMIN_PROTECTION_DENY, OIDC_SUBJECT_KEYS, RESOURCE_TEMPLATES, SENSITIVE_ACTIONS, SERVICE_PRINCIPAL_FOR_ACTION_PREFIX,
    SERVICE_WORKLOAD_ACTIONS, access_level,
)
from .context import Context, parse_trust
from .detectors import scan_policy
from .models import SEVERITY_RANK, Finding, Identity, Policy, as_list
from .policy_eval import PermissionSet, action_match, is_wildcard_action, statement_is_global

# Actions that only support Resource "*" (no resource-level permissions).
STAR_ONLY = {
    "s3:listallmybuckets", "ecr:getauthorizationtoken", "sts:getcalleridentity", "cloudtrail:startquery",
    "support:createcase", "ec2:describeinstances", "lambda:listfunctions", "ssm:describeparameters",
    "secretsmanager:listsecrets", "kms:listkeys", "kms:listaliases", "dynamodb:listtables", "sqs:listqueues", "sns:listtopics",
    "logs:describeloggroups", "iam:listroles", "iam:listpolicies", "rds:describedbinstances", "cloudformation:liststacks",
    "ssmmessages:createcontrolchannel", "ssmmessages:createdatachannel", "ssmmessages:opencontrolchannel",
    "ssmmessages:opendatachannel", "ec2messages:acknowledgemessage", "ec2messages:deletemessage", "ec2messages:failmessage",
    "ec2messages:getendpoint", "ec2messages:getmessages", "ec2messages:sendreply", "ssm:updateinstanceinformation",
    "ssm:listassociations", "ssm:listinstanceassociations", "ssm:putinventory", "ssm:putcomplianceitems",
}
PLACEHOLDER_RX = re.compile(r"<[A-Z0-9_\-]+>")


def _templates(svc: str, acct: str) -> list[str]:
    t = RESOURCE_TEMPLATES.get(svc) or [f"arn:aws:{svc}:<REGION>:{{acct}}:<{svc.upper().replace('-', '_')}_RESOURCE>"]
    return [x.replace("{acct}", acct) for x in t]


def _sid(base: str, suffix: str) -> str:
    pretty = "".join(part[:1].upper() + part[1:] for part in re.split(r"[-_\s]+", suffix))
    raw = re.sub(r"[^A-Za-z0-9]", "", (base or "") + pretty)
    return raw[:100] or "Scoped"


def _merge_cond(cond: dict | None, add: dict) -> dict:
    out = copy.deepcopy(cond or {})
    for op, kv in add.items():
        out.setdefault(op, {}).update(kv)
    return out


def _passed_services(ctx: Context, holders: list[Identity]) -> list[str]:
    svcs: set[str] = set()
    for h in holders:
        for _p, st, _v in ctx.sources.get(h.arn, []):
            for a in st.actions:
                pre = a.split(":")[0].lower()
                if pre in SERVICE_PRINCIPAL_FOR_ACTION_PREFIX and pre != "iam":
                    svcs.add(SERVICE_PRINCIPAL_FOR_ACTION_PREFIX[pre])
    return sorted(svcs)


# ======================================================================================
# Identity / permission policies
# ======================================================================================
def synthesize_policy(ctx: Context, policy: Policy, holders: list[Identity]) -> tuple[dict, list[str]]:
    acct = ctx.account.account_id
    human = any(h.kind == "user" for h in holders)
    changes: list[str] = []
    new_stmts: list[dict] = []
    deny_carve: list[str] = []
    passed = _passed_services(ctx, holders)

    for st in policy.statements:
        raw = copy.deepcopy(st.raw)
        if not st.is_allow:
            new_stmts.append(raw)
            continue
        glob = statement_is_global(st)

        # ---- Full admin --------------------------------------------------------------------
        if "*" in st.actions and glob:
            if human:
                new_stmts.append({"Sid": "AdminOnlyWithRecentMFA", "Effect": "Allow", "Action": "*", "Resource": "*",
                                  "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"},
                                                "NumericLessThan": {"aws:MultiFactorAuthAge": "3600"}}})
                changes.append("Admin access now requires an MFA-authenticated session younger than 1 hour (blocks leaked access keys).")
            else:
                new_stmts.append({"Sid": "ScopedAdmin", "Effect": "Allow", "Action": "*", "Resource": "*",
                                  "Condition": {"StringEquals": {"aws:RequestedRegion": ["<PRIMARY_REGION>"]}}})
                changes.append("Admin access restricted to the approved region(s).")
            new_stmts.append({"Sid": "ProtectSecurityTooling", "Effect": "Deny", "Action": ADMIN_PROTECTION_DENY, "Resource": "*"})
            new_stmts.append({"Sid": "DenyPrivilegedIdentityCreation", "Effect": "Deny",
                              "Action": ["iam:CreateUser", "iam:CreateAccessKey", "iam:CreateLoginProfile"], "Resource": "*",
                              "Condition": {"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}}})
            changes.append("Explicit Deny protects CloudTrail, GuardDuty, Config, Security Hub and Access Analyzer from tampering.")
            changes.append("Preferred end-state: delete standing admin; grant an assumable break-glass role / IAM Identity Center permission set.")
            continue

        # ---- NotAction -----------------------------------------------------------------------
        if st.not_actions:
            new_stmts.append({"Sid": _sid(st.sid, "ReadOnlyBaseline"), "Effect": "Allow",
                              "Action": ["ec2:Describe*", "s3:ListAllMyBuckets", "s3:GetBucketLocation", "lambda:List*",
                                         "cloudwatch:Get*", "cloudwatch:List*", "cloudwatch:Describe*", "logs:Describe*",
                                         "dynamodb:List*", "dynamodb:Describe*", "rds:Describe*", "cloudformation:Describe*",
                                         "cloudformation:List*"], "Resource": "*"})
            new_stmts.append({"Sid": _sid(st.sid, "RequiredWrites"), "Effect": "Allow", "Action": ["<SERVICE>:<ACTION>"],
                              "Resource": [f"arn:aws:<SERVICE>:<REGION>:{acct}:<RESOURCE>"],
                              "Condition": {"StringEquals": {"aws:ResourceAccount": acct}}})
            new_stmts.append({"Sid": "ProtectSecurityTooling", "Effect": "Deny", "Action": ADMIN_PROTECTION_DENY, "Resource": "*"})
            changes.append(f"NotAction ({', '.join(st.not_actions)}) replaced by an explicit read-only baseline + an allow-list for required writes.")
            continue

        keep_orig: list[str] = []
        keep_star: list[str] = []
        scoped: dict[str, list[str]] = defaultdict(list)
        for a in st.actions:
            svc, _, verb = a.partition(":")
            svc_l = svc.lower()
            if verb == "*":
                wl = SERVICE_WORKLOAD_ACTIONS.get(svc_l)
                if wl:
                    keep_star += wl.get("list", []) if glob else []
                    scoped[svc_l] += wl.get("bucket", []) + wl.get("object", [])
                    changes.append(f"{a} replaced by {len(wl.get('list', [])) + len(wl.get('bucket', [])) + len(wl.get('object', []))} "
                                   f"day-to-day {svc} actions; admin/destructive APIs (policy, ACL, delete, encryption config) removed.")
                else:
                    keep_star += [f"{svc}:Describe*", f"{svc}:List*", f"{svc}:Get*"]
                    changes.append(f"{a} reduced to read-only ({svc}:Describe*/List*/Get*) - add specific write actions if required.")
            elif is_wildcard_action(a):
                hits = [s for s in SENSITIVE_ACTIONS if action_match(a, s)]
                keep_orig.append(a)
                if hits:
                    deny_carve += hits
                    changes.append(f"{a} kept but its sensitive expansions ({', '.join(hits[:4])}{'…' if len(hits) > 4 else ''}) are explicitly denied.")
            elif glob and a.lower() in {k.lower() for k in SENSITIVE_ACTIONS} and a.lower() not in STAR_ONLY:
                scoped[svc_l].append(a)
            else:
                keep_orig.append(a)

        if keep_orig or keep_star:
            s = copy.deepcopy(raw)
            s["Action"] = keep_orig + [x for x in keep_star if x not in keep_orig]
            s.pop("NotAction", None)
            new_stmts.append(s)
        for svc, acts in scoped.items():
            acts = list(dict.fromkeys(acts))
            if svc == "iam" and any(x.lower() == "iam:passrole" for x in acts):
                rest = [x for x in acts if x.lower() != "iam:passrole"]
                pr = {"Sid": _sid(st.sid, "PassOnlyApprovedRole"), "Effect": "Allow", "Action": "iam:PassRole",
                      "Resource": [f"arn:aws:iam::{acct}:role/<APPROVED_EXECUTION_ROLE>"]}
                if passed:
                    pr["Condition"] = {"StringEquals": {"iam:PassedToService": passed if len(passed) > 1 else passed[0]}}
                    changes.append(f"iam:PassRole scoped to one execution role and limited to iam:PassedToService = {', '.join(passed)}.")
                else:
                    changes.append("iam:PassRole scoped to a single approved role ARN.")
                new_stmts.append(pr)
                if not rest:
                    continue
                acts = rest
            cond = _merge_cond(st.condition, {"StringEquals": {"aws:ResourceAccount": acct}})
            if human and any(SENSITIVE_ACTIONS.get(x) in ("privilege-escalation", "permissions-management") for x in acts):
                cond = _merge_cond(cond, {"Bool": {"aws:MultiFactorAuthPresent": "true"}})
            res = _templates(svc, acct)
            if svc == "lambda" and passed == ["lambda.amazonaws.com"]:
                res = [f"arn:aws:lambda:<REGION>:{acct}:function:{re.sub(r'[^a-z0-9-]', '-', policy.name.lower())}-*"]
            new_stmts.append({"Sid": _sid(st.sid, f"Scoped-{svc}"), "Effect": "Allow", "Action": acts, "Resource": res, "Condition": cond})
            changes.append(f"{', '.join(acts[:5])}{'…' if len(acts) > 5 else ''} moved from Resource \"*\" to {', '.join(res)} with aws:ResourceAccount guardrail.")

    if deny_carve:
        new_stmts.append({"Sid": "DenySensitiveWildcardExpansions", "Effect": "Deny", "Action": sorted(set(deny_carve)), "Resource": "*"})
    if policy.kind == "aws-managed":
        changes.insert(0, f"AWS-managed policies cannot be edited: this is a customer-managed replacement for {policy.name}.")
    return {"Version": policy.document.get("Version", "2012-10-17"), "Statement": new_stmts}, list(dict.fromkeys(changes))


# ======================================================================================
# Trust policies
# ======================================================================================
def synthesize_trust(ctx: Context, role: Identity) -> tuple[dict, list[str]]:
    acct = ctx.account.account_id
    doc = copy.deepcopy(role.trust.document if role.trust else {"Version": "2012-10-17", "Statement": []})
    changes: list[str] = []
    stmts = as_list(doc.get("Statement"))
    entries = parse_trust(role, acct)
    for i, raw in enumerate(stmts):
        mine = [e for e in entries if e.statement.index == i]
        if not mine:
            continue
        cond = raw.get("Condition") or {}
        for e in mine:
            keys = e.condition_keys
            if e.kind == "not-principal":
                raw.pop("NotPrincipal", None)
                raw["Principal"] = {"AWS": f"arn:aws:iam::<TRUSTED_ACCOUNT_ID>:role/<TRUSTED_ROLE>"}
                changes.append("NotPrincipal replaced with an explicit trusted role ARN.")
            elif e.kind == "anyone":
                raw["Principal"] = {"AWS": f"arn:aws:iam::<TRUSTED_ACCOUNT_ID>:role/<TRUSTED_ROLE>"}
                cond = _merge_cond(cond, {"StringEquals": {"aws:PrincipalOrgID": "<o-ORGANIZATION_ID>"}})
                changes.append("Wildcard principal \"*\" replaced with an explicit role ARN and pinned to your AWS Organization (aws:PrincipalOrgID).")
            elif e.kind in ("aws-account", "aws-principal") and e.external and "sts:externalid" not in keys:
                ext = str(uuid.uuid5(uuid.NAMESPACE_URL, role.arn + e.value))
                cond = _merge_cond(cond, {"StringEquals": {"sts:ExternalId": ext}})
                changes.append(f"Added sts:ExternalId = {ext} for {e.value} (share it with the third party out-of-band).")
                if e.kind == "aws-account":
                    raw["Principal"] = {"AWS": f"arn:aws:iam::{e.account}:role/<VENDOR_INTEGRATION_ROLE>"}
                    changes.append(f"Account root of {e.account} narrowed to a single vendor integration role.")
            elif e.kind == "aws-account" and e.account == acct and ctx.is_admin(role.arn):
                raw["Principal"] = {"AWS": f"arn:aws:iam::{acct}:role/<APPROVED_ADMIN_CALLER>"}
                cond = _merge_cond(cond, {"Bool": {"aws:MultiFactorAuthPresent": "true"}})
                changes.append("Own-account root trust narrowed to one approved caller with MFA.")
            elif e.kind == "federated":
                prov = e.value.split("oidc-provider/")[-1]
                host = prov.split("/")[0]
                if host in OIDC_SUBJECT_KEYS and f"{prov}:sub".lower() not in keys:
                    k, v = OIDC_SUBJECT_KEYS[host]
                    cond = _merge_cond(cond, {"StringEquals": {f"{prov}:aud": "sts.amazonaws.com"}, "StringLike": {k: v}})
                    changes.append(f"OIDC trust pinned to audience sts.amazonaws.com and subject {v}.")
                elif "cognito-identity" in prov and "cognito-identity.amazonaws.com:aud" not in keys:
                    cond = _merge_cond(cond, {"StringEquals": {"cognito-identity.amazonaws.com:aud": "<IDENTITY_POOL_ID>"},
                                              "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": "authenticated"}})
                    changes.append("Cognito trust pinned to one identity pool (authenticated users only).")
                elif "saml-provider/" in e.value and "saml:aud" not in keys:
                    cond = _merge_cond(cond, {"StringEquals": {"SAML:aud": "https://signin.aws.amazon.com/saml"}})
                    changes.append("SAML trust pinned to the AWS sign-in audience.")
            elif e.kind == "service" and not keys & {"aws:sourceaccount", "aws:sourcearn"}:
                from .catalog import CONFUSED_DEPUTY_SAFE_SERVICES
                if e.value not in CONFUSED_DEPUTY_SAFE_SERVICES:
                    cond = _merge_cond(cond, {"StringEquals": {"aws:SourceAccount": acct}})
                    changes.append(f"Added aws:SourceAccount = {acct} to {e.value} trust (confused-deputy protection).")
        if cond:
            raw["Condition"] = cond
    doc["Statement"] = stmts
    return doc, list(dict.fromkeys(changes))


# ======================================================================================
# Diff, CLI, verification
# ======================================================================================
def side_by_side(a: dict, b: dict) -> dict:
    left = json.dumps(a, indent=2).splitlines()
    right = json.dumps(b, indent=2).splitlines()
    rows: list[dict] = []
    sm = difflib.SequenceMatcher(None, left, right, autojunk=False)
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            for k in range(i2 - i1):
                rows.append({"t": "eq", "l": left[i1 + k], "r": right[j1 + k], "ln": i1 + k + 1, "rn": j1 + k + 1})
        else:
            n = max(i2 - i1, j2 - j1)
            for k in range(n):
                li, ri = i1 + k, j1 + k
                rows.append({"t": {"replace": "chg", "delete": "del", "insert": "add"}[tag] if (li < i2 and ri < j2) or tag != "replace"
                             else ("del" if li < i2 else "add"),
                             "l": left[li] if li < i2 else None, "r": right[ri] if ri < j2 else None,
                             "ln": li + 1 if li < i2 else None, "rn": ri + 1 if ri < j2 else None})
    unified = "\n".join(difflib.unified_diff(left, right, "original.json", "least-privilege.json", lineterm="", n=2))
    added = sum(1 for r in rows if r["t"] in ("add", "chg"))
    removed = sum(1 for r in rows if r["t"] in ("del", "chg"))
    return {"rows": rows, "unified": unified, "added": added, "removed": removed}


def _slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", s).strip("-")[:80]


def cli_commands(policy: Policy | None, holders: list[Identity], role: Identity | None, fname: str, acct: str) -> list[str]:
    v = [f"aws accessanalyzer validate-policy --policy-type {'RESOURCE_POLICY' if role else 'IDENTITY_POLICY'} "
         f"--policy-document file://{fname}"]
    if role is not None:
        return v + [f"aws iam update-assume-role-policy --role-name {role.name} --policy-document file://{fname}"]
    assert policy is not None
    if policy.kind == "inline":
        owner = next((h for h in holders if h.arn == policy.owner_arn), holders[0] if holders else None)
        if owner is None:
            return v
        flag = {"user": "--user-name", "role": "--role-name", "group": "--group-name"}[owner.kind]
        return v + [f"aws iam put-{owner.kind}-policy {flag} {owner.name} --policy-name {policy.name} --policy-document file://{fname}"]
    if policy.kind == "customer-managed":
        return v + [f"aws iam list-policy-versions --policy-arn {policy.arn}  # delete the oldest non-default version if 5 exist",
                    f"aws iam create-policy-version --policy-arn {policy.arn} --policy-document file://{fname} --set-as-default"]
    new_name = f"{policy.name}-LeastPrivilege"
    cmds = v + [f"aws iam create-policy --policy-name {new_name} --policy-document file://{fname}"]
    for h in holders:
        if policy.key not in h.policy_keys:
            continue
        flag = {"user": "--user-name", "role": "--role-name", "group": "--group-name"}[h.kind]
        cmds.append(f"aws iam attach-{h.kind}-policy {flag} {h.name} --policy-arn arn:aws:iam::{acct}:policy/{new_name}")
        cmds.append(f"aws iam detach-{h.kind}-policy {flag} {h.name} --policy-arn {policy.arn}")
    return cmds


def _verify(ctx: Context, policy: Policy, proposed: dict, holders: list[Identity], before: list[Finding]) -> dict:
    kind = "customer-managed" if policy.kind == "aws-managed" else policy.kind
    test = Policy.from_document(policy.key + ":proposed", policy.name, kind, proposed, arn=policy.arn)
    ps = PermissionSet([(test, s) for s in test.statements])
    residual = scan_policy(test, holders, [ps], ctx.account.account_id)
    b = max((SEVERITY_RANK[f.severity] for f in before), default=0)
    a = max((SEVERITY_RANK[f.severity] for f in residual), default=0)
    names = {v: k for k, v in SEVERITY_RANK.items()}
    return {"before": names[b], "after": names[a] if residual else "NONE", "residual": [f"{f.severity} {f.rule_id}: {f.title}" for f in residual],
            "improved": a < b or not residual}


def _verify_trust(ctx: Context, role: Identity, proposed: dict, before: list[Finding]) -> dict:
    from .detectors import detect_trust
    trial = copy.copy(role)
    trial.trust = Policy.from_document(f"trust:{role.arn}", f"{role.name} trust policy", "trust", proposed, owner_arn=role.arn)
    saved = ctx.trusts.get(role.arn, [])
    ctx.trusts[role.arn] = parse_trust(trial, ctx.account.account_id)
    try:
        residual = [f for f in detect_trust(ctx, [], roles=[trial]) if f.severity != "INFO"]
    finally:
        ctx.trusts[role.arn] = saved
    names = {v: k for k, v in SEVERITY_RANK.items()}
    b = max((SEVERITY_RANK[f.severity] for f in before), default=0)
    a = max((SEVERITY_RANK[f.severity] for f in residual), default=0)
    return {"before": names[b], "after": names[a] if residual else "NONE",
            "residual": [f"{f.severity} {f.rule_id}: {f.title}" for f in residual], "improved": a < b or not residual}


def build_remediations(ctx: Context, findings: list[Finding]) -> list[dict]:
    by_policy: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        if f.policy_key and f.rule_id not in ("HYG-001",):
            by_policy[f.policy_key].append(f)
    out: list[dict] = []
    acct = ctx.account.account_id
    for key, fs in by_policy.items():
        if max(SEVERITY_RANK[f.severity] for f in fs) < SEVERITY_RANK["MEDIUM"] and not key.startswith("trust:"):
            continue
        rid = f"REM-{len(out) + 1:03d}"
        if key.startswith("trust:"):
            role = ctx.identities.get(key[len("trust:"):])
            if not role or not role.trust:
                continue
            original = role.trust.document
            proposed, changes = synthesize_trust(ctx, role)
            if not changes:
                continue
            fname = f"remediation/{_slug(role.name)}-trust.json"
            cmds = cli_commands(None, [role], role, fname, acct)
            verification = _verify_trust(ctx, role, proposed, fs)
            title, holders_names, pkind = f"{role.name} trust policy", [role.name], "trust"
        else:
            pol = ctx.policies.get(key)
            if not pol:
                continue
            holders = [ctx.identities[a] for a in ctx.direct_holders.get(key, []) if a in ctx.identities]
            effective = [ctx.identities[a] for a in ctx.holders.get(key, []) if a in ctx.identities]
            original = pol.document
            proposed, changes = synthesize_policy(ctx, pol, effective or holders)
            if not changes:
                continue
            fname = f"remediation/{_slug(pol.name)}-least-privilege.json"
            cmds = cli_commands(pol, holders, None, fname, acct)
            verification = _verify(ctx, pol, proposed, effective or holders, fs)
            title, holders_names, pkind = pol.name, [h.name for h in holders], pol.kind
        placeholders = sorted(set(PLACEHOLDER_RX.findall(json.dumps(proposed))))
        diff = side_by_side(original, proposed)
        for f in fs:
            f.remediation_id = rid
        out.append({"id": rid, "policy_key": key, "policy_name": title, "policy_kind": pkind, "applies_to": holders_names,
                    "finding_ids": [f.id for f in fs], "max_severity": max((f.severity for f in fs), key=lambda s: SEVERITY_RANK[s]),
                    "original": original, "proposed": proposed, "changes": changes, "placeholders": placeholders,
                    "file_name": fname, "cli": cmds, "diff": diff, "verification": verification})
    return out
