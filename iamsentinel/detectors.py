"""Rule-based detectors. Each returns `Finding` objects with exact policy-level evidence."""
from __future__ import annotations

from typing import Iterable, Optional

from .catalog import (
    BROAD_MANAGED_POLICIES, CATEGORIES, CONFUSED_DEPUTY_SAFE_SERVICES, CRITICAL_SERVICES, ESCALATION_METHODS,
    HIGH_RISK_SERVICES, OIDC_SUBJECT_KEYS, SENSITIVE_ACTIONS, STRONG_CONDITION_KEYS, EscalationMethod,
)
from .context import Context, TrustEntry
from .models import SEVERITY_RANK, Finding, Identity, Policy, Statement, downgrade, upgrade
from .policy_eval import PermissionSet, action_match, is_wildcard_action, statement_is_global

BROAD_READ_ACTION_THRESHOLD = 50
BROAD_READ_SERVICE_THRESHOLD = 10


def _strong_condition(cond: dict) -> list[str]:
    keys = []
    for _op, kv in (cond or {}).items():
        if isinstance(kv, dict):
            keys += [k for k in kv if k.lower() in STRONG_CONDITION_KEYS or k.lower().startswith(("aws:resourcetag", "aws:principaltag"))]
    return keys


def _max_sev(sevs: Iterable[str]) -> str:
    return max(sevs, key=lambda s: SEVERITY_RANK[s], default="INFO")


# ======================================================================================
# 1) Statement-level excessive / wildcard permission analysis
# ======================================================================================
def scan_policy(policy: Policy, holders: list[Identity], permsets: list[PermissionSet], account_id: str,
                suppressed: Optional[list[dict]] = None) -> list[Finding]:
    """Analyse every Allow statement of a policy. Deny-aware: actions that every holder has hard-denied
    are dropped (and recorded in `suppressed` as respected guardrails)."""
    findings: list[Finding] = []
    names = [h.name for h in holders]
    arns = [h.arn for h in holders]
    kinds = {h.kind for h in holders}
    aws_managed = policy.kind == "aws-managed"

    def base(rule: str, title: str, sev: str, cat: str, st: Statement, desc: str, attack: str, rec: str,
             offending: list[str], mitre: list[str]) -> Finding:
        f = Finding(rule_id=rule, title=title, severity=sev, category=cat, description=desc, attack_scenario=attack,
                    recommendation=rec, identity_arns=list(arns), identity_names=list(names), policy_name=policy.name,
                    policy_arn=policy.arn, policy_key=policy.key, policy_kind=policy.kind, sid=st.sid or None,
                    statement_index=st.index, effect=st.effect, actions=st.action_display(),
                    resources=st.resource_display(), condition=st.condition or None, offending_actions=offending,
                    mitre=mitre)
        strong = _strong_condition(st.condition)
        if strong:
            f.severity = downgrade(f.severity)
            f.exploitability = "conditional"
            f.notes.append(f"Allow is constrained by condition key(s) {', '.join(strong)} - severity lowered one level.")
        elif st.condition:
            f.notes.append("Statement has a Condition block, but none of its keys meaningfully restrict who/where (no MFA, org, IP, VPC or account pinning).")
        if not holders:
            f.severity = downgrade(f.severity)
            f.notes.append("Policy is not attached to any identity in this export (latent risk if attached later).")
            f.exploitability = "latent"
        if aws_managed and rule != "ADMIN-001":
            f.notes.append("AWS-managed policy: you cannot edit it - replace it with a scoped customer-managed copy (generated below).")
        return f

    def deny_filter(st: Statement, actions: list[str]) -> tuple[list[str], list[str]]:
        """Return (still_allowed, blocked) considering every holder's explicit Deny statements."""
        if not permsets:
            return actions, []
        keep, blocked = [], []
        for a in actions:
            probe = a.replace("*", "Zz") if is_wildcard_action(a) else a
            if a == "*":
                probe = "zzsentinelservice:ZzSentinelAction"
            if all(not ps.evaluate(probe).allowed and ps.evaluate(probe).hard_denies for ps in permsets):
                blocked.append(a)
            else:
                keep.append(a)
        if blocked and suppressed is not None:
            suppressed.append({"policy": policy.name, "sid": st.label, "actions": blocked, "identities": names,
                               "reason": "Explicit unconditional Deny overrides this Allow for every holder."})
        return keep, blocked

    broad_managed = policy.kind == "aws-managed" and policy.name in BROAD_MANAGED_POLICIES and policy.name != "AdministratorAccess"
    if broad_managed:
        sev, why = BROAD_MANAGED_POLICIES[policy.name]
        st0 = policy.statements[0] if policy.statements else Statement.parse({"Effect": "Allow"}, 0)
        allowed_any = any(ps.evaluate("s3:GetObject").allowed or ps.evaluate("ec2:RunInstances").allowed or ps.evaluate("iam:CreateUser").allowed for ps in permsets) if permsets else True
        if allowed_any:
            findings.append(base(
                "ADMIN-002", f"Overly broad AWS managed policy '{policy.name}' attached", sev, "Excessive Privilege", st0,
                f"{policy.name}: {why}",
                "Any compromise of a holder's credentials (phished console password, leaked access key, SSRF on a workload) "
                "immediately yields account-wide data access and destructive capability.",
                f"Detach {policy.name}; attach a customer-managed policy listing only the services and resources the workload uses "
                "(use IAM Access Analyzer policy generation from CloudTrail activity).",
                st0.action_display(), ["T1078.004", "T1098"]))
        return findings

    for st in policy.statements:
        if not st.is_allow:
            continue
        global_res = statement_is_global(st)
        actions, _blocked = deny_filter(st, st.actions)

        # --- NotAction / NotResource --------------------------------------------------
        if st.not_actions:
            excludes_iam = any(action_match(p, "iam:CreateUser") for p in st.not_actions)
            sev = "HIGH" if excludes_iam else "CRITICAL"
            if not global_res:
                sev = downgrade(sev)
            findings.append(base(
                "WILD-004", "Allow with NotAction grants everything except a short deny-list", sev, "Wildcard Permission", st,
                f"Statement allows every AWS action except {', '.join(st.not_actions)} - new AWS services and APIs are granted automatically.",
                "The holder can use any service not on the exclusion list (data exfiltration, crypto-mining, destruction). "
                + ("" if excludes_iam else "IAM is not excluded, so this is equivalent to full administrator."),
                "Replace NotAction with an explicit Action allow-list of required APIs.",
                [f"NotAction: {a}" for a in st.not_actions], ["T1078.004"]))
            continue
        if st.not_resources and actions:
            findings.append(base(
                "WILD-005", "Allow with NotResource applies to (almost) every resource", "MEDIUM", "Wildcard Permission", st,
                f"Statement applies to every resource except {', '.join(st.not_resources)}.",
                "Resources created in the future are covered automatically; the carve-out is easy to bypass.",
                "Use an explicit Resource allow-list.", [f"NotResource: {r}" for r in st.not_resources], ["T1078.004"]))

        if not actions:
            continue

        # --- Full wildcard -----------------------------------------------------------------
        if "*" in actions:
            if global_res:
                via = f" via AWS managed policy {policy.name}" if aws_managed else ""
                f = base("ADMIN-001", f"Full administrator access (Action \"*\" on Resource \"*\"){via}", "CRITICAL",
                         "Excessive Privilege", st,
                         "The statement grants every action on every resource in the account. Holders can create users and keys, "
                         "rewrite any policy, read all data, disable CloudTrail/GuardDuty and delete resources.",
                         "Credential theft of this identity = full account takeover. An attacker typically creates a backdoor user "
                         "or access key (persistence), disables logging (defense evasion) and exfiltrates S3/RDS/Secrets data.",
                         "Remove standing admin. Use role-based, MFA-gated, time-bound elevation (IAM Identity Center permission set or "
                         "an assumable break-glass role) and protect security tooling with explicit Deny.",
                         ["*"], ["T1078.004", "T1098", "T1562.008"])
            else:
                f = base("WILD-001", "Wildcard action \"*\" on scoped resources", "HIGH", "Wildcard Permission", st,
                         f"Every API is allowed on {', '.join(st.resources)}.",
                         "All current and future destructive / permission-changing APIs are allowed on the matching resources.",
                         "List the exact actions required.", ["*"], ["T1078.004"])
            findings.append(f)
            continue

        # --- Service-wide wildcards (svc:*) ---------------------------------------------------
        svc_wild = [a for a in actions if a.endswith(":*")]
        if svc_wild:
            sevs = []
            for a in svc_wild:
                svc = a.split(":")[0].lower()
                sevs.append("CRITICAL" if svc in CRITICAL_SERVICES else "HIGH" if svc in HIGH_RISK_SERVICES else "MEDIUM")
            sev = _max_sev(sevs)
            if not global_res:
                sev = downgrade(sev)
            covered = sorted({s for s in SENSITIVE_ACTIONS if any(action_match(a, s) for a in svc_wild)})
            findings.append(base(
                "WILD-002", f"Service-wide wildcard {', '.join(svc_wild)} on {'all resources' if global_res else 'scoped resources'}", sev,
                "Wildcard Permission", st,
                f"{', '.join(svc_wild)} grants every current and future API of the service, including "
                f"{len(covered)} known-sensitive action(s) such as {', '.join(covered[:6]) or 'n/a'}.",
                _svc_attack(svc_wild),
                "Replace the service wildcard with the specific read/write actions the workload needs and scope Resource to named ARNs.",
                svc_wild, ["T1530", "T1485"] if any(a.lower().startswith("s3:") for a in svc_wild) else ["T1078.004"]))

        # --- Partial wildcards covering sensitive actions -------------------------------------
        partial = [a for a in actions if is_wildcard_action(a) and not a.endswith(":*")]
        covered_by: dict[str, list[str]] = {}
        for a in partial:
            hits = [s for s in SENSITIVE_ACTIONS if action_match(a, s)]
            if hits:
                covered_by[a] = hits
        if covered_by:
            cats = {SENSITIVE_ACTIONS[s] for hs in covered_by.values() for s in hs}
            sev = "HIGH" if cats & {"privilege-escalation", "credential-access", "permissions-management", "defense-evasion"} else "MEDIUM"
            if not global_res:
                sev = downgrade(sev)
            if aws_managed:
                sev = downgrade(sev)
            findings.append(base(
                "WILD-003", "Wildcard action pattern expands to sensitive APIs", sev, "Wildcard Permission", st,
                "Patterns " + "; ".join(f"{p} → {', '.join(h[:4])}{'…' if len(h) > 4 else ''}" for p, h in covered_by.items()),
                "Verb wildcards silently include high-impact APIs (and any API AWS adds later with the same prefix).",
                "Enumerate exact actions or add an explicit Deny for the sensitive matches.",
                list(covered_by), ["T1078.004"]))

        # --- Explicit sensitive actions on Resource "*" ----------------------------------------
        if global_res:
            explicit = [a for a in actions if not is_wildcard_action(a)]
            sens = {a: SENSITIVE_ACTIONS[k] for a in explicit for k in SENSITIVE_ACTIONS if k.lower() == a.lower()}
            if sens:
                sev = _max_sev(CATEGORIES[c]["severity"] for c in sens.values())
                if aws_managed:
                    sev = downgrade(sev)
                cats = sorted({CATEGORIES[c]["label"] for c in sens.values()})
                findings.append(base(
                    "RES-001", f"Sensitive action(s) allowed on Resource \"*\" ({', '.join(cats)})", sev, "Unscoped Resource", st,
                    f"{len(sens)} sensitive action(s) apply to every resource: {', '.join(list(sens)[:12])}{' …' if len(sens) > 12 else ''}.",
                    _res_attack(sens),
                    "Scope Resource to the specific ARNs (bucket, function, parameter path, role) and add guardrail conditions "
                    "(aws:ResourceAccount, iam:PassedToService, aws:MultiFactorAuthPresent).",
                    list(sens), sorted({m for c in sens.values() for m in _cat_mitre(c)})))

        # --- Very large permission surface ---------------------------------------------------
        services = {a.split(":")[0] for a in actions if ":" in a}
        if global_res and (len(actions) >= BROAD_READ_ACTION_THRESHOLD or len(services) >= BROAD_READ_SERVICE_THRESHOLD):
            findings.append(base(
                "READ-001", f"Very broad permission surface: {len(actions)} actions across {len(services)} services on \"*\"", "LOW",
                "Excessive Privilege", st,
                f"A single statement grants {len(actions)} actions across {len(services)} services on all resources (mostly read/list).",
                "Broad read access enables full reconnaissance of the account (T1580) and reading of operational data such as logs and templates.",
                "Confirm the identity really needs account-wide visibility; otherwise restrict to the services in use.",
                [], ["T1580"]))
    return findings


def _svc_attack(svc_wild: list[str]) -> str:
    s = {a.split(":")[0].lower() for a in svc_wild}
    if "s3" in s:
        return ("The holder can read and download every object in every bucket (data exfiltration), make buckets public "
                "via s3:PutBucketPolicy / PutBucketAcl, and destroy data with s3:DeleteBucket / DeleteObject (ransomware pattern).")
    if s & {"iam", "sts", "organizations"}:
        return "IAM control is equivalent to administrator: the holder can attach AdministratorAccess to itself."
    if "ec2" in s:
        return "Can launch instances with any instance profile, open security groups, snapshot and share volumes."
    if "lambda" in s:
        return "Can replace function code and inherit every Lambda execution role."
    return "All current and future APIs of the service are allowed."


def _res_attack(sens: dict[str, str]) -> str:
    acts = {a.lower() for a in sens}
    parts = []
    if "iam:passrole" in acts:
        parts.append("iam:PassRole on \"*\" lets the holder hand ANY role (including admin roles) to an AWS service it controls.")
    if acts & {"ssm:getparameter", "ssm:getparameters", "ssm:getparametersbypath", "secretsmanager:getsecretvalue"}:
        parts.append("Every parameter/secret in the account is readable - including database passwords and API tokens of other apps.")
    if acts & {"lambda:createfunction", "ec2:runinstances", "ssm:sendcommand"}:
        parts.append("Code-execution APIs on \"*\" allow running attacker-controlled code inside the account.")
    if acts & {"logs:getlogevents", "logs:filterlogevents"}:
        parts.append("All CloudWatch log data is readable (logs often contain tokens, PII and request payloads).")
    if acts & {"eks:accesskubernetesapi"}:
        parts.append("Kubernetes API access on every EKS cluster (subject to cluster access entries).")
    return " ".join(parts) or "Sensitive actions apply to every resource in the account instead of the specific resources required."


def _cat_mitre(cat: str) -> list[str]:
    return {
        "privilege-escalation": ["T1098"], "credential-access": ["T1555.006"], "defense-evasion": ["T1562.008"],
        "code-execution": ["T1648"], "data-destruction": ["T1485"], "data-read": ["T1530"],
        "data-write": ["T1530"], "permissions-management": ["T1098"],
    }.get(cat, [])


def detect_excessive(ctx: Context, suppressed: list[dict]) -> list[Finding]:
    out: list[Finding] = []
    for key, pol in ctx.policies.items():
        holders = [ctx.identities[a] for a in ctx.holders.get(key, []) if a in ctx.identities]
        if not holders and pol.kind == "aws-managed":
            continue  # unattached AWS managed policies are irrelevant
        permsets = [ctx.perms[h.arn] for h in holders]
        out += scan_policy(pol, holders, permsets, ctx.account.account_id, suppressed)
    return out


# ======================================================================================
# 2) Trust-policy / cross-account analysis
# ======================================================================================
def detect_trust(ctx: Context, positives: list[dict], roles: Optional[list[Identity]] = None) -> list[Finding]:
    out: list[Finding] = []
    acct = ctx.account.account_id
    for role in roles if roles is not None else ctx.account.roles():
        admin = ctx.is_admin(role.arn)
        for t in ctx.trusts.get(role.arn, []):
            keys = t.condition_keys
            st = t.statement

            def mk(rule: str, title: str, sev: str, desc: str, attack: str, rec: str, mitre: list[str], expl: str = "confirmed") -> Finding:
                f = Finding(rule_id=rule, title=title, severity=upgrade(sev) if admin and sev != "CRITICAL" and rule in ("TRUST-002", "TRUST-004", "TRUST-006") else sev,
                            category="Risky Trust", description=desc, attack_scenario=attack, recommendation=rec,
                            identity_arns=[role.arn], identity_names=[role.name], policy_name=f"{role.name} (AssumeRolePolicyDocument)",
                            policy_key=f"trust:{role.arn}", policy_kind="trust", sid=st.sid or None, statement_index=st.index,
                            effect=st.effect, actions=t.actions, resources=[f"Principal: {t.value}"], condition=st.condition or None,
                            offending_actions=t.actions, mitre=mitre, exploitability=expl)
                if admin:
                    f.notes.append("The role is administrator-equivalent, which raises the impact of this trust.")
                return f

            if t.kind == "not-principal":
                out.append(mk("TRUST-007", "Trust policy uses Allow + NotPrincipal", "CRITICAL",
                              "Allow with NotPrincipal trusts every principal in every AWS account except the listed ones.",
                              "Any AWS customer can assume the role.", "Replace NotPrincipal with an explicit Principal.", ["T1199"]))
            elif t.kind == "anyone":
                guards = keys & {"aws:principalorgid", "aws:principalarn", "aws:sourceaccount", "sts:externalid", "aws:principalaccount", "aws:sourceip"}
                if guards:
                    out.append(mk("TRUST-001", "Wildcard principal (\"*\") in trust policy - constrained by conditions", "MEDIUM",
                                  f"Principal is \"*\" but the trust requires {', '.join(sorted(guards))}.",
                                  "Safety rests entirely on the condition values; a typo or broad value re-opens the role to the internet.",
                                  "Name the trusted principals explicitly in addition to the condition.", ["T1199"], "conditional"))
                else:
                    out.append(mk("TRUST-001", "Role assumable by ANY AWS principal (\"Principal\": \"*\")", "CRITICAL",
                                  "The trust policy allows every IAM principal in every AWS account to call sts:AssumeRole on this role.",
                                  "An attacker with any AWS account (free tier) runs `aws sts assume-role --role-arn " + role.arn +
                                  "` and receives this role's credentials.",
                                  "Replace \"*\" with the specific trusted account/role ARNs and add aws:PrincipalOrgID.", ["T1199", "T1078.004"]))
            elif t.kind in ("aws-account", "aws-principal") and t.external:
                if "sts:externalid" in keys:
                    out.append(mk("TRUST-003", f"Cross-account trust to external account {t.account} (ExternalId enforced)", "LOW",
                                  f"Role trusts {t.value} and requires sts:ExternalId.",
                                  "Third-party access is legitimate but must be reviewed periodically; the external party's security is now part of yours.",
                                  "Verify the vendor relationship is still required and the ExternalId is unique per customer.", ["T1199"], "conditional"))
                    positives.append({"control": "ExternalId on cross-account trust", "identity": role.name, "detail": f"{t.value} must present sts:ExternalId"})
                else:
                    sev = "HIGH" if "aws:principalorgid" not in keys else "MEDIUM"
                    out.append(mk("TRUST-002", f"Cross-account trust to external account {t.account} without sts:ExternalId", sev,
                                  f"Role trusts {t.value} (account {t.account}, outside this account) with no sts:ExternalId condition.",
                                  "Confused-deputy: any principal the external account allows (or a third-party SaaS acting for another customer) "
                                  "can assume the role. Compromise of the external account = compromise of this role.",
                                  "Add Condition StringEquals sts:ExternalId (unique per customer) and narrow the principal to a specific role ARN.",
                                  ["T1199"]))
            elif t.kind in ("aws-account",) and t.account == acct:
                sev = "LOW"
                out.append(mk("TRUST-004", "Role trusts its own account root - any principal with sts:AssumeRole can assume it", sev,
                              f"Trust delegates to arn:aws:iam::{acct}:root; every user/role whose identity policy allows sts:AssumeRole on this role can become it.",
                              "Lateral movement hub: a broad `sts:AssumeRole` on \"*\" anywhere in the account becomes a path to this role.",
                              "Trust specific role ARNs instead of the account root, or add aws:PrincipalArn / aws:PrincipalTag conditions.",
                              ["T1078.004"]))
            elif t.kind == "federated":
                out += _federated(t, role, mk)
            elif t.kind == "service":
                if t.value in CONFUSED_DEPUTY_SAFE_SERVICES:
                    continue
                if keys & {"aws:sourceaccount", "aws:sourcearn", "aws:sourceorgid"}:
                    positives.append({"control": "Confused-deputy protection on service trust", "identity": role.name,
                                      "detail": f"{t.value} restricted by {', '.join(sorted(keys & {'aws:sourceaccount', 'aws:sourcearn', 'aws:sourceorgid'}))}"})
                else:
                    out.append(mk("TRUST-006", f"Service trust ({t.value}) without aws:SourceAccount / aws:SourceArn", "LOW",
                                  f"{t.value} can assume the role on behalf of any customer resource.",
                                  "Cross-service confused deputy: another AWS customer's resource in the same service may cause the service to act with this role.",
                                  "Add Condition StringEquals aws:SourceAccount and ArnLike aws:SourceArn.", ["T1199"]))
    return out


def _federated(t: TrustEntry, role: Identity, mk) -> list[Finding]:
    out = []
    prov = t.value.split("oidc-provider/")[-1] if "oidc-provider/" in t.value else t.value
    keys = t.condition_keys
    if "saml-provider/" in t.value:
        if "saml:aud" not in keys:
            out.append(mk("TRUST-005", "SAML federation trust without SAML:aud condition", "MEDIUM",
                          f"Role trusts SAML provider {t.value} without pinning SAML:aud.",
                          "Assertions intended for other service providers may be replayed.",
                          "Add StringEquals SAML:aud = https://signin.aws.amazon.com/saml.", ["T1199"]))
        return out
    host = prov.split("/")[0]
    sub_key = f"{prov}:sub".lower()
    aud_key = f"{prov}:aud".lower()
    if host in OIDC_SUBJECT_KEYS or prov in OIDC_SUBJECT_KEYS:
        if sub_key not in keys:
            out.append(mk("TRUST-005", f"OIDC trust to {host} without subject (sub) condition", "CRITICAL",
                          f"Any identity issued by {host} can assume this role - e.g. ANY GitHub repository in the world for GitHub Actions.",
                          f"An attacker creates their own repo/pipeline, requests an OIDC token for audience sts.amazonaws.com and calls "
                          f"AssumeRoleWithWebIdentity on {role.arn}.",
                          f"Add StringLike {prov}:sub restricted to your org/repo/branch and StringEquals {prov}:aud = sts.amazonaws.com.",
                          ["T1199", "T1078.004"]))
        else:
            vals = t.condition_values(f"{prov}:sub")
            if any(v.strip() in ("*", "repo:*") or v.endswith(":*") and v.count("/") == 0 for v in vals):
                out.append(mk("TRUST-005", f"OIDC trust to {host} with overly broad subject pattern", "HIGH",
                              f"Subject condition {vals} matches identities outside your organization.", "Foreign pipelines may match the pattern.",
                              "Pin the subject to org/repo and branch or environment.", ["T1199"]))
    elif "cognito-identity.amazonaws.com" in prov:
        if "cognito-identity.amazonaws.com:aud" not in keys:
            out.append(mk("TRUST-005", "Cognito identity-pool trust without aud condition", "HIGH",
                          "Identities from ANY Cognito identity pool can assume the role.", "Attacker uses their own identity pool.",
                          "Add StringEquals cognito-identity.amazonaws.com:aud = <IDENTITY_POOL_ID> and amr = authenticated.", ["T1199"]))
    elif aud_key not in keys and sub_key not in keys:
        out.append(mk("TRUST-005", f"OIDC trust to {prov} without aud/sub conditions", "HIGH",
                      f"Role trusts web identities from {prov} without restricting audience or subject.",
                      "Any token minted by the provider for any client can be exchanged for role credentials.",
                      f"Add {prov}:aud and {prov}:sub conditions.", ["T1199"]))
    return out


# ======================================================================================
# 3) Privilege escalation (toxic combinations)
# ======================================================================================
def _privileged_roles(ctx: Context) -> set[str]:
    return {r.arn for r in ctx.account.roles() if ctx.is_admin(r.arn)}


def detect_escalation(ctx: Context) -> tuple[list[Finding], list[dict]]:
    """Returns findings + structured escalation edges for the attack graph."""
    findings: list[Finding] = []
    edges: list[dict] = []
    admin_roles = _privileged_roles(ctx)
    for p in ctx.principals():
        if ctx.is_admin(p.arn):
            continue  # already full admin - nothing to escalate to
        ps = ctx.perms[p.arn]
        for m in ESCALATION_METHODS:
            decisions = []
            ok = True
            for group in m.requires:
                hit = next((d for d in (ps.evaluate(a) for a in group) if d.allowed), None)
                if not hit:
                    ok = False
                    break
                decisions.append(hit)
            if not ok:
                continue
            res = _evaluate_method(ctx, p, m, ps, admin_roles)
            if res is None:
                continue
            sev, expl, targets, target_admin, notes = res
            missing_completion = []
            if m.completion and not any(ps.evaluate(a).allowed for a in m.completion):
                missing_completion = list(m.completion)
                expl = "latent"
                sev = downgrade(sev) if sev == "CRITICAL" else sev
                notes.append(f"No trigger permission ({' / '.join(m.completion)}) found - the chain is one permission away from executable, "
                             "or relies on an existing event source / another principal to invoke it.")
            if any(d.conditional for d in decisions):
                sev = downgrade(sev)
                expl = "conditional"
                notes.append("At least one required permission is conditional.")
            ev = [g for d in decisions for g in d.grants]
            g0 = ev[0]
            f = Finding(
                rule_id=m.id, title=f"Privilege escalation: {m.name}", severity=sev, category="Privilege Escalation",
                description=m.description + f" Required permissions present: {', '.join(d.action for d in decisions)}.",
                attack_scenario=_escalation_story(m, p, targets, target_admin),
                recommendation=_escalation_fix(m),
                identity_arns=[p.arn], identity_names=[p.name], policy_name=", ".join(sorted({g.policy.name for g in ev})),
                policy_arn=g0.policy.arn, policy_key=g0.policy.key, policy_kind=g0.policy.kind, sid=g0.statement.sid or None,
                statement_index=g0.statement.index, effect="Allow", actions=sorted({a for g in ev for a in g.statement.action_display()}),
                resources=sorted({r for g in ev for r in g.statement.resource_display()}),
                condition=g0.statement.condition or None, offending_actions=[d.action for d in decisions] + [f"(missing) {a}" for a in missing_completion[:1]],
                exploitability=expl, mitre=list(m.mitre), notes=notes)
            findings.append(f)
            edges.append({"source": p.arn, "method": m.id, "name": m.name, "targets": targets, "to_admin": target_admin,
                          "exploitability": expl, "severity": sev, "finding": f})
    return findings, edges


def _evaluate_method(ctx: Context, p: Identity, m: EscalationMethod, ps: PermissionSet, admin_roles: set[str]):
    acct = ctx.account.account_id
    notes: list[str] = []
    primary = m.requires[0][0]
    if m.target == "passrole":
        svc = m.pass_to_service
        candidates = []
        for r in ctx.account.roles():
            if not ps.evaluate("iam:PassRole", r.arn).allowed:
                continue
            if any(t.kind == "service" and t.value == svc for t in ctx.trusts.get(r.arn, [])):
                candidates.append(r.arn)
        pr = ps.evaluate("iam:PassRole")
        passed_cond = any("iam:passedtoservice" in str(g.statement.condition).lower() for g in pr.grants)
        if passed_cond:
            notes.append("iam:PassRole is limited by iam:PassedToService.")
        to_admin = [c for c in candidates if c in admin_roles]
        if to_admin:
            return "CRITICAL", "confirmed", candidates, True, notes
        if candidates:
            notes.append(f"Passable roles trusted by {svc}: {', '.join(c.split('/')[-1] for c in candidates)} (none admin-equivalent).")
            return "HIGH", "confirmed", candidates, False, notes
        if pr.global_scope:
            notes.append(f"No role in this export currently trusts {svc}; PassRole on \"*\" means the escalation becomes immediate "
                         f"the moment any privileged role trusting {svc} exists (common for Lambda/EC2 execution roles).")
            return "HIGH", "latent", [], False, notes
        return None
    if m.target == "self":
        targets = []
        if primary in ("iam:AttachUserPolicy", "iam:PutUserPolicy", "iam:DeleteUserPermissionsBoundary") and p.kind == "user":
            targets = [p.arn]
        elif primary in ("iam:AttachGroupPolicy", "iam:PutGroupPolicy"):
            targets = list(p.group_arns)
        elif primary == "iam:DeleteRolePermissionsBoundary" and p.kind == "role":
            targets = [p.arn]
        elif primary in ("iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"):
            targets = [pol.arn for pol, _s, _v in ctx.sources[p.arn] if pol.kind == "customer-managed" and pol.arn]
            targets = sorted(set(targets))
        elif primary == "lambda:UpdateFunctionCode":
            notes.append("Lambda function inventory is not part of an IAM export; impact depends on the execution roles of existing functions.")
            return "HIGH", "conditional", [], False, notes
        hits = [t for t in targets if ps.evaluate(primary, t).allowed]
        if hits:
            return "CRITICAL", "confirmed", hits, True, notes
        if ps.evaluate(primary).allowed and ps.evaluate(primary).global_scope:
            notes.append("Not directly applicable to its own identity, but can modify other principals' permissions.")
            return "HIGH", "latent", [], False, notes
        return None
    if m.target == "roles":
        roles = [r.arn for r in ctx.account.roles() if ps.evaluate(primary, r.arn).allowed and r.arn != p.arn]
        if not roles:
            return None
        if primary == "iam:UpdateAssumeRolePolicy":
            to_admin = [r for r in roles if r in admin_roles]
            return ("CRITICAL" if to_admin or roles else "HIGH"), "confirmed", roles, bool(to_admin), notes
        assumable = [r for r in roles if ctx.can_assume(p.arn, r)]
        if assumable:
            return "CRITICAL", "confirmed", assumable, True, notes
        notes.append("Can grant admin to roles but cannot currently assume them; any principal/workload using those roles becomes admin.")
        return "HIGH", "latent", roles, False, notes
    if m.target == "users":
        users = [u.arn for u in ctx.account.users() if u.arn != p.arn and ps.evaluate(primary, u.arn).allowed]
        if not users:
            return None
        admins = [u for u in users if ctx.is_admin(u)]
        return ("CRITICAL" if admins else "HIGH"), "confirmed", users, bool(admins), notes
    if m.target == "groups":
        if p.kind != "user":
            return None
        groups = [g.arn for g in ctx.account.groups() if ps.evaluate(primary, g.arn).allowed and g.arn not in p.group_arns]
        if not groups:
            if ps.evaluate(primary).global_scope:
                return "HIGH", "latent", [], False, ["No other groups exist yet; any future privileged group is joinable."]
            return None
        admins = [g for g in groups if ctx.is_admin(g)]
        return ("CRITICAL" if admins else "HIGH"), "confirmed", groups, bool(admins), notes
    if m.target == "instances":
        roles = [r.arn for r in ctx.account.roles() if r.instance_profiles]
        if not roles:
            return "MEDIUM", "latent", [], False, ["No instance profiles found in export."]
        admins = [r for r in roles if r in admin_roles]
        notes.append("EC2 inventory is not part of an IAM export; assumes instances using these instance profiles are SSM-managed.")
        return ("CRITICAL" if admins else "HIGH"), "conditional", roles, bool(admins), notes
    return None


def _escalation_story(m: EscalationMethod, p: Identity, targets: list[str], to_admin: bool) -> str:
    tnames = ", ".join(t.split("/")[-1] for t in targets[:4]) or "a privileged role/policy"
    if m.id == "PRIV-015":
        return (f"1) {p.name} calls lambda:CreateFunction with --role pointing at {tnames} (allowed by iam:PassRole on that ARN). "
                "2) The function code reads AWS_ACCESS_KEY_ID/SECRET/SESSION_TOKEN from its environment or calls IAM directly. "
                "3) Once invoked, the attacker operates with the execution role's privileges"
                + (" - full administrator." if to_admin else "."))
    if m.id == "PRIV-014":
        return (f"1) {p.name} runs ec2:RunInstances with an instance profile for {tnames}. 2) User-data or SSH retrieves credentials from "
                "IMDS (169.254.169.254). 3) Attacker acts as that role" + (" (administrator)." if to_admin else "."))
    if m.target == "self":
        return f"{p.name} uses {m.requires[0][0]} against {tnames} to grant itself Action:* on Resource:* - instant administrator."
    if m.target == "users":
        return f"{p.name} uses {m.requires[0][0]} on {tnames} and then authenticates as that user" + (" (an administrator)." if to_admin else ".")
    if m.target == "roles":
        return f"{p.name} modifies {tnames} ({m.requires[0][0]}) and assumes it with the new permissions."
    return m.description


def _escalation_fix(m: EscalationMethod) -> str:
    if m.target == "passrole":
        return ("Scope iam:PassRole to the exact execution role ARN(s) and add Condition StringEquals iam:PassedToService = "
                f"{m.pass_to_service}; scope the compute action to a function/instance naming prefix.")
    if m.target == "self":
        return f"Remove {m.requires[0][0]} or scope it away from the identity's own ARN and policies; enforce a permissions boundary."
    return f"Remove {m.requires[0][0]} or restrict Resource to specific, non-privileged targets; enforce permissions boundaries."


# ======================================================================================
# 4) Stale / unused identities & credentials
# ======================================================================================
def detect_stale(ctx: Context) -> list[Finding]:
    out: list[Finding] = []
    n = ctx.stale_days
    no_telemetry_users = []
    no_telemetry_roles = []

    def mk(rule, title, sev, ident: Identity, desc, attack, rec, mitre=("T1078.004",)):
        return Finding(rule_id=rule, title=title, severity=sev, category="Stale / Unused Identity", description=desc,
                       attack_scenario=attack, recommendation=rec, identity_arns=[ident.arn], identity_names=[ident.name],
                       mitre=list(mitre), exploitability="confirmed")

    for ident in ctx.principals():
        privileged = ctx.is_admin(ident.arn) or bool(ctx.sensitive_allowed(ident.arn).get("privilege-escalation"))
        created_days = ctx.days_since(ident.create_date)
        if ident.kind == "role":
            if ident.path.startswith("/aws-service-role/"):
                continue
            if not ident.telemetry.get("role_last_used"):
                no_telemetry_roles.append(ident.name)
                continue
            days = ctx.days_since(ident.last_used)
            if days is None and (created_days or 0) > n:
                out.append(mk("STALE-001", f"Role never used ({created_days} days since creation)", "HIGH" if privileged else "MEDIUM", ident,
                              f"RoleLastUsed is empty and the role was created {created_days} days ago.",
                              "Unused roles keep their trust relationships and permissions alive - a forgotten door for attackers.",
                              "Delete the role or remove its policies after confirming with the owner."))
            elif days is not None and days > n:
                out.append(mk("STALE-001", f"Role unused for {days} days", "HIGH" if privileged else "MEDIUM", ident,
                              f"Last used {ident.last_used:%Y-%m-%d} in {ident.last_used_region or 'unknown region'} ({days} days > {n} day threshold).",
                              "Dormant privileged roles are rarely monitored; their use by an attacker is less likely to be noticed.",
                              "Remove or deactivate the role; if still needed, document an owner and review date."))
        else:
            has_tel = ident.telemetry.get("password_last_used") or ident.telemetry.get("credential_report")
            if not has_tel:
                no_telemetry_users.append(ident.name)
                continue
            if ident.password_enabled is not False and ident.password_last_used:
                d = ctx.days_since(ident.password_last_used)
                if d is not None and d > n:
                    out.append(mk("STALE-002", f"Console password unused for {d} days", "HIGH" if privileged else "MEDIUM", ident,
                                  f"PasswordLastUsed {ident.password_last_used:%Y-%m-%d} ({d} days).",
                                  "Dormant console credentials are prime targets for password spraying; nobody notices the login.",
                                  "Delete the login profile (aws iam delete-login-profile) or disable the user."))
            if ident.password_enabled and ident.mfa_active is False:
                out.append(mk("STALE-004", "Console user without MFA", "HIGH" if privileged else "MEDIUM", ident,
                              "Credential report shows password_enabled=true and mfa_active=false.",
                              "A phished or reused password alone grants console access.", "Enforce MFA (deny-without-MFA policy) and register a device."))
            for k in ident.access_keys:
                if not k.active:
                    continue
                used = ctx.days_since(k.last_used)
                rotated = ctx.days_since(k.last_rotated)
                if used is None and (rotated or 0) > n:
                    out.append(mk("STALE-003", f"Active access key never used ({rotated} days old)", "HIGH" if privileged else "MEDIUM", ident,
                                  f"{k.key_id} is active, created {rotated} days ago and never used.",
                                  "Unused long-lived keys are pure risk: if leaked (git, CI logs) they work and nobody will miss them.",
                                  "Deactivate and delete the key.", ("T1078.004", "T1098.001")))
                elif used is not None and used > n:
                    out.append(mk("STALE-003", f"Access key unused for {used} days", "HIGH" if privileged else "MEDIUM", ident,
                                  f"{k.key_id} last used {used} days ago.", "Dormant keys extend the attack surface.",
                                  "Deactivate, then delete after a grace period.", ("T1078.004", "T1098.001")))
                if rotated is not None and rotated > n and used is not None and used <= n:
                    out.append(mk("STALE-005", f"Access key not rotated for {rotated} days", "MEDIUM" if privileged else "LOW", ident,
                                  f"{k.key_id} was last rotated {rotated} days ago (> {n}).", "Old keys have had more opportunities to leak.",
                                  "Rotate the key or migrate to short-lived role credentials (IAM Identity Center / OIDC).", ("T1098.001",)))

    if no_telemetry_users or no_telemetry_roles:
        who = []
        if no_telemetry_users:
            who.append(f"{len(no_telemetry_users)} user(s): {', '.join(no_telemetry_users)}")
        if no_telemetry_roles:
            who.append(f"{len(no_telemetry_roles)} role(s): {', '.join(no_telemetry_roles)}")
        out.append(Finding(
            rule_id="TELEM-001", title="Usage telemetry absent - dormancy cannot be assessed for some identities", severity="INFO",
            category="Stale / Unused Identity",
            description="The export has no PasswordLastUsed / credential report data for " + "; ".join(who) +
                        ". get-account-authorization-details does not include user login or access-key activity.",
            attack_scenario="Unused credentials cannot be distinguished from active ones without telemetry.",
            recommendation="Run `python cli.py collect` (adds the IAM credential report) or merge `aws iam get-credential-report` output "
                           "into the export under the key \"CredentialReport\".",
            identity_names=no_telemetry_users + no_telemetry_roles, exploitability="informational"))
    return out


# ======================================================================================
# 5) Hygiene / persistence indicators
# ======================================================================================
def detect_hygiene(ctx: Context, prior: list[Finding]) -> list[Finding]:
    out: list[Finding] = []
    risky = {a for f in prior if SEVERITY_RANK[f.severity] >= 3 for a in f.identity_arns}
    for u in ctx.account.users():
        inl = [ctx.policies[k] for k in u.policy_keys if k.startswith("inline:") and k in ctx.policies]
        if inl:
            out.append(Finding(
                rule_id="HYG-001", title="Permissions granted through inline user policy", severity="LOW", category="Hygiene",
                description=f"{u.name} has inline policies: {', '.join(p.name for p in inl)}. Inline user policies are invisible in policy "
                            "inventories, cannot be reused or versioned, and bypass group-based access reviews.",
                attack_scenario="Attackers favour inline policies for persistence because they are easy to overlook.",
                recommendation="Move permissions to a versioned customer-managed policy attached to a group or role.",
                identity_arns=[u.arn], identity_names=[u.name], policy_name=", ".join(p.name for p in inl),
                policy_key=inl[0].key, policy_kind="inline", mitre=["T1098"], exploitability="informational"))
    for p in ctx.principals():
        age = ctx.days_since(p.create_date)
        if age is not None and age <= 7 and (ctx.is_admin(p.arn) or p.arn in risky) and not p.is_service_role:
            out.append(Finding(
                rule_id="HYG-002", title=f"Recently created privileged {p.kind} (created {'< 24 hours' if age == 0 else f'{age} day(s)'} ago)", severity="MEDIUM", category="Hygiene",
                description=f"{p.name} was created {p.create_date:%Y-%m-%d %H:%M} UTC and already holds high-risk permissions.",
                attack_scenario="Creating a new privileged IAM user/role is a classic persistence technique after initial compromise (T1136.003). "
                                "Confirm it maps to an approved change ticket.",
                recommendation="Verify the creator in CloudTrail (CreateUser/CreateRole events) and the business justification.",
                identity_arns=[p.arn], identity_names=[p.name], mitre=["T1136.003"], exploitability="informational"))
        if p.kind == "user" and ctx.is_admin(p.arn):
            out.append(Finding(
                rule_id="HYG-003", title="Administrator is a long-lived IAM user", severity="HIGH", category="Hygiene",
                description=f"{p.name} is an IAM user with full administrator rights. IAM users carry long-lived credentials (password / access keys).",
                attack_scenario="Leaked access keys of an admin IAM user never expire; MFA cannot be enforced on API keys without explicit conditions.",
                recommendation="Use IAM Identity Center or an assumable admin role with MFA and short sessions; remove the user's direct admin policy.",
                identity_arns=[p.arn], identity_names=[p.name], mitre=["T1078.004"], exploitability="confirmed"))
    return out
