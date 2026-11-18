from conftest import NOW, doc, role, rules, user

from iamsentinel.engine import analyze

ADMIN = "arn:aws:iam::aws:policy/AdministratorAccess"
EC2_TRUST = [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]


def run(users=(), roles=(), groups=(), policies=(), **extra):
    return analyze({"UserDetailList": list(users), "RoleDetailList": list(roles), "GroupDetailList": list(groups),
                    "Policies": list(policies), **extra}, now=NOW)


def sev(r, rule):
    return [f["severity"] for f in r["findings"] if f["rule_id"] == rule]


# ---------------------------------------------------------------- trust
def test_wildcard_principal_is_critical():
    r = run(roles=[role("open", [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}])])
    assert sev(r, "TRUST-001") == ["CRITICAL"]


def test_wildcard_principal_with_org_condition_is_medium():
    r = run(roles=[role("org", [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole",
                                 "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc"}}}])])
    assert sev(r, "TRUST-001") == ["MEDIUM"]


def test_external_account_without_external_id():
    t = [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:root"}, "Action": "sts:AssumeRole"}]
    r = run(roles=[role("vendor", t)])
    assert sev(r, "TRUST-002") == ["HIGH"]
    rem = next(x for x in r["remediations"] if x["policy_kind"] == "trust")
    assert "sts:ExternalId" in str(rem["proposed"]) and rem["verification"]["after"] in ("LOW", "NONE")


def test_external_account_with_external_id_is_low():
    t = [{"Effect": "Allow", "Principal": {"AWS": "999999999999"}, "Action": "sts:AssumeRole",
          "Condition": {"StringEquals": {"sts:ExternalId": "x"}}}]
    assert sev(run(roles=[role("vendor", t)]), "TRUST-003") == ["LOW"]


def test_github_oidc_without_sub_is_critical_and_fixed():
    t = [{"Effect": "Allow", "Principal": {"Federated": "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"},
          "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}}}]
    r = run(roles=[role("gh", t)])
    assert sev(r, "TRUST-005") == ["CRITICAL"]
    rem = next(x for x in r["remediations"] if x["policy_kind"] == "trust")
    assert "token.actions.githubusercontent.com:sub" in str(rem["proposed"]) and rem["verification"]["after"] == "NONE"


def test_service_trust_confused_deputy():
    t = [{"Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"}, "Action": "sts:AssumeRole"}]
    assert sev(run(roles=[role("sns", t)]), "TRUST-006") == ["LOW"]
    assert sev(run(roles=[role("ec2", EC2_TRUST)]), "TRUST-006") == []  # ec2 is not a confused-deputy service


# ---------------------------------------------------------------- deny-aware / conditions
def test_explicit_deny_suppresses_false_positive():
    u = user("g", inline={"p": doc({"Effect": "Allow", "Action": "s3:*", "Resource": "*"}, {"Effect": "Deny", "Action": "s3:*", "Resource": "*"})})
    r = run(users=[u])
    assert "WILD-002" not in rules(r)
    assert any("Deny" in p["control"] for p in r["positive_controls"])
    assert not r["attack_paths"]


def test_mfa_condition_lowers_admin_severity():
    u = user("bg", inline={"p": doc({"Effect": "Allow", "Action": "*", "Resource": "*", "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}})})
    r = run(users=[u])
    f = next(f for f in r["findings"] if f["rule_id"] == "ADMIN-001")
    assert f["severity"] == "HIGH" and f["exploitability"] == "conditional"


def test_notaction_and_power_user():
    # PowerUserAccess referenced without its document -> reconstructed from the built-in knowledge base
    r = run(users=[user("pu", managed=["arn:aws:iam::aws:policy/PowerUserAccess"])])
    assert "ADMIN-002" in rules(r)
    # NotAction that does not exclude IAM == administrator
    r2 = run(users=[user("na", inline={"p": doc({"Effect": "Allow", "NotAction": "s3:*", "Resource": "*"})})])
    assert sev(r2, "WILD-004") == ["CRITICAL"]


def test_unattached_customer_policy_is_latent():
    pol = {"PolicyName": "Unused", "Arn": "arn:aws:iam::111111111111:policy/Unused",
           "PolicyVersionList": [{"IsDefaultVersion": True, "Document": doc({"Effect": "Allow", "Action": "iam:*", "Resource": "*"})}]}
    r = run(policies=[pol])
    f = next(f for f in r["findings"] if f["rule_id"] == "WILD-002")
    assert f["exploitability"] == "latent" and f["severity"] == "HIGH"


# ---------------------------------------------------------------- privilege escalation
def test_attach_user_policy_self_escalation():
    r = run(users=[user("dev", inline={"p": doc({"Effect": "Allow", "Action": "iam:AttachUserPolicy", "Resource": "*"})})])
    assert sev(r, "PRIV-003") == ["CRITICAL"]
    assert any(p["target"] == "crown:admin" and p["severity"] == "CRITICAL" for p in r["attack_paths"])


def test_passrole_ec2_to_admin_role_is_critical():
    u = user("ops", inline={"p": doc({"Effect": "Allow", "Action": ["iam:PassRole", "ec2:RunInstances"], "Resource": "*"})})
    r = run(users=[u], roles=[role("admin-ec2", EC2_TRUST, managed=[ADMIN])])
    f = next(f for f in r["findings"] if f["rule_id"] == "PRIV-014")
    assert f["severity"] == "CRITICAL" and f["exploitability"] == "confirmed"


def test_scoped_passrole_to_unprivileged_role_is_not_critical():
    u = user("ops", inline={"p": doc({"Effect": "Allow", "Action": ["iam:PassRole"], "Resource": "arn:aws:iam::111111111111:role/app"},
                                     {"Effect": "Allow", "Action": "ec2:RunInstances", "Resource": "*"})})
    r = run(users=[u], roles=[role("app", EC2_TRUST), role("admin-ec2", EC2_TRUST, managed=[ADMIN])])
    assert sev(r, "PRIV-014") == ["HIGH"]


def test_multi_hop_group_assume_create_policy_version():
    pol = {"PolicyName": "Pipe", "Arn": "arn:aws:iam::111111111111:policy/Pipe", "PolicyVersionList": [{"IsDefaultVersion": True,
           "Document": doc({"Effect": "Allow", "Action": "iam:CreatePolicyVersion", "Resource": "arn:aws:iam::111111111111:policy/Pipe"})}]}
    grp = {"GroupName": "devs", "Arn": "arn:aws:iam::111111111111:group/devs",
           "GroupPolicyList": [{"PolicyName": "assume", "PolicyDocument": doc({"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "arn:aws:iam::111111111111:role/pipe"})}]}
    rl = role("pipe", [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111111111111:root"}, "Action": "sts:AssumeRole"}],
              managed=["arn:aws:iam::111111111111:policy/Pipe"])
    r = run(users=[user("alice", groups=["devs"])], groups=[grp], roles=[rl], policies=[pol])
    p = next(p for p in r["attack_paths"] if p["source_label"] == "alice")
    assert p["severity"] == "CRITICAL" and p["multi_hop"] and p["target"] == "crown:admin"
    assert "PATH-001" in rules(r)
    alice = next(i for i in r["identities"] if i["name"] == "alice")
    assert alice["blast"]["admin_via_path"] and alice["blast"]["score"] >= 75


def test_add_user_to_admin_group():
    grp = {"GroupName": "admins", "Arn": "arn:aws:iam::111111111111:group/admins",
           "AttachedManagedPolicies": [{"PolicyName": "AdministratorAccess", "PolicyArn": ADMIN}]}
    u = user("helpdesk", inline={"p": doc({"Effect": "Allow", "Action": "iam:AddUserToGroup", "Resource": "*"})})
    assert sev(run(users=[u], groups=[grp]), "PRIV-009") == ["CRITICAL"]


# ---------------------------------------------------------------- stale
def test_stale_role_and_credentials():
    rl = role("old", EC2_TRUST, CreateDate="2024-01-01T00:00:00Z", RoleLastUsed={"LastUsedDate": "2025-01-01T00:00:00Z"})
    never = role("never", EC2_TRUST, CreateDate="2024-01-01T00:00:00Z", RoleLastUsed={})
    cr = [{"user": "u", "password_enabled": "true", "password_last_used": "2025-01-01T00:00:00+00:00", "mfa_active": "false",
           "access_key_1_active": "true", "access_key_1_last_rotated": "2024-01-01T00:00:00+00:00", "access_key_1_last_used_date": "N/A",
           "access_key_2_active": "false", "access_key_2_last_rotated": "N/A", "access_key_2_last_used_date": "N/A"}]
    r = run(users=[user("u")], roles=[rl, never], CredentialReport=cr)
    titles = [f["title"] for f in r["findings"] if f["rule_id"].startswith("STALE")]
    assert any("unused for" in t for t in titles) and any("never used" in t for t in titles)
    assert {"STALE-002", "STALE-003", "STALE-004"} <= rules(r)
    assert "TELEM-001" not in rules(r)


def test_single_policy_document_upload():
    r = analyze(doc({"Effect": "Allow", "Action": "iam:*", "Resource": "*"}), "pol.json", now=NOW)
    assert "WILD-002" in rules(r) and r["meta"]["warnings"]


def test_url_encoded_policy_document():
    import json, urllib.parse
    enc = urllib.parse.quote(json.dumps(doc({"Effect": "Allow", "Action": "s3:*", "Resource": "*"})))
    r = run(users=[{"UserName": "e", "Arn": "arn:aws:iam::111111111111:user/e", "UserPolicyList": [{"PolicyName": "x", "PolicyDocument": enc}]}])
    assert "WILD-002" in rules(r)
