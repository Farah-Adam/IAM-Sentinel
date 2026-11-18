"""Every intentional flaw in ./iam-small.json must be caught - and nothing safe may be over-reported."""
from conftest import rules


def finding(result, rule, name):
    return next(f for f in result["findings"] if f["rule_id"] == rule and name in f["identity_names"])


def test_schema_mapped(small):
    s = small["summary"]
    assert (s["users"], s["groups"], s["roles"]) == (3, 0, 2)
    assert small["meta"]["account_id"] == "182102543085"


def test_admin_user_is_critical(small):
    f = finding(small, "ADMIN-001", "test-admin")
    assert f["severity"] == "CRITICAL"
    assert f["policy_name"] == "AdministratorAccess" and f["actions"] == ["*"] and f["resources"] == ["*"]
    assert small["summary"]["admin_identities"] == ["test-admin"]
    assert "HYG-003" in rules(small, "test-admin")


def test_passrole_lambda_toxic_combination(small):
    f = finding(small, "PRIV-015", "test-passrole")
    assert f["policy_name"] == "ci-deploy"
    assert {"iam:PassRole", "lambda:CreateFunction"} <= set(f["offending_actions"])
    # no role in the export trusts lambda.amazonaws.com -> latent, honestly reported
    assert f["exploitability"] == "latent" and f["severity"] == "HIGH"
    assert finding(small, "RES-001", "test-passrole")["severity"] == "HIGH"


def test_s3_wildcard(small):
    f = finding(small, "WILD-002", "test-s3-all")
    assert f["severity"] == "HIGH" and f["offending_actions"] == ["s3:*"] and f["resources"] == ["*"]


def test_aws_managed_role_policies_flagged_at_medium(small):
    assert finding(small, "RES-001", "connct-with-ssm")["severity"] == "MEDIUM"  # ssm:GetParameter(s) on *
    assert finding(small, "RES-001", "ec2-console-devops-agent-us-east-1")["severity"] == "MEDIUM"
    assert finding(small, "READ-001", "ec2-console-devops-agent-us-east-1")["severity"] == "LOW"


def test_trust_policies_safe_and_positive_control_recorded(small):
    assert not [f for f in small["findings"] if f["category"] == "Risky Trust"]
    assert any(p["control"].startswith("Confused-deputy") for p in small["positive_controls"])


def test_missing_user_telemetry_is_reported_not_guessed(small):
    f = next(f for f in small["findings"] if f["rule_id"] == "TELEM-001")
    assert f["severity"] == "INFO" and set(f["identity_names"]) == {"test-admin", "test-passrole", "test-s3-all"}
    assert not [f for f in small["findings"] if f["rule_id"].startswith("STALE")]  # roles used < 90 days ago


def test_recently_created_privileged_users(small):
    assert {"test-admin", "test-passrole", "test-s3-all"} <= {n for f in small["findings"] if f["rule_id"] == "HYG-002" for n in f["identity_names"]}


def test_attack_paths_and_blast_radius(small):
    crit = [p for p in small["attack_paths"] if p["severity"] == "CRITICAL"]
    assert len(crit) == 1 and crit[0]["source_label"] == "test-admin" and crit[0]["target"] == "crown:admin"
    blast = {i["name"]: i["blast"]["score"] for i in small["identities"]}
    assert blast["test-admin"] == 100
    assert blast["test-admin"] > blast["test-s3-all"] > blast["connct-with-ssm"]
    assert blast["test-passrole"] > blast["connct-with-ssm"]


def test_grade_is_failing(small):
    assert small["summary"]["grade"] == "F"
    assert 0 < small["summary"]["excess_permission_ratio"] <= 1
