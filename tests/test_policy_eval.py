from iamsentinel.models import Policy
from iamsentinel.policy_eval import PermissionSet, action_match, resource_match


def ps(*stmts):
    p = Policy.from_document("p", "p", "inline", {"Version": "2012-10-17", "Statement": list(stmts)})
    return PermissionSet([(p, s) for s in p.statements])


def test_wildcard_matching_is_case_insensitive_for_actions():
    assert action_match("s3:Get*", "s3:getobject")
    assert action_match("*", "iam:PassRole")
    assert not action_match("s3:Get*", "s3:PutObject")
    assert action_match("ec2:Describe?nstances", "ec2:DescribeInstances")


def test_resource_matching_is_case_sensitive():
    assert resource_match("arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/a/b")
    assert not resource_match("arn:aws:s3:::Bucket", "arn:aws:s3:::bucket")


def test_explicit_deny_overrides_allow():
    p = ps({"Effect": "Allow", "Action": "s3:*", "Resource": "*"}, {"Effect": "Deny", "Action": "s3:DeleteBucket", "Resource": "*"})
    assert p.evaluate("s3:GetObject").allowed
    d = p.evaluate("s3:DeleteBucket")
    assert not d.allowed and d.hard_denies


def test_conditional_deny_is_a_guardrail_not_a_block():
    p = ps({"Effect": "Allow", "Action": "*", "Resource": "*"},
           {"Effect": "Deny", "Action": "*", "Resource": "*", "Condition": {"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}}})
    d = p.evaluate("iam:CreateUser")
    assert d.allowed and d.conditional_denies and not d.hard_denies


def test_partial_resource_deny_does_not_block_global_query():
    p = ps({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
           {"Effect": "Deny", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::secret/*"})
    assert p.evaluate("s3:GetObject").allowed
    assert not p.evaluate("s3:GetObject", "arn:aws:s3:::secret/x").allowed
    assert p.evaluate("s3:GetObject", "arn:aws:s3:::public/x").allowed


def test_notaction_allow_grants_everything_else():
    p = ps({"Effect": "Allow", "NotAction": ["iam:*"], "Resource": "*"})
    assert p.evaluate("ec2:RunInstances").allowed
    assert not p.evaluate("iam:CreateUser").allowed


def test_notresource_allow():
    p = ps({"Effect": "Allow", "Action": "s3:GetObject", "NotResource": "arn:aws:s3:::secret/*"})
    assert p.evaluate("s3:GetObject", "arn:aws:s3:::public/x").allowed
    assert not p.evaluate("s3:GetObject", "arn:aws:s3:::secret/x").allowed


def test_full_admin_detection_respects_deny():
    assert ps({"Effect": "Allow", "Action": "*", "Resource": "*"}).is_full_admin()
    assert not ps({"Effect": "Allow", "Action": "*", "Resource": "*"}, {"Effect": "Deny", "Action": "iam:*", "Resource": "*"}).is_full_admin()
    assert not ps({"Effect": "Allow", "Action": "s3:*", "Resource": "*"}).is_full_admin()


def test_permissions_boundary_limits_effective_access():
    from iamsentinel.engine import analyze
    data = {
        "UserDetailList": [{"UserName": "b", "Arn": "arn:aws:iam::111111111111:user/b",
                            "PermissionsBoundary": {"PermissionsBoundaryArn": "arn:aws:iam::111111111111:policy/Boundary"},
                            "AttachedManagedPolicies": [{"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}]}],
        "Policies": [{"PolicyName": "Boundary", "Arn": "arn:aws:iam::111111111111:policy/Boundary", "PolicyVersionList": [
            {"IsDefaultVersion": True, "Document": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}}]}],
    }
    r = analyze(data)
    assert r["summary"]["admin_identities"] == []
