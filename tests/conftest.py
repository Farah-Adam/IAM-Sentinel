import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from iamsentinel.engine import analyze  # noqa: E402
from iamsentinel.loader import load_json  # noqa: E402

NOW = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)


@pytest.fixture(scope="session")
def small():
    return analyze(load_json(ROOT / "iam-small.json"), "iam-small.json", now=NOW)


@pytest.fixture(scope="session")
def demo():
    return analyze(load_json(ROOT / "samples" / "iam-multihop-demo.json"), "demo", now=NOW)


def rules(result, name=None):
    return {(f["rule_id"]) for f in result["findings"] if name is None or name in f["identity_names"]}


def user(name, inline=None, managed=None, groups=None, acct="111111111111"):
    return {"UserName": name, "Arn": f"arn:aws:iam::{acct}:user/{name}", "GroupList": groups or [],
            "UserPolicyList": [{"PolicyName": k, "PolicyDocument": v} for k, v in (inline or {}).items()],
            "AttachedManagedPolicies": [{"PolicyName": m.split("/")[-1], "PolicyArn": m} for m in (managed or [])]}


def role(name, trust_statements, inline=None, managed=None, acct="111111111111", **extra):
    r = {"RoleName": name, "Arn": f"arn:aws:iam::{acct}:role/{name}", "Path": "/",
         "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": trust_statements},
         "RolePolicyList": [{"PolicyName": k, "PolicyDocument": v} for k, v in (inline or {}).items()],
         "AttachedManagedPolicies": [{"PolicyName": m.split("/")[-1], "PolicyArn": m} for m in (managed or [])]}
    r.update(extra)
    return r


def doc(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}
