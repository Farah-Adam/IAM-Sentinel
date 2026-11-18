"""Optional read-only live collector (boto3).

Minimum IAM permissions (all read-only):
    iam:GetAccountAuthorizationDetails   - users, groups, roles, inline + managed policies, trust policies, RoleLastUsed
    iam:GenerateCredentialReport         - triggers credential report generation (no data returned)
    iam:GetCredentialReport              - password / access-key last-used + MFA status
Optional:
    sts:GetCallerIdentity                - prints which principal/account is being scanned (always allowed)

The AWS managed policy `SecurityAudit` (or `IAMReadOnlyAccess` + the two credential-report actions) covers these.
"""
from __future__ import annotations

import base64
import json
import time
from datetime import datetime
from typing import Any, Optional


def collect(profile: Optional[str] = None, region: Optional[str] = None, include_credential_report: bool = True,
            log=print) -> dict[str, Any]:
    try:
        import boto3  # type: ignore
    except ImportError as e:  # pragma: no cover - optional dependency
        raise RuntimeError("boto3 is required for live collection: pip install boto3") from e

    session = boto3.Session(profile_name=profile, region_name=region)
    try:
        ident = session.client("sts").get_caller_identity()
        log(f"[collector] scanning account {ident['Account']} as {ident['Arn']}")
    except Exception as e:  # pragma: no cover
        log(f"[collector] sts:GetCallerIdentity failed ({e}); continuing")
    iam = session.client("iam")

    out: dict[str, Any] = {"UserDetailList": [], "GroupDetailList": [], "RoleDetailList": [], "Policies": []}
    paginator = iam.get_paginator("get_account_authorization_details")
    for page in paginator.paginate(Filter=["User", "Role", "Group", "LocalManagedPolicy", "AWSManagedPolicy"]):
        for k in out:
            out[k].extend(page.get(k, []))
    # keep only AWS managed policies that are actually attached (the full catalogue is ~1300 policies)
    out["Policies"] = [p for p in out["Policies"] if ":aws:policy/" not in p["Arn"] or p.get("AttachmentCount", 0) > 0]
    log(f"[collector] {len(out['UserDetailList'])} users, {len(out['GroupDetailList'])} groups, "
        f"{len(out['RoleDetailList'])} roles, {len(out['Policies'])} policies")

    if include_credential_report:
        try:
            for _ in range(20):
                state = iam.generate_credential_report().get("State")
                if state == "COMPLETE":
                    break
                time.sleep(1.5)
            rep = iam.get_credential_report()
            content = rep["Content"]
            if isinstance(content, str):
                content = content.encode("utf-8")
            out["CredentialReport"] = {"Content": base64.b64encode(content).decode("ascii")}
            log("[collector] credential report collected")
        except Exception as e:  # pragma: no cover
            log(f"[collector] credential report unavailable ({e}); stale-user checks will be limited")
    return json.loads(json.dumps(out, default=lambda o: o.isoformat() if isinstance(o, datetime) else str(o)))
