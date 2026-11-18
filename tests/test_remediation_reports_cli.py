import json
import subprocess
import sys

from conftest import ROOT

from iamsentinel.reports import to_html, to_markdown, to_sarif


def rem(result, name):
    return next(r for r in result["remediations"] if r["policy_name"] == name)


def test_ci_deploy_remediation_scopes_passrole(small):
    r = rem(small, "ci-deploy")
    stmts = r["proposed"]["Statement"]
    pr = next(s for s in stmts if s.get("Action") == "iam:PassRole")
    assert pr["Resource"] != "*" and pr["Condition"]["StringEquals"]["iam:PassedToService"] == "lambda.amazonaws.com"
    assert all(s.get("Resource") != "*" for s in stmts)
    assert r["verification"]["after"] == "NONE"
    assert any("put-user-policy" in c and "test-passrole" in c for c in r["cli"])


def test_s3_remediation_removes_wildcard(small):
    r = rem(small, "s3-all")
    text = json.dumps(r["proposed"])
    assert "s3:*" not in text and "<BUCKET_NAME>" in r["placeholders"]
    assert r["verification"]["improved"]


def test_admin_remediation_adds_mfa_and_protection(small):
    r = rem(small, "AdministratorAccess")
    text = json.dumps(r["proposed"])
    assert "aws:MultiFactorAuthPresent" in text and "cloudtrail:StopLogging" in text
    assert any("detach-user-policy" in c for c in r["cli"]) and any("create-policy " in c for c in r["cli"])


def test_every_remediation_reduces_or_bounds_risk(demo):
    order = ["NONE", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    for r in demo["remediations"]:
        assert order.index(r["verification"]["after"]) <= order.index(r["verification"]["before"]), r["policy_name"]
        assert r["diff"]["rows"] and r["cli"]


def test_diff_rows_shape(small):
    rows = rem(small, "s3-all")["diff"]["rows"]
    assert {"t", "l", "r", "ln", "rn"} <= set(rows[0]) and any(x["t"] != "eq" for x in rows)


def test_exports(small):
    sarif = json.loads(to_sarif(small))
    assert sarif["version"] == "2.1.0" and len(sarif["runs"][0]["results"]) == len(small["findings"])
    md = to_markdown(small)
    assert "test-admin" in md and "```diff" in md
    html = to_html(small)
    assert html.startswith("<!doctype html>") and "Least-privilege remediations" in html


def _cli(*args):
    return subprocess.run([sys.executable, str(ROOT / "cli.py"), *args], capture_output=True, text=True, cwd=ROOT,
                          env={"PYTHONIOENCODING": "utf-8", **__import__("os").environ})


def test_cli_fail_on_gate():
    assert _cli("scan", "iam-small.json", "--fail-on", "CRITICAL").returncode == 1
    assert _cli("scan", "iam-small.json", "--fail-on", "low").returncode == 1


def test_cli_passes_clean_input(tmp_path):
    p = tmp_path / "clean.json"
    p.write_text(json.dumps({"UserDetailList": [{"UserName": "r", "Arn": "arn:aws:iam::111111111111:user/r", "UserPolicyList": [
        {"PolicyName": "ro", "PolicyDocument": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::reports/*"}]}}]}]}))
    assert _cli("scan", str(p), "--fail-on", "HIGH").returncode == 0


def test_cli_bad_input_exit_2(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json")
    assert _cli("scan", str(p)).returncode == 2


def test_cli_sarif_and_remediation_files(tmp_path):
    out = tmp_path / "r.sarif"
    res = _cli("scan", "iam-small.json", "-f", "sarif", "-o", str(out), "--write-remediations", str(tmp_path / "rem"))
    assert res.returncode == 0 and json.loads(out.read_text())["version"] == "2.1.0"
    assert (tmp_path / "rem" / "apply.sh").exists()


def test_api_endpoints():
    from fastapi.testclient import TestClient
    from iamsentinel.server import app
    c = TestClient(app)
    r = c.get("/api/analysis").json()
    assert r["meta"]["source"] == "iam-small.json"
    for fmt in ("html", "md", "json", "sarif"):
        assert c.get(f"/api/report/{r['meta']['analysis_id']}.{fmt}").status_code == 200
    up = c.post("/api/analyze", files={"file": ("x.json", (ROOT / "samples" / "iam-multihop-demo.json").read_bytes(), "application/json")})
    assert up.status_code == 200 and up.json()["summary"]["critical_attack_paths"] >= 3
    assert c.post("/api/analyze", files={"file": ("x.json", b"{}", "application/json")}).status_code == 422
    assert c.get("/").status_code == 200
