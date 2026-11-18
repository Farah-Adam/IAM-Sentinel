"""GitHub Pages build: docs/ is in sync with static/, and the browser engine matches the Python engine."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import build_pages  # noqa: E402

from iamsentinel.engine import analyze  # noqa: E402
from iamsentinel.loader import load_json  # noqa: E402

DOCS = ROOT / "docs"
NOW = "2026-11-18T12:00:00+00:00"
NODE = shutil.which("node")


def _read_catalog_js(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    return json.loads(text[text.index("= {") + 2: text.rindex(";")])


def test_catalog_js_matches_python_catalog():
    assert _read_catalog_js(ROOT / "static" / "catalog.js") == json.loads(json.dumps(build_pages.catalog_payload()))


@pytest.mark.skipif(not DOCS.exists(), reason="docs/ not built - run python tools/build_pages.py")
def test_docs_in_sync_with_static():
    for name in build_pages.COPY:
        assert (DOCS / name).read_bytes() == (ROOT / "static" / name).read_bytes(), f"docs/{name} is stale - rebuild"
    html = (DOCS / "index.html").read_text(encoding="utf-8")
    assert html == build_pages.static_index_html()
    assert "/static/" not in html and 'src="./app.js"' in html and 'href="./app.css"' in html
    assert (DOCS / "vendor" / "cytoscape.min.js").exists() and (DOCS / "vendor" / "tailwind.js").exists()


@pytest.mark.skipif(not (DOCS / "data" / "default-scan.json").exists(), reason="docs/ not built")
def test_default_scan_bundle():
    b = json.loads((DOCS / "data" / "default-scan.json").read_text(encoding="utf-8"))
    assert set(b["samples"]) == {"default", "multihop"}
    d = b["samples"]["default"]
    assert d["meta"]["source"] == "iam-small.json"
    for key in ("summary", "findings", "attack_paths", "identities", "remediations", "graph", "policies"):
        assert key in d
    assert d["summary"]["grade"] == "F" and d["summary"]["findings_by_severity"]["CRITICAL"] >= 1
    assert d["remediations"] and all(r["diff"]["rows"] for r in d["remediations"])
    assert d["graph"]["nodes"] and d["graph"]["edges"]


def _normalise(r: dict) -> dict:
    r = json.loads(json.dumps(r, default=str))
    r["meta"].pop("analysis_id")
    r["meta"].pop("engine", None)
    g = r["graph"]  # Python iterates a set when adding policy nodes -> compare the graph order-insensitively
    g["nodes"] = {n["data"]["id"]: n["data"] for n in g["nodes"]}
    g["edges"] = {f"{e['data']['source']}->{e['data']['target']}": {k: v for k, v in e["data"].items() if k != "id"} for e in g["edges"]}
    for i in r["identities"]:
        i["blast"]["reachable_roles"] = sorted(i["blast"]["reachable_roles"])
        i["blast"]["capabilities"] = dict(sorted(i["blast"]["capabilities"].items()))
    return r


@pytest.mark.skipif(NODE is None, reason="node not installed")
@pytest.mark.parametrize("sample", ["iam-small.json", "samples/iam-multihop-demo.json"])
def test_browser_engine_matches_python_engine(sample):
    path = ROOT / sample
    py = analyze(load_json(path), source=path.name, now=datetime.fromisoformat(NOW))
    out = subprocess.run([NODE, str(ROOT / "tools" / "js_analyze.js"), str(path), NOW], capture_output=True, check=True, encoding="utf-8")
    js = json.loads(out.stdout)
    assert js["meta"]["engine"] == "browser"
    a, b = _normalise(py), _normalise(js)
    for key in a:
        assert a[key] == b[key], f"{sample}: '{key}' differs between Python and browser engines"


@pytest.mark.skipif(NODE is None, reason="node not installed")
def test_browser_engine_rejects_garbage(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"hello": 1}', encoding="utf-8")
    out = subprocess.run([NODE, str(ROOT / "tools" / "js_analyze.js"), str(bad)], capture_output=True, encoding="utf-8")
    assert out.returncode == 2 and "Unrecognised IAM export" in out.stderr
