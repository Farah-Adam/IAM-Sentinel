"""FastAPI web dashboard + REST API."""
from __future__ import annotations

import json
import os
from collections import OrderedDict
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from . import __version__
from .engine import analyze
from .loader import IAMParseError, load_json
from .reports import EXPORTERS

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "static"
SAMPLES = {
    "default": ROOT / "iam-small.json",
    "multihop": ROOT / "samples" / "iam-multihop-demo.json",
}
MAX_UPLOAD = 25 * 1024 * 1024

app = FastAPI(title="IAM Sentinel", version=__version__, description="Cloud Identity & Excessive IAM Permission Detection (PS-07)")
_cache: "OrderedDict[str, dict]" = OrderedDict()


def _remember(result: dict) -> dict:
    _cache[result["meta"]["analysis_id"]] = result
    _cache.move_to_end(result["meta"]["analysis_id"])
    while len(_cache) > 20:
        _cache.popitem(last=False)
    return result


def default_file() -> Path:
    return Path(os.environ.get("IAM_SENTINEL_FILE", SAMPLES["default"]))


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "version": __version__, "default_file": default_file().name}


@app.get("/api/samples")
def samples() -> dict:
    return {"samples": [{"id": k, "file": v.name, "available": v.exists()} for k, v in SAMPLES.items()],
            "default": default_file().name}


@app.get("/api/analysis")
def analysis(sample: str = "default") -> JSONResponse:
    path = default_file() if sample == "default" else SAMPLES.get(sample)
    if path is None or not path.exists():
        raise HTTPException(404, f"Sample '{sample}' not found")
    try:
        return JSONResponse(_remember(analyze(load_json(path), source=path.name)))
    except IAMParseError as e:
        raise HTTPException(422, str(e))


@app.post("/api/analyze")
async def analyze_upload(file: UploadFile = File(...)) -> JSONResponse:
    raw = await file.read()
    if len(raw) > MAX_UPLOAD:
        raise HTTPException(413, "File too large (25 MB max)")
    try:
        data = json.loads(raw.decode("utf-8-sig"))
        return JSONResponse(_remember(analyze(data, source=file.filename or "upload.json")))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise HTTPException(422, f"Not valid JSON: {e}")
    except IAMParseError as e:
        raise HTTPException(422, str(e))


@app.get("/api/report/{analysis_id}.{fmt}")
def report(analysis_id: str, fmt: str) -> Response:
    if fmt not in EXPORTERS:
        raise HTTPException(400, f"Unknown format {fmt}; use one of {', '.join(EXPORTERS)}")
    result = _cache.get(analysis_id)
    if result is None:
        raise HTTPException(404, "Analysis expired - re-run the scan")
    fn, mime = EXPORTERS[fmt]
    name = f"iam-sentinel-{result['meta']['account_id']}.{ 'sarif.json' if fmt == 'sarif' else fmt}"
    return Response(fn(result), media_type=mime, headers={"Content-Disposition": f'attachment; filename="{name}"'})


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")
