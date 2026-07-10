"""FastAPI service: dry-run preview with HTML redline diff (required for
customer policy sign-off) + break-glass re-identification endpoint.

Dry runs produce receipts and a redline WITHOUT writing final artifacts.
"""
from __future__ import annotations

import os

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse

from . import __version__
from .core.redline import redline_html
from .core.types import PolicyViolation
from .core.vault import BreakGlassDenied
from .models import DryRunRequest, RevealRequest
from .runtime import Runtime, load_app_config

app = FastAPI(title="Anonymization Engine", version=__version__)
_runtime: Runtime | None = None


def get_runtime() -> Runtime:
    global _runtime
    if _runtime is None:
        _runtime = Runtime(load_app_config(os.environ.get("ANON_CONFIG", "config/app.yaml")))
    return _runtime


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "version": __version__}


@app.post("/dry-run")
def dry_run(req: DryRunRequest) -> dict:
    rt = get_runtime()
    job = req.job.to_core()
    engine = rt.engine_for(job)
    try:
        result = engine.transform(
            req.text, [f.to_core() for f in req.findings], job, req.file_id
        )
    except PolicyViolation as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    receipt = result.receipt
    return {
        "masked_text": result.masked_text,
        "receipt": receipt.to_dict(),
        "deliverable": result.deliverable,
    }


@app.post("/dry-run/redline", response_class=HTMLResponse)
def dry_run_redline(req: DryRunRequest) -> str:
    rt = get_runtime()
    job = req.job.to_core()
    result = rt.engine_for(job).transform(
        req.text, [f.to_core() for f in req.findings], job, req.file_id
    )
    r = result.receipt
    return redline_html(
        req.text, result.masked_text, file_id=req.file_id, mode=r.mode,
        policy_version=r.policy_version, status=r.status, count=len(r.replacements),
    )


@app.post("/vault/reveal")
def reveal(
    req: RevealRequest,
    x_actor: str = Header(...),
    x_role: str = Header(...),
    tenant_id: str = "default",
) -> dict:
    """Break-glass re-identification: role-checked, reason mandatory, audited."""
    rt = get_runtime()
    try:
        original = rt.vault_for(tenant_id).reveal(
            req.pseudonym, actor=x_actor, role=x_role, reason=req.reason
        )
    except BreakGlassDenied as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"pseudonym": req.pseudonym, "original": original}
