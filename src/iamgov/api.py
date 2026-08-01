"""Aplicação FastAPI: API de governança read-only, um editor de dados e o dashboard.

Rode com:

    iamgov serve
    # ou
    uvicorn iamgov.api:app

O estado vive num banco (SQLite por padrão, ver iamgov.db). O YAML embutido semeia um banco
vazio na primeira subida e lastreia o "restore defaults", então um deployment público sempre
pode voltar a um estado bom conhecido. Os endpoints de análise são read-only; os endpoints do
editor mutam o dataset sintético do próprio lab, nunca uma fonte de identidade real.

Ambiente opcional:
    DATABASE_URL         URL SQLAlchemy (ex. postgresql+psycopg://...); sobrepõe o SQLite
    IAMGOV_DB_PATH       caminho do arquivo SQLite (padrão do container: /data/iamgov.db)
    IAMGOV_DATA_DIR      diretório do seed YAML (padrão do container: /app/data)
    IAMGOV_AUTH_USER     se ambos setados, operações de escrita exigem HTTP Basic auth
    IAMGOV_AUTH_PASS
    IAMGOV_CORS_ORIGINS  origens liberadas por CORS (lista por vírgula); vazio = só same-origin
    DEMO_RESET_MINUTES   se > 0, restaura o padrão automaticamente nesse intervalo
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import os
import secrets
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from fastapi import Body, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from .access import effective_access
from .jml import dormant_identities, joiner_gaps, orphaned_access, privilege_creep
from .loader import DataError
from .model import Dataset
from .reachability import (
    build_graph,
    escalation_paths,
    export_cytoscape,
    node_id,
    reach_path,
    reachability_report,
    sensitive_target_nodes,
)
from .recert import build_campaigns, revocation_worklist
from .report import build_report, headline_metrics
from .sod import find_violations
from .store import EDITABLE_KINDS, DataStore, StoreError

_WEB_DIR = Path(__file__).parent / "web"
_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

_store: DataStore | None = None


def _get_store() -> DataStore:
    global _store
    if _store is None:
        try:
            _store = DataStore()
        except DataError as exc:
            raise HTTPException(status_code=500, detail=f"dataset error: {exc}") from exc
    return _store


def get_dataset() -> Dataset:
    return _get_store().dataset


# --- HTTP Basic auth opcional na escrita ---------------------------------------------
def _authorized(header: str | None, user: str, password: str) -> bool:
    if not header or not header.startswith("Basic "):
        return False
    try:
        got_user, _, got_pw = base64.b64decode(header[6:]).decode().partition(":")
    except (ValueError, UnicodeDecodeError):
        return False
    return secrets.compare_digest(got_user, user) and secrets.compare_digest(got_pw, password)


class WriteAuthMiddleware(BaseHTTPMiddleware):
    """Exige HTTP Basic auth nas operações de escrita, só quando há credencial configurada.

    A leitura fica aberta, então um demo público é visível por qualquer um. Defina
    IAMGOV_AUTH_USER e IAMGOV_AUTH_PASS para proteger o editor (create/update/delete/restore).
    Ponha TLS na frente, porque Basic auth é encodado, não encriptado.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        user = os.environ.get("IAMGOV_AUTH_USER")
        password = os.environ.get("IAMGOV_AUTH_PASS")
        if (
            user
            and password
            and request.method in _WRITE_METHODS
            and not _authorized(request.headers.get("Authorization"), user, password)
        ):
            return Response(
                status_code=401,
                headers={"WWW-Authenticate": 'Basic realm="iam-governance-lab"'},
            )
        return await call_next(request)


# --- lifespan: seed no start, restore periódico opcional -----------------------------
def _reset_minutes() -> int:
    try:
        return int(os.environ.get("DEMO_RESET_MINUTES", "0") or "0")
    except ValueError:
        return 0


async def _periodic_restore(minutes: int) -> None:
    while True:
        await asyncio.sleep(minutes * 60)
        with contextlib.suppress(Exception):
            _get_store().restore_defaults()


@contextlib.asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    _get_store()  # semeia um banco vazio e aquece o dataset em memória
    task: asyncio.Task[None] | None = None
    minutes = _reset_minutes()
    if minutes > 0:
        task = asyncio.create_task(_periodic_restore(minutes))
    try:
        yield
    finally:
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task


app = FastAPI(
    title="iam-governance-lab",
    version="0.1.0",
    description="Governança IAM/IGA sobre dados sintéticos multi-conta, com editor de dados.",
    lifespan=lifespan,
)
app.add_middleware(WriteAuthMiddleware)


def _cors_origins() -> list[str]:
    """Origens permitidas por CORS, vindas de IAMGOV_CORS_ORIGINS (lista separada por vírgula).

    O dashboard é servido pela mesma origem da API, então CORS nem é necessário para ele; por
    isso o padrão é uma lista vazia (nenhuma origem cross-site liberada) em vez de um wildcard.
    Consumir a API de outra origem passa a ser opt-in explícito por ambiente.
    """
    raw = os.environ.get("IAMGOV_CORS_ORIGINS", "").strip()
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


_cors = _cors_origins()
if _cors:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["*"],
    )


@app.get("/api/health")
def health() -> dict[str, object]:
    ds = get_dataset()
    return {"status": "ok", "accounts": len(ds.accounts), "identities": len(ds.identities)}


@app.get("/api/metrics")
def metrics() -> dict[str, object]:
    return headline_metrics(get_dataset())


@app.get("/api/report")
def report() -> dict[str, object]:
    return build_report(get_dataset())


@app.get("/api/accounts")
def accounts() -> list[dict[str, str]]:
    ds = get_dataset()
    return [{"id": a.id, "name": a.name, "environment": a.environment.value} for a in ds.accounts]


@app.get("/api/identities")
def identities() -> list[dict[str, object]]:
    ds = get_dataset()
    out: list[dict[str, object]] = []
    for i in ds.identities:
        access = effective_access(ds, i.id)
        out.append(
            {
                "id": i.id,
                "name": i.name,
                "type": i.type.value,
                "department": i.department,
                "title": i.title,
                "status": i.status.value,
                "home_account_id": i.home_account_id,
                "manager_id": i.manager_id,
                "last_activity_days": i.last_activity_days,
                "entitlement_count": len(access.entitlement_ids),
                "group_count": len(i.group_ids),
            }
        )
    return out


@app.get("/api/sod")
def sod() -> list[dict[str, object]]:
    return [v.to_dict() for v in find_violations(get_dataset())]


@app.get("/api/reachability")
def reachability() -> list[dict[str, object]]:
    return [t.to_dict() for t in reachability_report(get_dataset())]


@app.get("/api/escalation")
def escalation() -> list[dict[str, object]]:
    return [p.to_dict() for p in escalation_paths(get_dataset())]


@app.get("/api/jml")
def jml() -> dict[str, object]:
    ds = get_dataset()
    return {
        "joiner_gaps": [g.to_dict() for g in joiner_gaps(ds)],
        "privilege_creep": [c.to_dict() for c in privilege_creep(ds)],
        "orphaned_access": [o.to_dict() for o in orphaned_access(ds)],
        "dormant": [d.to_dict() for d in dormant_identities(ds)],
    }


@app.get("/api/recert")
def recert() -> dict[str, object]:
    ds = get_dataset()
    return {
        "campaigns": [c.to_dict() for c in build_campaigns(ds)],
        "revocation_worklist": [i.to_dict() for i in revocation_worklist(ds)],
    }


@app.get("/api/graph")
def graph() -> dict[str, object]:
    return export_cytoscape(get_dataset())


@app.get("/api/graph/targets")
def graph_targets() -> list[dict[str, str]]:
    """Os nós de entitlement sensível disponíveis como targets de reachability."""
    ds = get_dataset()
    g = build_graph(ds)
    out: list[dict[str, str]] = []
    for n in sensitive_target_nodes(g):
        a = g.nodes[n]
        out.append(
            {"node": n, "ref": a["ref"], "label": a["label"], "account": a.get("account", "")}
        )
    return out


@app.get("/api/graph/path")
def graph_path(
    identity: str = Query(..., description="identity id"),
    target: str = Query(..., description="node id do target, ex. entitlement:ent-prod-iam-admin"),
) -> dict[str, object]:
    """Computa o caminho mais curto de uma identity a um target e devolve o grafo destacado."""
    ds = get_dataset()
    try:
        path = reach_path(ds, identity, target)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    if path is None:
        return {
            "reachable": False,
            "identity": identity,
            "target": target,
            "graph": export_cytoscape(ds),
        }
    highlight = [node_id("identity", path.identity_id), *[s.node for s in path.steps[1:]]]
    return {
        "reachable": True,
        "path": path.to_dict(),
        "graph": export_cytoscape(ds, highlight_path=highlight),
    }


# --- editor de dados (muta o dataset do lab no banco, nunca um store real) ------------
@app.get("/api/data")
def data() -> dict[str, Any]:
    """O dataset editável completo, no shape que o editor da UI espera."""
    return _get_store().as_payload()


# A rota estática "restore" é declarada antes da paramétrica /api/data/{kind}, senão
# "restore" seria capturada como um valor de {kind}.
@app.post("/api/data/restore")
def data_restore() -> dict[str, object]:
    """Reseta o dataset para os defaults embutidos. Sempre disponível; cura um demo apagado."""
    store = _get_store()
    store.restore_defaults()
    return {"ok": True, "metrics": headline_metrics(store.dataset)}


@app.post("/api/data/{kind}")
def data_upsert(kind: str, body: dict[str, Any] = Body(...)) -> dict[str, object]:
    """Cria ou atualiza um item por id. Rejeitado com 400 se quebra a integridade."""
    store = _get_store()
    if kind not in EDITABLE_KINDS:
        raise HTTPException(status_code=404, detail=f"unknown kind: {kind}")
    try:
        store.upsert(kind, body)
    except StoreError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True, "metrics": headline_metrics(store.dataset)}


@app.delete("/api/data/{kind}/{item_id}")
def data_delete(kind: str, item_id: str) -> dict[str, object]:
    """Remove um item. Rejeitado com 400 se algo ainda o referencia."""
    store = _get_store()
    if kind not in EDITABLE_KINDS:
        raise HTTPException(status_code=404, detail=f"unknown kind: {kind}")
    try:
        store.delete(kind, item_id)
    except StoreError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True, "metrics": headline_metrics(store.dataset)}


# Monta o dashboard por último, para as rotas /api/* terem precedência.
if _WEB_DIR.is_dir():
    app.mount("/", StaticFiles(directory=str(_WEB_DIR), html=True), name="web")
