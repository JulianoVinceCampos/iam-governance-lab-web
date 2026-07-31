"""Superfície da API: todo endpoint responde, e a query de escalonamento devolve um path real."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from iamgov.api import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def _restore_store():  # type: ignore[no-untyped-def]
    """Mantém o store compartilhado limpo entre testes restaurando o padrão depois."""
    yield
    client.post("/api/data/restore")


def test_health() -> None:
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@pytest.mark.parametrize(
    "path",
    [
        "/api/metrics",
        "/api/accounts",
        "/api/identities",
        "/api/sod",
        "/api/reachability",
        "/api/escalation",
        "/api/jml",
        "/api/recert",
        "/api/graph",
        "/api/graph/targets",
    ],
)
def test_endpoint_answers(path: str) -> None:
    assert client.get(path).status_code == 200


def test_graph_path_cross_account_escalation() -> None:
    r = client.get(
        "/api/graph/path",
        params={"identity": "id-erin", "target": "entitlement:ent-prod-iam-admin"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["reachable"] is True
    assert body["path"]["uses_assume"] is True
    assert body["path"]["crosses_account"] is True
    # O grafo destacado volta para a UI conseguir desenhar a rota.
    assert body["graph"]["nodes"] and body["graph"]["edges"]


def test_graph_path_unknown_identity_is_404() -> None:
    r = client.get(
        "/api/graph/path",
        params={"identity": "ghost", "target": "entitlement:ent-prod-iam-admin"},
    )
    assert r.status_code == 404


def test_editor_data_is_editable_shape() -> None:
    body = client.get("/api/data").json()
    for kind in ("accounts", "entitlements", "groups", "roles", "identities", "sod_rules"):
        assert kind in body


def test_editor_upsert_then_delete_recomputes() -> None:
    obj = {
        "id": "id-temp",
        "name": "Temp",
        "type": "human",
        "department": "X",
        "title": "Analyst",
        "home_account_id": "acc-prod",
        "group_ids": ["grp-prod-dba"],
    }
    created = client.post("/api/data/identities", json=obj)
    assert created.status_code == 200
    # A resposta carrega as métricas recalculadas.
    assert "metrics" in created.json()
    ids = [i["id"] for i in client.get("/api/data").json()["identities"]]
    assert "id-temp" in ids
    assert client.delete("/api/data/identities/id-temp").status_code == 200


def test_editor_rejects_integrity_violation() -> None:
    bad = {
        "id": "id-bad",
        "name": "Bad",
        "type": "human",
        "department": "X",
        "title": "T",
        "home_account_id": "ghost-account",
    }
    assert client.post("/api/data/identities", json=bad).status_code == 400


def test_editor_unknown_kind_is_404() -> None:
    assert client.post("/api/data/widgets", json={"id": "x"}).status_code == 404


def test_editor_restore_route_not_shadowed_by_kind() -> None:
    # Regressão: /api/data/restore não pode ser capturada por /api/data/{kind}.
    r = client.post("/api/data/restore")
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_editor_restore_recovers_seeded_state() -> None:
    before = len(client.get("/api/data").json()["identities"])
    # Apaga o que for apagável (managers com subordinados são recusados, o que é correto).
    for i in client.get("/api/data").json()["identities"]:
        client.delete(f"/api/data/identities/{i['id']}")
    client.post("/api/data/restore")
    assert len(client.get("/api/data").json()["identities"]) == before
