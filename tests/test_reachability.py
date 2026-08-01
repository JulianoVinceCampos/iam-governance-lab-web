"""Privilege reachability: caminhos de escalonamento, semântica de trust, flag cross-account."""

from __future__ import annotations

from iamgov.model import Dataset
from iamgov.reachability import (
    build_graph,
    escalation_paths,
    node_id,
    reachability_report,
    who_can_reach,
)


def test_tiny_escalation_path_is_cross_account(tiny_ds: Dataset) -> None:
    g = build_graph(tiny_ds)
    paths = who_can_reach(g, tiny_ds, node_id("entitlement", "e-admin"))
    assert [p.identity_id for p in paths] == ["u-dev"]
    p = paths[0]
    assert p.uses_assume is True
    assert p.crosses_account is True
    assert p.length == 4  # u-dev -> g-dev -> e-assume -> r-admin -> e-admin
    kinds = [s.kind for s in p.steps]
    assert kinds == ["identity", "group", "entitlement", "role", "entitlement"]


def test_trust_must_admit_source_account() -> None:
    # Igual ao tiny, mas o role só confia em outra conta, então não existe aresta de assume.
    payload = {
        "accounts": [
            {"id": "a1", "name": "Dev", "environment": "development"},
            {"id": "a2", "name": "Prod", "environment": "production"},
            {"id": "a3", "name": "Other", "environment": "development"},
        ],
        "entitlements": [
            {"id": "e-admin", "account_id": "a2", "name": "Admin", "actions": ["iam:*"],
             "privilege_level": "critical"},
            {"id": "e-assume", "account_id": "a1", "name": "Assume", "actions": ["sts:AssumeRole"],
             "privilege_level": "medium", "assume_targets": ["r-admin"]},
        ],
        "roles": [
            {"id": "r-admin", "account_id": "a2", "name": "R", "entitlement_ids": ["e-admin"],
             "trusts": ["a3"]}
        ],
        "groups": [{"id": "g", "account_id": "a1", "name": "G", "entitlement_ids": ["e-assume"]}],
        "identities": [
            {"id": "u", "name": "U", "type": "human", "department": "d", "title": "t",
             "home_account_id": "a1", "group_ids": ["g"]}
        ],
    }
    ds = Dataset.model_validate(payload)
    g = build_graph(ds)
    assert who_can_reach(g, ds, node_id("entitlement", "e-admin")) == []


def test_wildcard_trust_is_reachable() -> None:
    payload = {
        "accounts": [
            {"id": "a1", "name": "Dev", "environment": "development"},
            {"id": "a2", "name": "Mgmt", "environment": "management"},
        ],
        "entitlements": [
            {"id": "e-admin", "account_id": "a2", "name": "Admin", "actions": ["iam:*"],
             "privilege_level": "critical"},
            {"id": "e-assume", "account_id": "a1", "name": "Assume", "actions": ["sts:AssumeRole"],
             "privilege_level": "medium", "assume_targets": ["r-admin"]},
        ],
        "roles": [
            {"id": "r-admin", "account_id": "a2", "name": "R", "entitlement_ids": ["e-admin"],
             "trusts": ["*"]}
        ],
        "groups": [{"id": "g", "account_id": "a1", "name": "G", "entitlement_ids": ["e-assume"]}],
        "identities": [
            {"id": "u", "name": "U", "type": "human", "department": "d", "title": "t",
             "home_account_id": "a1", "group_ids": ["g"]}
        ],
    }
    ds = Dataset.model_validate(payload)
    g = build_graph(ds)
    paths = who_can_reach(g, ds, node_id("entitlement", "e-admin"))
    assert [p.identity_id for p in paths] == ["u"]


def test_abac_grant_creates_typed_edge() -> None:
    payload = {
        "accounts": [{"id": "a1", "name": "A", "environment": "security"}],
        "entitlements": [{"id": "e1", "account_id": "a1", "name": "Audit", "actions": ["x:*"]}],
        "groups": [],
        "roles": [],
        "identities": [
            {"id": "u", "name": "U", "type": "human", "department": "Security", "title": "t",
             "home_account_id": "a1"}
        ],
        "abac_rules": [
            {"id": "ar", "name": "sec", "conditions": [{"attribute": "department",
             "values": ["Security"]}], "entitlement_ids": ["e1"]}
        ],
    }
    ds = Dataset.model_validate(payload)
    g = build_graph(ds)
    edge = g.edges[node_id("identity", "u"), node_id("entitlement", "e1")]
    assert edge["kind"] == "abac_grant"


def test_main_dataset_escalation_all_cross_account(main_ds: Dataset) -> None:
    paths = escalation_paths(main_ds)
    assert len(paths) == 12
    assert all(p.crosses_account for p in paths)
    # Nove entitlements sensíveis (high/critical) são auditados como targets.
    assert len(reachability_report(main_ds)) == 9
