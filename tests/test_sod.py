"""Detecção de SoD: respostas exatas no dataset tiny, contagens travadas no data publicado."""

from __future__ import annotations

from iamgov.model import Dataset
from iamgov.sod import find_violations


def test_tiny_single_inherited_violation(tiny_ds: Dataset) -> None:
    violations = find_violations(tiny_ds)
    assert len(violations) == 1
    v = violations[0]
    assert v.identity_id == "u-lead"
    assert v.severity.value == "critical"
    # Os dois lados herdados por grupo: remediação é no grupo, não na identity.
    assert v.inherited_only is True
    assert {m.entitlement_id for m in v.side_a} == {"e-vendor"}
    assert {m.entitlement_id for m in v.side_b} == {"e-pay"}


def test_clean_identity_has_no_violation(tiny_ds: Dataset) -> None:
    assert all(v.identity_id != "u-clean" for v in find_violations(tiny_ds))


def test_two_distinct_entitlements_required() -> None:
    # Uma regra cujos dois lados casam o MESMO entitlement único não é falha de separação.
    payload = {
        "accounts": [{"id": "a1", "name": "A", "environment": "production"}],
        "entitlements": [
            {"id": "e1", "account_id": "a1", "name": "E", "actions": ["x:*"],
             "tags": ["red", "blue"]}
        ],
        "groups": [],
        "roles": [],
        "identities": [
            {"id": "u1", "name": "U", "type": "human", "department": "d", "title": "t",
             "home_account_id": "a1", "entitlement_ids": ["e1"]}
        ],
        "sod_rules": [
            {"id": "r", "name": "same-ent", "set_a": [{"match": "tag", "values": ["red"]}],
             "set_b": [{"match": "tag", "values": ["blue"]}]}
        ],
    }
    ds = Dataset.model_validate(payload)
    assert find_violations(ds) == []


def test_main_dataset_violation_counts(main_ds: Dataset) -> None:
    violations = find_violations(main_ds)
    by_sev = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for v in violations:
        by_sev[v.severity.value] += 1
    assert by_sev == {"low": 9, "medium": 8, "high": 10, "critical": 10}
    # Alice herda a toxic combination inteira; Bob carrega payment direto.
    alice = next(v for v in violations if v.identity_id == "id-alice")
    assert alice.inherited_only is True
    bob = next(v for v in violations if v.identity_id == "id-bob")
    assert bob.inherited_only is False
