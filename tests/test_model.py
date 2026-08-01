"""Integridade referencial: dataset ruim tem que falhar no load, não produzir finding errado."""

from __future__ import annotations

import pytest

from iamgov.model import Dataset


def _base() -> dict:
    return {
        "accounts": [{"id": "a1", "name": "A", "environment": "production"}],
        "entitlements": [{"id": "e1", "account_id": "a1", "name": "E", "actions": ["x:*"]}],
        "groups": [],
        "roles": [],
        "identities": [
            {"id": "u1", "name": "U", "type": "human", "department": "d",
             "title": "t", "home_account_id": "a1"}
        ],
    }


def test_valid_minimal_dataset() -> None:
    ds = Dataset.model_validate(_base())
    assert ds.entitlement("e1").account_id == "a1"


def test_unknown_account_rejected() -> None:
    payload = _base()
    payload["entitlements"][0]["account_id"] = "ghost"
    with pytest.raises(ValueError, match="unknown account"):
        Dataset.model_validate(payload)


def test_unknown_group_membership_rejected() -> None:
    payload = _base()
    payload["identities"][0]["group_ids"] = ["ghost"]
    with pytest.raises(ValueError, match="unknown group"):
        Dataset.model_validate(payload)


def test_assume_target_must_be_a_role() -> None:
    payload = _base()
    payload["entitlements"][0]["assume_targets"] = ["e1"]  # aponta para um entitlement, não role
    with pytest.raises(ValueError, match="assume_target"):
        Dataset.model_validate(payload)


def test_abac_rule_unknown_entitlement_rejected() -> None:
    payload = _base()
    payload["abac_rules"] = [
        {"id": "ar1", "name": "bad", "conditions": [{"attribute": "department",
         "values": ["X"]}], "entitlement_ids": ["ghost-ent"]}
    ]
    with pytest.raises(ValueError, match="unknown entitlement"):
        Dataset.model_validate(payload)


def test_abac_rule_bad_attribute_rejected() -> None:
    payload = _base()
    payload["abac_rules"] = [
        {"id": "ar1", "name": "bad", "conditions": [{"attribute": "salary",
         "values": ["100"]}], "entitlement_ids": ["e1"]}
    ]
    with pytest.raises(ValueError):
        Dataset.model_validate(payload)


def test_group_cycle_rejected() -> None:
    payload = _base()
    payload["groups"] = [
        {"id": "g1", "account_id": "a1", "member_of": ["g2"], "name": "g1"},
        {"id": "g2", "account_id": "a1", "member_of": ["g1"], "name": "g2"},
    ]
    with pytest.raises(ValueError, match="cycle"):
        Dataset.model_validate(payload)


def test_duplicate_ids_rejected() -> None:
    payload = _base()
    payload["accounts"].append({"id": "a1", "name": "dup", "environment": "development"})
    with pytest.raises(ValueError, match="duplicate account"):
        Dataset.model_validate(payload)
