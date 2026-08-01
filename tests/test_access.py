"""Standing access efetivo e sua procedência."""

from __future__ import annotations

from iamgov.access import effective_access, group_closure
from iamgov.model import Dataset, GrantSource


def test_group_closure_follows_nesting(tiny_ds: Dataset) -> None:
    # g-lead aninha g-ops e g-appr, então seu closure é os três.
    closure = group_closure(tiny_ds, "g-lead")
    assert set(closure) == {"g-lead", "g-ops", "g-appr"}
    assert closure["g-ops"] == ("g-lead", "g-ops")


def test_effective_access_collects_inherited(tiny_ds: Dataset) -> None:
    access = effective_access(tiny_ds, "u-lead")
    # Finance lead herda vendor (via g-ops) e payment (via g-appr).
    assert access.entitlement_ids == {"e-vendor", "e-pay"}
    vendor_grant = access.grant_for("e-vendor")
    assert vendor_grant.source is GrantSource.GROUP
    assert vendor_grant.group_path == ("g-lead", "g-ops")


def test_direct_grant_beats_inherited() -> None:
    payload = {
        "accounts": [{"id": "a1", "name": "A", "environment": "production"}],
        "entitlements": [{"id": "e1", "account_id": "a1", "name": "E", "actions": ["x:*"]}],
        "groups": [{"id": "g1", "account_id": "a1", "name": "G", "entitlement_ids": ["e1"]}],
        "roles": [],
        "identities": [
            {"id": "u1", "name": "U", "type": "human", "department": "d", "title": "t",
             "home_account_id": "a1", "group_ids": ["g1"], "entitlement_ids": ["e1"]}
        ],
    }
    ds = Dataset.model_validate(payload)
    access = effective_access(ds, "u1")
    assert access.grant_for("e1").source is GrantSource.DIRECT


def _abac_payload() -> dict:
    """Duas identities, uma casa a regra de atributo por department, a outra não."""
    return {
        "accounts": [{"id": "a1", "name": "A", "environment": "security"}],
        "entitlements": [{"id": "e1", "account_id": "a1", "name": "Audit", "actions": ["x:*"]}],
        "groups": [{"id": "g1", "account_id": "a1", "name": "G", "entitlement_ids": ["e1"]}],
        "roles": [],
        "identities": [
            {"id": "u-sec", "name": "Sec", "type": "human", "department": "Security",
             "title": "Auditor", "home_account_id": "a1"},
            {"id": "u-fin", "name": "Fin", "type": "human", "department": "Finance",
             "title": "Analyst", "home_account_id": "a1"},
        ],
        "abac_rules": [
            {"id": "ar-audit", "name": "Security gets audit",
             "conditions": [{"attribute": "department", "values": ["Security"]}],
             "entitlement_ids": ["e1"]},
        ],
    }


def test_abac_rule_grants_by_attribute() -> None:
    ds = Dataset.model_validate(_abac_payload())
    sec = effective_access(ds, "u-sec")
    assert "e1" in sec.entitlement_ids
    grant = sec.grant_for("e1")
    assert grant.source is GrantSource.ABAC
    assert grant.rule_id == "ar-audit"
    assert grant.describe() == "abac via ar-audit"
    # Quem não casa o atributo não recebe o entitlement por ABAC.
    fin = effective_access(ds, "u-fin")
    assert "e1" not in fin.entitlement_ids


def test_abac_conditions_are_conjunctive() -> None:
    payload = _abac_payload()
    # Exige department Security E type service; a identity humana de Security não casa mais.
    payload["abac_rules"][0]["conditions"].append({"attribute": "type", "values": ["service"]})
    ds = Dataset.model_validate(payload)
    assert "e1" not in effective_access(ds, "u-sec").entitlement_ids


def test_abac_precedence_below_direct_above_group() -> None:
    payload = _abac_payload()
    # A identity de Security também é membro de g1 (que carrega e1): grupo + atributo no mesmo
    # entitlement. A procedência escolhida deve ser ABAC (vence grupo, perde só para direto).
    payload["identities"][0]["group_ids"] = ["g1"]
    ds = Dataset.model_validate(payload)
    assert effective_access(ds, "u-sec").grant_for("e1").source is GrantSource.ABAC
