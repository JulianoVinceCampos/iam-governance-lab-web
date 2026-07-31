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
