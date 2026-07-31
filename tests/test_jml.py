"""Findings de lifecycle contra o dataset publicado (casos semeados de propósito)."""

from __future__ import annotations

from iamgov.jml import dormant_identities, joiner_gaps, orphaned_access, privilege_creep
from iamgov.model import Dataset


def test_orphaned_access_finds_leavers(main_ds: Dataset) -> None:
    orphans = {o.identity_id for o in orphaned_access(main_ds)}
    assert orphans == {"id-ken", "id-laura"}  # engineer terminated + DBA disabled


def test_dormant_identities(main_ds: Dataset) -> None:
    dormant = {d.identity_id for d in dormant_identities(main_ds)}
    assert dormant == {"id-grace", "id-mallory"}


def test_privilege_creep_targets(main_ds: Dataset) -> None:
    creep = {c.identity_id for c in privilege_creep(main_ds)}
    # Bob (payment direto), Carol (approve direto), Olivia (grupo extra), Frank (admin).
    assert creep == {"id-bob", "id-carol", "id-olivia", "id-frank"}


def test_frank_creep_is_admin(main_ds: Dataset) -> None:
    frank = next(c for c in privilege_creep(main_ds) if c.identity_id == "id-frank")
    extra_ids = {e.entitlement_id for e in frank.extra}
    assert "ent-dev-admin" in extra_ids


def test_joiner_gaps(main_ds: Dataset) -> None:
    gaps = {g.identity_id for g in joiner_gaps(main_ds)}
    assert gaps == {"id-nathan", "id-olivia", "id-frank"}
    nathan = next(g for g in joiner_gaps(main_ds) if g.identity_id == "id-nathan")
    assert "grp-prod-finance-lead" in nathan.missing_group_ids
