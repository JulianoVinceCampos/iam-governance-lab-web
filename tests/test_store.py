"""O store editável: edições são validadas ao vivo, integridade é imposta, restore é limpo."""

from __future__ import annotations

from pathlib import Path

import pytest

from iamgov.loader import load_dataset
from iamgov.store import DataStore, StoreError

DATA_DIR = Path(__file__).resolve().parents[1] / "data"


def test_upsert_new_identity(store: DataStore) -> None:
    store.upsert(
        "identities",
        {
            "id": "id-temp",
            "name": "Temp",
            "type": "human",
            "department": "X",
            "title": "Analyst",
            "home_account_id": "acc-prod",
            "group_ids": ["grp-prod-readonly"],
        },
    )
    assert store.dataset.identity("id-temp").name == "Temp"


def test_upsert_dangling_reference_rejected(store: DataStore) -> None:
    with pytest.raises(StoreError):
        store.upsert(
            "identities",
            {
                "id": "id-bad",
                "name": "Bad",
                "type": "human",
                "department": "X",
                "title": "T",
                "home_account_id": "ghost-account",
            },
        )
    # A edição rejeitada deixa o estado anterior intacto.
    assert all(i.id != "id-bad" for i in store.dataset.identities)


def test_delete_referenced_entitlement_rejected(store: DataStore) -> None:
    # Um grupo ainda concede este entitlement, então removê-lo deixaria uma referência solta.
    with pytest.raises(StoreError):
        store.delete("entitlements", "ent-prod-approve-payment")


def test_delete_unreferenced_ok(store: DataStore) -> None:
    store.upsert(
        "entitlements",
        {"id": "ent-temp", "account_id": "acc-dev", "name": "Temp", "actions": ["x:*"]},
    )
    store.delete("entitlements", "ent-temp")
    assert all(e.id != "ent-temp" for e in store.dataset.entitlements)


def test_group_self_cycle_rejected(store: DataStore) -> None:
    with pytest.raises(StoreError):
        store.upsert(
            "groups",
            {
                "id": "grp-cycle",
                "account_id": "acc-prod",
                "name": "Cycle",
                "member_of": ["grp-cycle"],
            },
        )


def test_restore_defaults_discards_edits(store: DataStore) -> None:
    store.upsert("accounts", {"id": "acc-temp", "name": "Temp", "environment": "development"})
    assert any(a.id == "acc-temp" for a in store.dataset.accounts)
    store.restore_defaults()
    assert all(a.id != "acc-temp" for a in store.dataset.accounts)


def test_edits_persist_across_instances(tmp_path: Path) -> None:
    # Um segundo store aberto no mesmo banco enxerga a edição commitada pelo primeiro.
    db_url = f"sqlite:///{(tmp_path / 'shared.db').as_posix()}"
    first = DataStore(db_url=db_url, seed_dir=DATA_DIR)
    first.upsert("accounts", {"id": "acc-new", "name": "New", "environment": "development"})

    second = DataStore(db_url=db_url, seed_dir=DATA_DIR)
    assert any(a.id == "acc-new" for a in second.dataset.accounts)


def test_restore_defaults_rebuilds(tmp_path: Path) -> None:
    db_url = f"sqlite:///{(tmp_path / 'wipe.db').as_posix()}"
    s = DataStore(db_url=db_url, seed_dir=DATA_DIR)
    default_identities = len(load_dataset(DATA_DIR).identities)

    s.upsert("accounts", {"id": "acc-junk", "name": "Junk", "environment": "development"})
    assert any(a.id == "acc-junk" for a in s.dataset.accounts)

    # Restore substitui o snapshot inteiro, então cura qualquer edição, seja qual for o estado.
    s.restore_defaults()
    assert all(a.id != "acc-junk" for a in s.dataset.accounts)
    assert len(s.dataset.identities) == default_identities
