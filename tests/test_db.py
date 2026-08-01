"""A camada de banco: seed substitui o snapshot inteiro e faz round-trip para um Dataset."""

from __future__ import annotations

from pathlib import Path

from iamgov.db import Database
from iamgov.loader import load_dataset
from iamgov.model import Dataset

DATA_DIR = Path(__file__).resolve().parents[1] / "data"


def _seed_payload() -> dict:
    return load_dataset(DATA_DIR).model_dump(mode="json")


def _db(tmp_path: Path, name: str = "t.db") -> Database:
    return Database(f"sqlite:///{(tmp_path / name).as_posix()}")


def test_empty_then_seed(tmp_path: Path) -> None:
    db = _db(tmp_path)
    assert db.is_empty()
    db.seed(_seed_payload())
    assert not db.is_empty()


def test_roundtrip_validates_back_into_dataset(tmp_path: Path) -> None:
    db = _db(tmp_path)
    payload = _seed_payload()
    db.seed(payload)
    ds = Dataset.model_validate(db.to_payload())
    assert len(ds.identities) == len(payload["identities"])
    assert len(ds.accounts) == len(payload["accounts"])
    assert len(ds.sod_rules) == len(payload["sod_rules"])
    assert len(ds.abac_rules) == len(payload["abac_rules"])
    assert ds.policy.dormancy_days == payload["policy"]["dormancy_days"]


def test_seed_replaces_rather_than_appends(tmp_path: Path) -> None:
    db = _db(tmp_path)
    db.seed(_seed_payload())
    smaller = _seed_payload()
    smaller["accounts"] = smaller["accounts"][:1]
    db.seed(smaller)
    assert len(db.to_payload()["accounts"]) == 1
