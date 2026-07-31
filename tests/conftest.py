"""Fixtures compartilhados.

Dois sabores de dataset:

* ``tiny_ds`` é montado em código com respostas calculadas à mão. Os testes de unidade
  asseguram resultados exatos contra ele, então uma regressão de engine falha alto e aponta
  a causa.
* ``main_ds`` carrega o diretório ``data/`` publicado. Alguns testes travam seus números de
  resumo, para que mudanças no dataset de exemplo sejam intencionais, não acidentais.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from iamgov.loader import load_dataset
from iamgov.model import Dataset

DATA_DIR = Path(__file__).resolve().parents[1] / "data"

# Aponta o store da app para um SQLite descartável e para o seed do repo, para os testes nunca
# tocarem num banco real ou no iamgov.db do dev. Setado antes de a app criar o store.
_TMP_DB = Path(tempfile.mkdtemp(prefix="iamgov-test-")) / "api.db"
os.environ["DATABASE_URL"] = f"sqlite:///{_TMP_DB.as_posix()}"
os.environ["IAMGOV_DATA_DIR"] = str(DATA_DIR)


def build_tiny() -> Dataset:
    """Dataset mínimo de duas contas com um SoD herdado e um escalonamento cross-account.

    Findings esperados (assegurados pelos testes):
      * SoD: exatamente u-lead viola a regra de finanças, só por herança.
      * Reachability: só u-dev alcança e-admin, via assume, cruzando contas, comprimento 4.
    """
    payload = {
        "accounts": [
            {"id": "a1", "name": "Dev", "environment": "development"},
            {"id": "a2", "name": "Prod", "environment": "production"},
        ],
        "entitlements": [
            {"id": "e-vendor", "account_id": "a2", "name": "Create vendor",
             "actions": ["vendor:Create"], "privilege_level": "medium", "tags": ["vendor"]},
            {"id": "e-pay", "account_id": "a2", "name": "Approve payment",
             "actions": ["payment:Approve"], "privilege_level": "high", "tags": ["payment"]},
            {"id": "e-admin", "account_id": "a2", "name": "Prod admin",
             "actions": ["iam:*"], "privilege_level": "critical", "tags": ["admin"]},
            {"id": "e-assume", "account_id": "a1", "name": "Assume prod admin",
             "actions": ["sts:AssumeRole"], "privilege_level": "medium",
             "tags": ["assume"], "assume_targets": ["r-admin"]},
        ],
        "roles": [
            {"id": "r-admin", "account_id": "a2", "name": "Prod admin role",
             "entitlement_ids": ["e-admin"], "trusts": ["a1"]},
        ],
        "groups": [
            {"id": "g-ops", "account_id": "a2", "name": "Ops", "entitlement_ids": ["e-vendor"]},
            {"id": "g-appr", "account_id": "a2", "name": "Approvers", "entitlement_ids": ["e-pay"]},
            {"id": "g-lead", "account_id": "a2", "name": "Lead", "member_of": ["g-ops", "g-appr"]},
            {"id": "g-dev", "account_id": "a1", "name": "Dev", "entitlement_ids": ["e-assume"]},
        ],
        "identities": [
            {"id": "u-lead", "name": "Lead", "type": "human", "department": "Fin",
             "title": "Finance Lead", "home_account_id": "a2", "group_ids": ["g-lead"]},
            {"id": "u-dev", "name": "Dev", "type": "human", "department": "Eng",
             "title": "Dev", "home_account_id": "a1", "group_ids": ["g-dev"]},
            {"id": "u-clean", "name": "Clean", "type": "human", "department": "Fin",
             "title": "Analyst", "home_account_id": "a2", "group_ids": ["g-ops"]},
        ],
        "sod_rules": [
            {"id": "r-fin", "name": "Vendor vs payment", "severity": "critical",
             "set_a": [{"match": "tag", "values": ["vendor"]}],
             "set_b": [{"match": "tag", "values": ["payment"]}]},
        ],
    }
    return Dataset.model_validate(payload)


@pytest.fixture
def tiny_ds() -> Dataset:
    return build_tiny()


@pytest.fixture(scope="session")
def main_ds() -> Dataset:
    return load_dataset(DATA_DIR)


@pytest.fixture
def store(tmp_path: Path):  # type: ignore[no-untyped-def]
    """Um store lastreado em banco, sobre seu próprio SQLite temp, semeado do data publicado."""
    from iamgov.store import DataStore

    db_url = f"sqlite:///{(tmp_path / 'store.db').as_posix()}"
    return DataStore(db_url=db_url, seed_dir=DATA_DIR)
