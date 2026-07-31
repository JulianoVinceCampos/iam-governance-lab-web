"""Dataset editável lastreado em banco, com um restore-para-o-padrão durável.

Os engines de análise nunca mutam um store de identidades real. O que o editor muta é o
input sintético do próprio lab, persistido num banco para que um deployment público mantenha
as edições entre restarts. Toda edição reconstrói o :class:`Dataset` inteiro e o revalida (sem
referência inexistente, sem id duplicado, sem ciclo de grupo); só um snapshot válido é
gravado, numa única transação, então o banco nunca guarda uma edição meio aplicada.

O dataset padrão vem embutido na imagem como YAML. Ele semeia um banco vazio na primeira
subida e lastreia o :meth:`restore_defaults`, então mesmo que um visitante apague tudo, o demo
sempre pode voltar a um estado bom conhecido.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .db import Database
from .loader import load_dataset
from .model import Dataset

EDITABLE_KINDS = ("accounts", "entitlements", "groups", "roles", "identities", "sod_rules")


class StoreError(ValueError):
    """Levantado quando uma edição produziria um dataset inválido."""


def resolve_seed_dir() -> Path:
    """Localiza o dataset padrão embutido (YAML) usado para semear e restaurar."""
    env = os.environ.get("IAMGOV_DATA_DIR")
    if env:
        return Path(env)
    cwd_data = Path("data")
    if cwd_data.is_dir():
        return cwd_data
    return Path(__file__).resolve().parents[2] / "data"


class DataStore:
    def __init__(self, db_url: str | None = None, seed_dir: str | Path | None = None) -> None:
        self.seed_dir = Path(seed_dir) if seed_dir else resolve_seed_dir()
        self._default_payload = load_dataset(self.seed_dir).model_dump(mode="json")
        self.db = Database(db_url)
        if self.db.is_empty():
            self.db.seed(self._default_payload)
        self._ds = Dataset.model_validate(self.db.to_payload())

    @property
    def dataset(self) -> Dataset:
        return self._ds

    def as_payload(self) -> dict[str, Any]:
        return self._ds.model_dump(mode="json")

    def _commit(self, payload: dict[str, Any]) -> None:
        try:
            ds = Dataset.model_validate(payload)
        except Exception as exc:  # ValidationError do pydantic ou ValueError de integridade
            raise StoreError(str(exc)) from exc
        self.db.seed(ds.model_dump(mode="json"))
        self._ds = ds

    def upsert(self, kind: str, obj: dict[str, Any]) -> None:
        if kind not in EDITABLE_KINDS:
            raise StoreError(f"unknown kind: {kind}")
        if not obj.get("id"):
            raise StoreError("object needs a non-empty 'id'")
        payload = self.as_payload()
        items: list[dict[str, Any]] = payload[kind]
        for i, existing in enumerate(items):
            if existing.get("id") == obj["id"]:
                items[i] = obj
                break
        else:
            items.append(obj)
        self._commit(payload)

    def delete(self, kind: str, item_id: str) -> None:
        if kind not in EDITABLE_KINDS:
            raise StoreError(f"unknown kind: {kind}")
        payload = self.as_payload()
        before = len(payload[kind])
        payload[kind] = [x for x in payload[kind] if x.get("id") != item_id]
        if len(payload[kind]) == before:
            raise StoreError(f"{kind} id not found: {item_id}")
        self._commit(payload)

    def restore_defaults(self) -> None:
        """Reseta o banco para o dataset padrão embutido."""
        self.db.seed(self._default_payload)
        self._ds = Dataset.model_validate(self._default_payload)
