"""Carrega um diretório de dados num :class:`~iamgov.model.Dataset` validado.

Layout esperado dentro do diretório (cada arquivo é opcional, exceto accounts e
identities; arquivos ausentes viram coleções vazias):

    accounts.yaml      list[Account]
    entitlements.yaml  list[Entitlement]
    groups.yaml        list[Group]
    roles.yaml         list[Role]
    identities.yaml    list[Identity]
    sod-rules.yaml     list[SoDRule]
    policy.yaml        Policy (objeto, não lista)

A validação é em duas fases: o Pydantic valida o shape de cada registro, depois o model
validator do Dataset checa a integridade referencial e rejeita ciclos de nesting de grupo.
Dataset ruim falha alto no load em vez de produzir finding calado e errado.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .model import Dataset

_LIST_FILES = {
    "accounts": "accounts.yaml",
    "entitlements": "entitlements.yaml",
    "groups": "groups.yaml",
    "roles": "roles.yaml",
    "identities": "identities.yaml",
    "sod_rules": "sod-rules.yaml",
}


class DataError(RuntimeError):
    """Levantado quando o diretório de dados está incompleto ou malformado."""


def _read_yaml(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _read_list(directory: Path, filename: str) -> list[dict[str, Any]]:
    path = directory / filename
    if not path.exists():
        return []
    data = _read_yaml(path)
    if data is None:
        return []
    if not isinstance(data, list):
        raise DataError(f"{filename}: expected a YAML list, got {type(data).__name__}")
    return data


def load_dataset(data_dir: str | Path) -> Dataset:
    """Lê e valida o diretório de dados. Levanta :class:`DataError` em caso de problema."""
    directory = Path(data_dir)
    if not directory.is_dir():
        raise DataError(f"data directory not found: {directory}")

    payload: dict[str, Any] = {
        key: _read_list(directory, name) for key, name in _LIST_FILES.items()
    }

    policy_path = directory / "policy.yaml"
    if policy_path.exists():
        policy_raw = _read_yaml(policy_path)
        if policy_raw is not None:
            if not isinstance(policy_raw, dict):
                raise DataError("policy.yaml: expected a YAML mapping")
            payload["policy"] = policy_raw

    if not payload["accounts"]:
        raise DataError("accounts.yaml is required and must contain at least one account")
    if not payload["identities"]:
        raise DataError("identities.yaml is required and must contain at least one identity")

    try:
        return Dataset.model_validate(payload)
    except Exception as exc:  # ValidationError do pydantic ou nosso ValueError
        raise DataError(f"dataset failed validation: {exc}") from exc
