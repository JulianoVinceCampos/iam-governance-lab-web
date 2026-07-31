"""Persistência em banco do dataset editável do lab.

Uma tabela por kind de entidade, com campos escalares em coluna e campos de lista/nested em
coluna JSON (portável entre SQLite e PostgreSQL). O dataset inteiro é gravado como um único
snapshot validado a cada mudança (``seed``), então o banco é sempre um espelho fiel de um
dataset que passou na validação de integridade, nunca uma edição meio aplicada.

O engine padrão é um arquivo SQLite, que não precisa de servidor e vive num volume Docker.
Aponte ``DATABASE_URL`` para PostgreSQL para rodar o mesmo schema lá.
"""

from __future__ import annotations

import os
from typing import Any

from sqlalchemy import JSON, Integer, String, create_engine, delete, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

DEFAULT_DB_URL = "sqlite:///./iamgov.db"


def database_url() -> str:
    """Resolve a URL do banco.

    Prioridade: DATABASE_URL (qualquer URL SQLAlchemy, ex. PostgreSQL) vence. Senão, se
    IAMGOV_DB_PATH aponta para um arquivo SQLite (o padrão do container), usa ele. Por fim,
    cai para um arquivo SQLite no diretório de trabalho.
    """
    explicit = os.environ.get("DATABASE_URL")
    if explicit:
        return explicit
    sqlite_path = os.environ.get("IAMGOV_DB_PATH")
    if sqlite_path:
        return f"sqlite:///{sqlite_path}"
    return DEFAULT_DB_URL


class Base(DeclarativeBase):
    pass


class AccountRow(Base):
    __tablename__ = "accounts"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, default="")
    environment: Mapped[str] = mapped_column(String, default="production")


class EntitlementRow(Base):
    __tablename__ = "entitlements"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    account_id: Mapped[str] = mapped_column(String)
    name: Mapped[str] = mapped_column(String, default="")
    actions: Mapped[list[Any]] = mapped_column(JSON, default=list)
    resource: Mapped[str] = mapped_column(String, default="*")
    privilege_level: Mapped[str] = mapped_column(String, default="low")
    assume_targets: Mapped[list[Any]] = mapped_column(JSON, default=list)
    tags: Mapped[list[Any]] = mapped_column(JSON, default=list)
    description: Mapped[str] = mapped_column(String, default="")


class GroupRow(Base):
    __tablename__ = "groups"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    account_id: Mapped[str] = mapped_column(String)
    name: Mapped[str] = mapped_column(String, default="")
    entitlement_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    member_of: Mapped[list[Any]] = mapped_column(JSON, default=list)
    description: Mapped[str] = mapped_column(String, default="")


class RoleRow(Base):
    __tablename__ = "roles"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    account_id: Mapped[str] = mapped_column(String)
    name: Mapped[str] = mapped_column(String, default="")
    entitlement_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    trusts: Mapped[list[Any]] = mapped_column(JSON, default=list)
    description: Mapped[str] = mapped_column(String, default="")


class IdentityRow(Base):
    __tablename__ = "identities"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, default="")
    type: Mapped[str] = mapped_column(String, default="human")
    department: Mapped[str] = mapped_column(String, default="")
    title: Mapped[str] = mapped_column(String, default="")
    home_account_id: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String, default="active")
    manager_id: Mapped[str | None] = mapped_column(String, nullable=True)
    hire_date: Mapped[str | None] = mapped_column(String, nullable=True)
    last_activity_days: Mapped[int | None] = mapped_column(Integer, nullable=True)
    entitlement_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    group_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)


class SodRuleRow(Base):
    __tablename__ = "sod_rules"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, default="")
    severity: Mapped[str] = mapped_column(String, default="high")
    set_a: Mapped[list[Any]] = mapped_column(JSON, default=list)
    set_b: Mapped[list[Any]] = mapped_column(JSON, default=list)
    rationale: Mapped[str] = mapped_column(String, default="")


class PolicyRow(Base):
    __tablename__ = "policy"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    dormancy_days: Mapped[int] = mapped_column(Integer, default=90)
    baselines: Mapped[list[Any]] = mapped_column(JSON, default=list)


_KIND_ROWS: dict[str, type[Any]] = {
    "accounts": AccountRow,
    "entitlements": EntitlementRow,
    "groups": GroupRow,
    "roles": RoleRow,
    "identities": IdentityRow,
    "sod_rules": SodRuleRow,
}


def _row_to_dict(row: Any, drop: tuple[str, ...] = ()) -> dict[str, Any]:
    return {c.name: getattr(row, c.name) for c in row.__table__.columns if c.name not in drop}


def _only_columns(row_cls: type[Any], obj: dict[str, Any]) -> dict[str, Any]:
    cols = {c.name for c in row_cls.__table__.columns}
    return {k: v for k, v in obj.items() if k in cols}


class Database:
    """Wrapper fino de persistência. Toda escrita passa por :meth:`seed` (snapshot inteiro)."""

    def __init__(self, url: str | None = None) -> None:
        url = url or database_url()
        connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
        self.engine = create_engine(url, connect_args=connect_args, future=True)
        Base.metadata.create_all(self.engine)
        self._Session = sessionmaker(self.engine, expire_on_commit=False)

    def is_empty(self) -> bool:
        with self._Session() as s:
            return s.scalar(select(AccountRow).limit(1)) is None

    def to_payload(self) -> dict[str, Any]:
        with self._Session() as s:
            payload: dict[str, Any] = {}
            for kind, row_cls in _KIND_ROWS.items():
                payload[kind] = [_row_to_dict(r) for r in s.scalars(select(row_cls)).all()]
            pol = s.get(PolicyRow, 1)
            payload["policy"] = _row_to_dict(pol, drop=("id",)) if pol else {}
            return payload

    def seed(self, payload: dict[str, Any]) -> None:
        """Substitui o dataset inteiro por ``payload`` numa única transação."""
        with self._Session() as s:
            for kind, row_cls in _KIND_ROWS.items():
                s.execute(delete(row_cls))
                for obj in payload.get(kind, []):
                    s.add(row_cls(**_only_columns(row_cls, obj)))
            s.execute(delete(PolicyRow))
            policy = payload.get("policy") or {}
            s.add(
                PolicyRow(
                    id=1,
                    dormancy_days=policy.get("dormancy_days", 90),
                    baselines=policy.get("baselines", []),
                )
            )
            s.commit()
