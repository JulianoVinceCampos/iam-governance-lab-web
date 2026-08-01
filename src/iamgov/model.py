"""Modelo de domínio tipado do lab de governança.

O modelo é de propósito próximo de como uma ferramenta de IGA raciocina sobre acesso, não
de como um IdP específico guarda:

    Account        uma fronteira de isolamento (uma conta AWS, um tenant, uma org unit)
    Entitlement    um grant atômico: um conjunto de actions sobre um resource, num privilege level
    Group          um agrupamento RBAC que carrega entitlements e pode aninhar em outros
    Role           um principal *assumível* que carrega entitlements e tem uma trust policy
    Identity       um principal humano ou service com grants diretos e memberships de grupo

A distinção entre Group e Role importa para as duas análises:

* Standing access (usado por SoD e recertification) = entitlements diretos mais o fecho
  transitivo dos entitlements de grupo. Roles NÃO são standing access, porque você não
  "tem" um role até assumi-lo.
* Reachable access (usado por privilege reachability) = standing access mais todo
  entitlement obtível seguindo as arestas de assume-role até o fixpoint.

Manter as duas noções separadas é deliberado; ver docs/reachability.md.
"""

from __future__ import annotations

from datetime import date
from enum import StrEnum
from typing import Protocol, TypeVar

from pydantic import BaseModel, ConfigDict, Field, model_validator


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Environment(StrEnum):
    MANAGEMENT = "management"
    PRODUCTION = "production"
    DEVELOPMENT = "development"
    SECURITY = "security"


class PrivilegeLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> int:
        return {"low": 5, "medium": 15, "high": 30, "critical": 45}[self.value]


class IdentityType(StrEnum):
    HUMAN = "human"
    SERVICE = "service"


class IdentityStatus(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"
    TERMINATED = "terminated"


class GrantSource(StrEnum):
    """Como uma identity acabou carregando um entitlement.

    O lab modela os dois mecanismos de autorização que convivem numa organização real:

    * ``GROUP`` é RBAC (role-based): o acesso vem de participar de um grupo, direta ou por
      nesting. O grant é explícito e some quando a identity sai do grupo.
    * ``ABAC`` é attribute-based: o acesso vem de a identity *casar um atributo* (department,
      title, type, status), sem ninguém a ter colocado num grupo. O grant aparece e some
      sozinho quando o atributo muda, que é a força e o risco do ABAC.

    ``DIRECT`` é um grant pregado na própria identity, e ``ROLE_ASSUMPTION`` é acesso obtido
    assumindo um role (tratado só na reachability, não é standing access).
    """

    DIRECT = "direct"
    GROUP = "group"
    ABAC = "abac"
    ROLE_ASSUMPTION = "role_assumption"


class Account(_Base):
    id: str
    name: str
    environment: Environment


class Entitlement(_Base):
    id: str
    account_id: str
    name: str
    actions: list[str] = Field(min_length=1)
    resource: str = "*"
    privilege_level: PrivilegeLevel = PrivilegeLevel.LOW
    # Ids dos roles que este entitlement permite ao holder assumir (modela sts:AssumeRole).
    assume_targets: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    description: str = ""


class Group(_Base):
    """Agrupamento RBAC. Membros herdam seus entitlements e os dos grupos aninhados."""

    id: str
    account_id: str
    name: str
    entitlement_ids: list[str] = Field(default_factory=list)
    member_of: list[str] = Field(default_factory=list)
    description: str = ""


class Role(_Base):
    """Um principal assumível (estilo STS). Carrega entitlements depois de assumido.

    ``trusts`` lista os patterns de principal autorizados a assumir o role. O valor ``"*"``
    modela uma trust policy wildcard, que o engine de reachability trata como alcançável por
    qualquer principal e marca explicitamente.
    """

    id: str
    account_id: str
    name: str
    entitlement_ids: list[str] = Field(default_factory=list)
    trusts: list[str] = Field(default_factory=list)
    description: str = ""


class Identity(_Base):
    id: str
    name: str
    type: IdentityType
    department: str
    title: str
    home_account_id: str
    status: IdentityStatus = IdentityStatus.ACTIVE
    manager_id: str | None = None
    hire_date: date | None = None
    # Dias desde a última atividade observada; usado no score de dormancy. None = nunca vista.
    last_activity_days: int | None = None
    entitlement_ids: list[str] = Field(default_factory=list)
    group_ids: list[str] = Field(default_factory=list)


class SoDSelector(_Base):
    """Casa um conjunto de entitlements por id, por glob de action ou por tag."""

    match: str = Field(pattern="^(entitlement|action|tag)$")
    values: list[str] = Field(min_length=1)


class SoDRule(_Base):
    """Uma toxic combination. Uma identity viola a regra quando seu standing access efetivo
    casa com pelo menos um selector de ``set_a`` E um de ``set_b``.
    """

    id: str
    name: str
    severity: PrivilegeLevel = PrivilegeLevel.HIGH
    set_a: list[SoDSelector] = Field(min_length=1)
    set_b: list[SoDSelector] = Field(min_length=1)
    rationale: str = ""


class AbacCondition(_Base):
    """Casa uma identity por um de seus atributos.

    ``attribute`` é o nome de um atributo escalar da identity; ``values`` é o conjunto de
    valores aceitos. A condição casa quando o valor do atributo da identity está em ``values``.
    Só atributos estáveis e de baixo risco de digitação são permitidos, para uma regra de ABAC
    nunca depender de um campo que o editor não expõe.
    """

    attribute: str = Field(pattern="^(department|title|type|status|home_account_id)$")
    values: list[str] = Field(min_length=1)


class AbacRule(_Base):
    """Regra de ABAC: concede entitlements a toda identity cujos atributos casam.

    Todas as condições precisam casar (semântica E). Diferente de um grupo RBAC, ninguém
    atribui a regra a uma identity: ela se aplica sozinha a quem tiver o atributo, e deixa de
    valer quando o atributo muda. É o standing access que aparece sem um clique de provisioning.
    """

    id: str
    name: str
    conditions: list[AbacCondition] = Field(min_length=1)
    entitlement_ids: list[str] = Field(min_length=1)
    description: str = ""


class BaselinePolicy(_Base):
    """Baseline de joiner: os group ids que um título deveria ter, nem mais nem menos."""

    title: str
    group_ids: list[str] = Field(default_factory=list)


class Policy(_Base):
    """Tunables de governança guardados em dados, não hardcoded, para runs reproduzíveis."""

    dormancy_days: int = 90
    baselines: list[BaselinePolicy] = Field(default_factory=list)

    def baseline_for(self, title: str) -> BaselinePolicy | None:
        for b in self.baselines:
            if b.title == title:
                return b
        return None


class Dataset(_Base):
    """Agregado raiz. Montado e checado por :func:`iamgov.loader.load_dataset`."""

    accounts: list[Account]
    entitlements: list[Entitlement]
    groups: list[Group]
    roles: list[Role]
    identities: list[Identity]
    sod_rules: list[SoDRule] = Field(default_factory=list)
    abac_rules: list[AbacRule] = Field(default_factory=list)
    policy: Policy = Field(default_factory=Policy)

    # --- índices -------------------------------------------------------------
    def account(self, account_id: str) -> Account:
        return _by_id(self.accounts, account_id, "account")

    def entitlement(self, entitlement_id: str) -> Entitlement:
        return _by_id(self.entitlements, entitlement_id, "entitlement")

    def group(self, group_id: str) -> Group:
        return _by_id(self.groups, group_id, "group")

    def role(self, role_id: str) -> Role:
        return _by_id(self.roles, role_id, "role")

    def identity(self, identity_id: str) -> Identity:
        return _by_id(self.identities, identity_id, "identity")

    def abac_rule(self, rule_id: str) -> AbacRule:
        return _by_id(self.abac_rules, rule_id, "abac_rule")

    @property
    def account_of(self) -> dict[str, str]:
        """Mapeia cada id de entitlement/group/role para o id da conta dona."""
        out: dict[str, str] = {}
        for e in self.entitlements:
            out[e.id] = e.account_id
        for g in self.groups:
            out[g.id] = g.account_id
        for r in self.roles:
            out[r.id] = r.account_id
        return out

    # --- integridade referencial --------------------------------------------
    @model_validator(mode="after")
    def _check_integrity(self) -> Dataset:
        account_ids = {a.id for a in self.accounts}
        entitlement_ids = {e.id for e in self.entitlements}
        group_ids = {g.id for g in self.groups}
        role_ids = {r.id for r in self.roles}

        _require_unique([a.id for a in self.accounts], "account")
        _require_unique([e.id for e in self.entitlements], "entitlement")
        _require_unique([g.id for g in self.groups], "group")
        _require_unique([r.id for r in self.roles], "role")
        _require_unique([i.id for i in self.identities], "identity")
        _require_unique([r.id for r in self.sod_rules], "sod_rule")
        _require_unique([r.id for r in self.abac_rules], "abac_rule")

        for e in self.entitlements:
            _require(
                e.account_id in account_ids,
                f"entitlement {e.id}: unknown account {e.account_id}",
            )
            for t in e.assume_targets:
                _require(t in role_ids, f"entitlement {e.id}: assume_target {t} is not a role")
        for g in self.groups:
            _require(g.account_id in account_ids, f"group {g.id}: unknown account {g.account_id}")
            for eid in g.entitlement_ids:
                _require(eid in entitlement_ids, f"group {g.id}: unknown entitlement {eid}")
            for parent in g.member_of:
                _require(parent in group_ids, f"group {g.id}: unknown parent group {parent}")
        for r in self.roles:
            _require(r.account_id in account_ids, f"role {r.id}: unknown account {r.account_id}")
            for eid in r.entitlement_ids:
                _require(eid in entitlement_ids, f"role {r.id}: unknown entitlement {eid}")
        for i in self.identities:
            _require(
                i.home_account_id in account_ids,
                f"identity {i.id}: unknown account {i.home_account_id}",
            )
            if i.manager_id is not None:
                _require(
                    i.manager_id in {x.id for x in self.identities},
                    f"identity {i.id}: unknown manager {i.manager_id}",
                )
            for eid in i.entitlement_ids:
                _require(eid in entitlement_ids, f"identity {i.id}: unknown entitlement {eid}")
            for gid in i.group_ids:
                _require(gid in group_ids, f"identity {i.id}: unknown group {gid}")

        for rule in self.abac_rules:
            for eid in rule.entitlement_ids:
                _require(
                    eid in entitlement_ids,
                    f"abac_rule {rule.id}: unknown entitlement {eid}",
                )

        _check_no_group_cycles(self.groups)
        for b in self.policy.baselines:
            for gid in b.group_ids:
                _require(gid in group_ids, f"baseline {b.title}: unknown group {gid}")
        return self


# --- helpers -----------------------------------------------------------------
class _HasId(Protocol):
    @property
    def id(self) -> str: ...


T = TypeVar("T", bound=_HasId)


def _by_id(items: list[T], item_id: str, kind: str) -> T:
    for it in items:
        if it.id == item_id:
            return it
    raise KeyError(f"{kind} {item_id!r} not found")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _require_unique(ids: list[str], kind: str) -> None:
    seen: set[str] = set()
    for i in ids:
        if i in seen:
            raise ValueError(f"duplicate {kind} id: {i}")
        seen.add(i)


def _check_no_group_cycles(groups: list[Group]) -> None:
    parents = {g.id: list(g.member_of) for g in groups}
    color: dict[str, int] = {}  # 0=nao visto, 1=em progresso, 2=concluido

    def visit(node: str, trail: list[str]) -> None:
        color[node] = 1
        for parent in parents.get(node, []):
            if color.get(parent, 0) == 1:
                cycle = " -> ".join([*trail, node, parent])
                raise ValueError(f"group nesting cycle detected: {cycle}")
            if color.get(parent, 0) == 0:
                visit(parent, [*trail, node])
        color[node] = 2

    for g in groups:
        if color.get(g.id, 0) == 0:
            visit(g.id, [])
