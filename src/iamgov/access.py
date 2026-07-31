"""Resolução de standing access efetivo.

"Standing access" é o que uma identity carrega sem assumir nada: seus entitlements diretos
mais todo entitlement carregado por um grupo do qual ela participa, seguindo a membership
aninhada até o fecho transitivo.

Cada entitlement resolvido guarda sua procedência (um :class:`Grant`), para que os reports a
jusante possam dizer *por que* uma identity tem algo: por grant direto, ou herdado por uma
cadeia nomeada de grupos. É essa procedência que torna um finding de SoD acionável em vez de
só alarmante.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .model import Dataset, GrantSource


@dataclass(frozen=True)
class Grant:
    """Uma razão pela qual uma identity carrega um entitlement."""

    entitlement_id: str
    source: GrantSource
    # Para grants de GROUP: a cadeia de membership do grupo atribuído direto até o grupo que de
    # fato carrega o entitlement. Vazia para grants DIRECT.
    group_path: tuple[str, ...] = ()

    def describe(self) -> str:
        if self.source is GrantSource.DIRECT:
            return "direct"
        return "group via " + " -> ".join(self.group_path)


@dataclass(frozen=True)
class EffectiveAccess:
    identity_id: str
    grants: dict[str, list[Grant]] = field(default_factory=dict)

    @property
    def entitlement_ids(self) -> set[str]:
        return set(self.grants)

    def grant_for(self, entitlement_id: str) -> Grant:
        """Devolve o grant mais direto de um entitlement (direto vence herdado)."""
        options = self.grants[entitlement_id]
        for g in options:
            if g.source is GrantSource.DIRECT:
                return g
        return min(options, key=lambda g: len(g.group_path))


def group_closure(ds: Dataset, group_id: str) -> dict[str, tuple[str, ...]]:
    """Todos os grupos alcançáveis para cima a partir de ``group_id`` via ``member_of``.

    Devolve um mapa de group-id-alcançado -> caminho de membership (começando em ``group_id``).
    Breadth-first, então os caminhos são as cadeias de membership mais curtas. Ciclos de nesting
    são impossíveis aqui porque o validator do dataset os rejeita no load.
    """
    result: dict[str, tuple[str, ...]] = {group_id: (group_id,)}
    frontier: list[str] = [group_id]
    while frontier:
        current = frontier.pop(0)
        path = result[current]
        for parent in ds.group(current).member_of:
            if parent not in result:
                result[parent] = (*path, parent)
                frontier.append(parent)
    return result


def effective_access(ds: Dataset, identity_id: str) -> EffectiveAccess:
    """Resolve o standing access de uma identity com procedência completa."""
    identity = ds.identity(identity_id)
    grants: dict[str, list[Grant]] = {}

    for eid in identity.entitlement_ids:
        grants.setdefault(eid, []).append(Grant(eid, GrantSource.DIRECT))

    for assigned in identity.group_ids:
        for gid, path in group_closure(ds, assigned).items():
            for eid in ds.group(gid).entitlement_ids:
                grants.setdefault(eid, []).append(
                    Grant(eid, GrantSource.GROUP, group_path=path)
                )

    return EffectiveAccess(identity_id=identity_id, grants=grants)


def effective_entitlement_ids(ds: Dataset, identity_id: str) -> set[str]:
    """Conveniência: só o conjunto de entitlement ids que a identity carrega (standing)."""
    return effective_access(ds, identity_id).entitlement_ids
