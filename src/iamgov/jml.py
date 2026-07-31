"""Análise de lifecycle Joiner / Mover / Leaver.

O lifecycle compara o que uma identity *deveria* ter, dada a baseline do seu título, com o
que ela *tem*:

* Joiner gap: grupos da baseline que a identity não tem (under-provisioned) ou que tem além
  da baseline (o sinal de mover, em geral acesso arrastado de uma função anterior).
* Privilege creep: entitlements efetivos além do que a baseline do título concede. É o
  acúmulo que a recertification existe para pegar.
* Orphaned access: identities disabled ou terminated que ainda carregam standing access. São
  as falhas de leaver e a limpeza de maior valor.
* Dormant access: identities ativas com acesso mas sem atividade recente.

As baselines e o threshold de dormancy ficam no ``policy.yaml``, para que a run seja
reproduzível e as definições sejam auditáveis em vez de enterradas no código.
"""

from __future__ import annotations

from dataclasses import dataclass

from .access import effective_access, group_closure
from .model import Dataset, IdentityStatus


def _baseline_entitlements(ds: Dataset, group_ids: list[str]) -> set[str]:
    out: set[str] = set()
    for gid in group_ids:
        for reached in group_closure(ds, gid):
            out.update(ds.group(reached).entitlement_ids)
    return out


@dataclass(frozen=True)
class JoinerGap:
    identity_id: str
    identity_name: str
    title: str
    missing_group_ids: tuple[str, ...]
    extra_group_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "identity_id": self.identity_id,
            "identity_name": self.identity_name,
            "title": self.title,
            "missing_group_ids": list(self.missing_group_ids),
            "extra_group_ids": list(self.extra_group_ids),
        }


@dataclass(frozen=True)
class CreepEntitlement:
    entitlement_id: str
    entitlement_name: str
    privilege: str
    account_id: str
    reason: str


@dataclass(frozen=True)
class PrivilegeCreep:
    identity_id: str
    identity_name: str
    title: str
    extra: tuple[CreepEntitlement, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "identity_id": self.identity_id,
            "identity_name": self.identity_name,
            "title": self.title,
            "extra": [
                {
                    "entitlement_id": c.entitlement_id,
                    "entitlement_name": c.entitlement_name,
                    "privilege": c.privilege,
                    "account_id": c.account_id,
                    "reason": c.reason,
                }
                for c in self.extra
            ],
        }


@dataclass(frozen=True)
class OrphanedAccess:
    identity_id: str
    identity_name: str
    status: str
    entitlement_count: int
    group_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "identity_id": self.identity_id,
            "identity_name": self.identity_name,
            "status": self.status,
            "entitlement_count": self.entitlement_count,
            "group_ids": list(self.group_ids),
        }


@dataclass(frozen=True)
class DormantIdentity:
    identity_id: str
    identity_name: str
    last_activity_days: int | None
    entitlement_count: int

    def to_dict(self) -> dict[str, object]:
        return {
            "identity_id": self.identity_id,
            "identity_name": self.identity_name,
            "last_activity_days": self.last_activity_days,
            "entitlement_count": self.entitlement_count,
        }


def joiner_gaps(ds: Dataset) -> list[JoinerGap]:
    gaps: list[JoinerGap] = []
    for identity in ds.identities:
        if identity.status is not IdentityStatus.ACTIVE:
            continue
        baseline = ds.policy.baseline_for(identity.title)
        if baseline is None:
            continue
        held = set(identity.group_ids)
        expected = set(baseline.group_ids)
        missing = tuple(sorted(expected - held))
        extra = tuple(sorted(held - expected))
        if missing or extra:
            gaps.append(
                JoinerGap(
                    identity_id=identity.id,
                    identity_name=identity.name,
                    title=identity.title,
                    missing_group_ids=missing,
                    extra_group_ids=extra,
                )
            )
    return gaps


def privilege_creep(ds: Dataset) -> list[PrivilegeCreep]:
    findings: list[PrivilegeCreep] = []
    for identity in ds.identities:
        if identity.status is not IdentityStatus.ACTIVE:
            continue
        baseline = ds.policy.baseline_for(identity.title)
        if baseline is None:
            continue
        allowed = _baseline_entitlements(ds, baseline.group_ids)
        access = effective_access(ds, identity.id)
        extra_ids = sorted(access.entitlement_ids - allowed)
        if not extra_ids:
            continue
        extra = tuple(
            CreepEntitlement(
                entitlement_id=eid,
                entitlement_name=ds.entitlement(eid).name,
                privilege=ds.entitlement(eid).privilege_level.value,
                account_id=ds.entitlement(eid).account_id,
                reason=access.grant_for(eid).describe(),
            )
            for eid in extra_ids
        )
        findings.append(
            PrivilegeCreep(
                identity_id=identity.id,
                identity_name=identity.name,
                title=identity.title,
                extra=extra,
            )
        )
    return findings


def orphaned_access(ds: Dataset) -> list[OrphanedAccess]:
    findings: list[OrphanedAccess] = []
    for identity in ds.identities:
        if identity.status is IdentityStatus.ACTIVE:
            continue
        access = effective_access(ds, identity.id)
        if access.entitlement_ids or identity.group_ids:
            findings.append(
                OrphanedAccess(
                    identity_id=identity.id,
                    identity_name=identity.name,
                    status=identity.status.value,
                    entitlement_count=len(access.entitlement_ids),
                    group_ids=tuple(identity.group_ids),
                )
            )
    return findings


def is_dormant(ds: Dataset, identity_id: str) -> bool:
    identity = ds.identity(identity_id)
    if identity.status is not IdentityStatus.ACTIVE:
        return False
    days = identity.last_activity_days
    return days is None or days > ds.policy.dormancy_days


def dormant_identities(ds: Dataset) -> list[DormantIdentity]:
    findings: list[DormantIdentity] = []
    for identity in ds.identities:
        if not is_dormant(ds, identity.id):
            continue
        access = effective_access(ds, identity.id)
        if not access.entitlement_ids:
            continue
        findings.append(
            DormantIdentity(
                identity_id=identity.id,
                identity_name=identity.name,
                last_activity_days=identity.last_activity_days,
                entitlement_count=len(access.entitlement_ids),
            )
        )
    return findings
