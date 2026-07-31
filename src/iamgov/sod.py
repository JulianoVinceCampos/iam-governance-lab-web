"""Detecção de Segregation of Duties (SoD).

Uma regra de SoD declara dois baldes de capacidade (``set_a`` e ``set_b``). Uma identity
viola a regra quando seu *standing access efetivo* casa com pelo menos um selector de cada
balde, carregado em pelo menos dois entitlements distintos. Exigir dois entitlements
distintos é o ponto da separação: uma mesma identity não deveria conseguir criar um vendor e
aprovar o pagamento dele, nem fazer deploy em produção e aprovar a própria mudança.

Todo match carrega sua procedência (grant direto ou a cadeia de grupos que o produziu),
porque a remediação difere: grant direto se revoga na identity, herdado se conserta no grupo.
"""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch

from .access import EffectiveAccess, effective_access
from .model import Dataset, Entitlement, PrivilegeLevel, SoDRule, SoDSelector


@dataclass(frozen=True)
class SoDMatch:
    entitlement_id: str
    entitlement_name: str
    account_id: str
    grant_reason: str  # "direct" ou "group via g-a -> g-b"

    def to_dict(self) -> dict[str, str]:
        return {
            "entitlement_id": self.entitlement_id,
            "entitlement_name": self.entitlement_name,
            "account_id": self.account_id,
            "grant_reason": self.grant_reason,
        }


@dataclass(frozen=True)
class SoDViolation:
    rule_id: str
    rule_name: str
    severity: PrivilegeLevel
    identity_id: str
    identity_name: str
    side_a: tuple[SoDMatch, ...]
    side_b: tuple[SoDMatch, ...]

    @property
    def inherited_only(self) -> bool:
        """True quando nenhum lado do conflito veio por grant direto (conserto no grupo)."""
        return all(m.grant_reason != "direct" for m in (*self.side_a, *self.side_b))

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "identity_id": self.identity_id,
            "identity_name": self.identity_name,
            "side_a": [m.to_dict() for m in self.side_a],
            "side_b": [m.to_dict() for m in self.side_b],
            "inherited_only": self.inherited_only,
        }


def _entitlement_matches(entitlement: Entitlement, selector: SoDSelector) -> bool:
    if selector.match == "entitlement":
        return entitlement.id in selector.values
    if selector.match == "action":
        return any(
            fnmatch(action, pat)
            for action in entitlement.actions
            for pat in selector.values
        )
    if selector.match == "tag":
        return any(tag in selector.values for tag in entitlement.tags)
    return False


def _matches_for_side(
    ds: Dataset,
    access: EffectiveAccess,
    selectors: list[SoDSelector],
) -> list[SoDMatch]:
    hits: dict[str, SoDMatch] = {}
    for eid in sorted(access.entitlement_ids):
        entitlement = ds.entitlement(eid)
        if any(_entitlement_matches(entitlement, sel) for sel in selectors):
            grant = access.grant_for(eid)
            hits[eid] = SoDMatch(
                entitlement_id=eid,
                entitlement_name=entitlement.name,
                account_id=entitlement.account_id,
                grant_reason=grant.describe(),
            )
    return list(hits.values())


def evaluate_rule(ds: Dataset, rule: SoDRule, access: EffectiveAccess) -> SoDViolation | None:
    side_a = _matches_for_side(ds, access, rule.set_a)
    side_b = _matches_for_side(ds, access, rule.set_b)
    if not side_a or not side_b:
        return None
    # Exige separação em dois entitlements distintos.
    distinct = {m.entitlement_id for m in side_a} | {m.entitlement_id for m in side_b}
    if len(distinct) < 2:
        return None
    identity = ds.identity(access.identity_id)
    return SoDViolation(
        rule_id=rule.id,
        rule_name=rule.name,
        severity=rule.severity,
        identity_id=identity.id,
        identity_name=identity.name,
        side_a=tuple(side_a),
        side_b=tuple(side_b),
    )


def find_violations(ds: Dataset) -> list[SoDViolation]:
    """Avalia cada regra de SoD contra o standing access de cada identity."""
    violations: list[SoDViolation] = []
    for identity in ds.identities:
        access = effective_access(ds, identity.id)
        for rule in ds.sod_rules:
            found = evaluate_rule(ds, rule, access)
            if found is not None:
                violations.append(found)
    # Ordem estável: severidade primeiro (critical -> low), depois identity, depois rule.
    order = {level: i for i, level in enumerate(reversed(list(PrivilegeLevel)))}
    violations.sort(key=lambda v: (order[v.severity], v.identity_id, v.rule_id))
    return violations


def violations_for_identity(ds: Dataset, identity_id: str) -> list[SoDViolation]:
    access = effective_access(ds, identity_id)
    return [v for r in ds.sod_rules if (v := evaluate_rule(ds, r, access)) is not None]
