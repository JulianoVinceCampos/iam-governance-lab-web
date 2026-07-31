"""Recertification de acesso com um risk score explícito e auditável.

Recertification transforma "aqui está todo o acesso" em "aqui está o acesso que um manager
precisa revisar, pior primeiro, com uma recomendação". O score é determinístico e cada termo
é documentado, porque um número de risco que ninguém sabe explicar é pior que nenhum número.

Score de uma linha (identity, entitlement), limitado a 0..100:

    base                 peso do privilege       low 5, medium 15, high 30, critical 45
    + 30                 o par está numa violação de SoD
    + 20                 a identity está dormante (ver policy.dormancy_days)
    + 15                 o entitlement habilita assunção de role (superfície de escalonamento)

Buckets e a recomendação resultante:

    score < 25           low       -> keep
    25 <= score < 50     medium    -> review
    50 <= score < 75     high      -> revoke
    score >= 75          critical  -> revoke

Uma identity disabled ou terminated que ainda carrega o entitlement é sempre ``revoke``,
qualquer que seja o score: standing access de leaver é limpeza, não julgamento.
"""

from __future__ import annotations

from dataclasses import dataclass

from .access import effective_access
from .jml import is_dormant
from .model import Dataset, Entitlement, IdentityStatus
from .reachability import ASSUME_EDGE, build_graph
from .sod import find_violations

SOD_WEIGHT = 30
DORMANT_WEIGHT = 20
ESCALATION_WEIGHT = 15


@dataclass(frozen=True)
class RiskFactors:
    in_sod: bool
    dormant: bool
    enables_escalation: bool
    leaver: bool


def score_entitlement(entitlement: Entitlement, factors: RiskFactors) -> int:
    score = entitlement.privilege_level.weight
    if factors.in_sod:
        score += SOD_WEIGHT
    if factors.dormant:
        score += DORMANT_WEIGHT
    if factors.enables_escalation:
        score += ESCALATION_WEIGHT
    return min(score, 100)


def bucket_for(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def recommendation_for(score: int, leaver: bool) -> str:
    if leaver:
        return "revoke"
    bucket = bucket_for(score)
    if bucket in ("high", "critical"):
        return "revoke"
    if bucket == "medium":
        return "review"
    return "keep"


@dataclass(frozen=True)
class AccessLineItem:
    identity_id: str
    entitlement_id: str
    entitlement_name: str
    account_id: str
    privilege: str
    grant_reason: str
    in_sod: bool
    dormant: bool
    enables_escalation: bool
    score: int
    bucket: str
    recommendation: str

    def to_dict(self) -> dict[str, object]:
        return {
            "identity_id": self.identity_id,
            "entitlement_id": self.entitlement_id,
            "entitlement_name": self.entitlement_name,
            "account_id": self.account_id,
            "privilege": self.privilege,
            "grant_reason": self.grant_reason,
            "in_sod": self.in_sod,
            "dormant": self.dormant,
            "enables_escalation": self.enables_escalation,
            "score": self.score,
            "bucket": self.bucket,
            "recommendation": self.recommendation,
        }


@dataclass(frozen=True)
class RevieweeAccess:
    identity_id: str
    identity_name: str
    status: str
    items: tuple[AccessLineItem, ...]

    @property
    def max_score(self) -> int:
        return max((i.score for i in self.items), default=0)

    def to_dict(self) -> dict[str, object]:
        return {
            "identity_id": self.identity_id,
            "identity_name": self.identity_name,
            "status": self.status,
            "max_score": self.max_score,
            "items": [i.to_dict() for i in self.items],
        }


@dataclass(frozen=True)
class Campaign:
    reviewer_id: str
    reviewer_name: str
    reviewees: tuple[RevieweeAccess, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "reviewer_id": self.reviewer_id,
            "reviewer_name": self.reviewer_name,
            "reviewees": [r.to_dict() for r in self.reviewees],
        }


def _sod_pairs(ds: Dataset) -> set[tuple[str, str]]:
    """Conjunto de (identity_id, entitlement_id) que participam de alguma violação de SoD."""
    pairs: set[tuple[str, str]] = set()
    for v in find_violations(ds):
        for m in (*v.side_a, *v.side_b):
            pairs.add((v.identity_id, m.entitlement_id))
    return pairs


def _escalation_entitlements(ds: Dataset) -> set[str]:
    """Entitlements que têm uma aresta de assume viva (habilitam assunção de role)."""
    g = build_graph(ds)
    out: set[str] = set()
    for u, _v, a in g.edges(data=True):
        if a["kind"] == ASSUME_EDGE and g.nodes[u]["kind"] == "entitlement":
            out.add(g.nodes[u]["ref"])
    return out


def _line_items(
    ds: Dataset,
    identity_id: str,
    sod_pairs: set[tuple[str, str]],
    escalation: set[str],
) -> list[AccessLineItem]:
    identity = ds.identity(identity_id)
    access = effective_access(ds, identity_id)
    dormant = is_dormant(ds, identity_id)
    leaver = identity.status is not IdentityStatus.ACTIVE
    items: list[AccessLineItem] = []
    for eid in sorted(access.entitlement_ids):
        entitlement = ds.entitlement(eid)
        factors = RiskFactors(
            in_sod=(identity_id, eid) in sod_pairs,
            dormant=dormant,
            enables_escalation=eid in escalation,
            leaver=leaver,
        )
        score = score_entitlement(entitlement, factors)
        items.append(
            AccessLineItem(
                identity_id=identity_id,
                entitlement_id=eid,
                entitlement_name=entitlement.name,
                account_id=entitlement.account_id,
                privilege=entitlement.privilege_level.value,
                grant_reason=access.grant_for(eid).describe(),
                in_sod=factors.in_sod,
                dormant=factors.dormant,
                enables_escalation=factors.enables_escalation,
                score=score,
                bucket=bucket_for(score),
                recommendation=recommendation_for(score, leaver),
            )
        )
    items.sort(key=lambda i: (-i.score, i.entitlement_id))
    return items


def build_campaigns(ds: Dataset) -> list[Campaign]:
    """Agrupa o acesso de cada identity sob seu manager (o reviewer)."""
    sod_pairs = _sod_pairs(ds)
    escalation = _escalation_entitlements(ds)

    reviewees_by_reviewer: dict[str, list[RevieweeAccess]] = {}
    for identity in ds.identities:
        items = _line_items(ds, identity.id, sod_pairs, escalation)
        if not items:
            continue
        reviewer = identity.manager_id or "unassigned"
        reviewees_by_reviewer.setdefault(reviewer, []).append(
            RevieweeAccess(
                identity_id=identity.id,
                identity_name=identity.name,
                status=identity.status.value,
                items=tuple(items),
            )
        )

    campaigns: list[Campaign] = []
    for reviewer_id, reviewees in reviewees_by_reviewer.items():
        if reviewer_id == "unassigned":
            reviewer_name = "Unassigned (no manager)"
        else:
            reviewer_name = ds.identity(reviewer_id).name
        reviewees.sort(key=lambda r: (-r.max_score, r.identity_id))
        campaigns.append(
            Campaign(
                reviewer_id=reviewer_id,
                reviewer_name=reviewer_name,
                reviewees=tuple(reviewees),
            )
        )
    campaigns.sort(
        key=lambda c: (-max((r.max_score for r in c.reviewees), default=0), c.reviewer_id)
    )
    return campaigns


def revocation_worklist(ds: Dataset) -> list[AccessLineItem]:
    """Lista plana de toda linha recomendada para revogação, pior primeiro."""
    sod_pairs = _sod_pairs(ds)
    escalation = _escalation_entitlements(ds)
    out: list[AccessLineItem] = []
    for identity in ds.identities:
        for item in _line_items(ds, identity.id, sod_pairs, escalation):
            if item.recommendation == "revoke":
                out.append(item)
    out.sort(key=lambda i: (-i.score, i.identity_id, i.entitlement_id))
    return out
