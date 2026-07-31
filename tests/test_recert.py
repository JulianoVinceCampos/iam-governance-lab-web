"""O risk score é uma fórmula documentada; estes testes travam cada termo e threshold."""

from __future__ import annotations

from iamgov.model import Dataset, Entitlement, PrivilegeLevel
from iamgov.recert import (
    RiskFactors,
    bucket_for,
    build_campaigns,
    recommendation_for,
    revocation_worklist,
    score_entitlement,
)


def _ent(level: PrivilegeLevel) -> Entitlement:
    return Entitlement(id="e", account_id="a", name="E", actions=["x:*"], privilege_level=level)


def test_base_weights() -> None:
    none = RiskFactors(in_sod=False, dormant=False, enables_escalation=False, leaver=False)
    assert score_entitlement(_ent(PrivilegeLevel.LOW), none) == 5
    assert score_entitlement(_ent(PrivilegeLevel.MEDIUM), none) == 15
    assert score_entitlement(_ent(PrivilegeLevel.HIGH), none) == 30
    assert score_entitlement(_ent(PrivilegeLevel.CRITICAL), none) == 45


def test_additive_factors_and_clamp() -> None:
    loaded = RiskFactors(in_sod=True, dormant=True, enables_escalation=True, leaver=False)
    # critical 45 + 30 + 20 + 15 = 110, limitado a 100.
    assert score_entitlement(_ent(PrivilegeLevel.CRITICAL), loaded) == 100
    # medium 15 + 30 (sod) = 45.
    only_sod = RiskFactors(in_sod=True, dormant=False, enables_escalation=False, leaver=False)
    assert score_entitlement(_ent(PrivilegeLevel.MEDIUM), only_sod) == 45


def test_buckets() -> None:
    assert bucket_for(10) == "low"
    assert bucket_for(25) == "medium"
    assert bucket_for(50) == "high"
    assert bucket_for(75) == "critical"


def test_recommendation_leaver_always_revokes() -> None:
    assert recommendation_for(5, leaver=True) == "revoke"
    assert recommendation_for(5, leaver=False) == "keep"
    assert recommendation_for(45, leaver=False) == "review"
    assert recommendation_for(60, leaver=False) == "revoke"


def test_worklist_and_campaigns_present(main_ds: Dataset) -> None:
    worklist = revocation_worklist(main_ds)
    assert worklist, "esperava alguma revogação no dataset semeado"
    assert worklist == sorted(worklist, key=lambda i: (-i.score, i.identity_id, i.entitlement_id))
    # Leavers precisam aparecer com recomendação de revoke.
    assert any(i.identity_id == "id-laura" for i in worklist)
    campaigns = build_campaigns(main_ds)
    assert campaigns
    assert all(c.reviewees for c in campaigns)
