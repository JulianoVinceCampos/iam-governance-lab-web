"""Report agregado: compõe todos os engines num documento JSON e num render Markdown.

Este módulo é pura agregação. Ele lê o dataset e as saídas dos engines e produz estruturas
serializáveis; nunca escreve de volta na fonte. Gravar arquivo é papel de quem chama (comando
``report`` da CLI), e vai para ``out/``, que é git-ignored.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from datetime import UTC, datetime

from .jml import dormant_identities, joiner_gaps, orphaned_access, privilege_creep
from .model import Dataset, IdentityStatus, PrivilegeLevel
from .reachability import PathStep, escalation_paths, reachability_report
from .recert import build_campaigns, revocation_worklist
from .sod import find_violations


def headline_metrics(ds: Dataset) -> dict[str, object]:
    """Números de resumo, rápidos o bastante para os cards do dashboard e a CLI."""
    violations = find_violations(ds)
    escalations = escalation_paths(ds)
    status_counts = Counter(i.status.value for i in ds.identities)
    sev_counts = Counter(v.severity.value for v in violations)
    by_severity = {level.value: sev_counts.get(level.value, 0) for level in PrivilegeLevel}

    return {
        "accounts": len(ds.accounts),
        "identities": {
            "total": len(ds.identities),
            "active": status_counts.get(IdentityStatus.ACTIVE.value, 0),
            "disabled": status_counts.get(IdentityStatus.DISABLED.value, 0),
            "terminated": status_counts.get(IdentityStatus.TERMINATED.value, 0),
        },
        "entitlements": len(ds.entitlements),
        "groups": len(ds.groups),
        "roles": len(ds.roles),
        "sod": {"total": len(violations), "by_severity": by_severity},
        "escalation": {
            "paths": len(escalations),
            "cross_account": sum(1 for p in escalations if p.crosses_account),
        },
        "jml": {
            "privilege_creep": len(privilege_creep(ds)),
            "joiner_gaps": len(joiner_gaps(ds)),
            "orphaned": len(orphaned_access(ds)),
            "dormant": len(dormant_identities(ds)),
        },
        "recert": {"revocations_recommended": len(revocation_worklist(ds))},
    }


def build_report(ds: Dataset) -> dict[str, object]:
    """O report de governança completo, legível por máquina."""
    return {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "metrics": headline_metrics(ds),
        "sod_violations": [v.to_dict() for v in find_violations(ds)],
        "reachability": [t.to_dict() for t in reachability_report(ds)],
        "escalation_paths": [p.to_dict() for p in escalation_paths(ds)],
        "jml": {
            "joiner_gaps": [g.to_dict() for g in joiner_gaps(ds)],
            "privilege_creep": [c.to_dict() for c in privilege_creep(ds)],
            "orphaned_access": [o.to_dict() for o in orphaned_access(ds)],
            "dormant": [d.to_dict() for d in dormant_identities(ds)],
        },
        "recertification": {
            "campaigns": [c.to_dict() for c in build_campaigns(ds)],
            "revocation_worklist": [i.to_dict() for i in revocation_worklist(ds)],
        },
    }


def _render_path(steps: Sequence[PathStep]) -> str:
    parts: list[str] = []
    for s in steps:
        if s.edge_from_prev:
            parts.append(f" --[{s.edge_from_prev}]--> ")
        parts.append(f"{s.label} ({s.account})")
    return "".join(parts)


def render_markdown(ds: Dataset) -> str:
    """Markdown legível, bom para um comentário de PR ou um anexo de auditoria.

    Construído direto das saídas tipadas dos engines, para se manter honesto: o que a API
    devolve e o que isto renderiza vêm das mesmas funções.
    """
    violations = find_violations(ds)
    escalations = escalation_paths(ds)
    creep = privilege_creep(ds)
    orphaned = orphaned_access(ds)
    dormant = dormant_identities(ds)
    worklist = revocation_worklist(ds)
    sev = Counter(v.severity.value for v in violations)
    status = Counter(i.status.value for i in ds.identities)
    cross = [p for p in escalations if p.crosses_account]

    lines: list[str] = []
    add = lines.append

    add("# Scan de governança IAM")
    add("")
    stamp = datetime.now(UTC).isoformat(timespec="seconds")
    add(f"Gerado em {stamp} (UTC). Read-only sobre dados sintéticos.")
    add("")

    add("## Resumo")
    add("")
    add(f"- Contas: {len(ds.accounts)}")
    add(
        f"- Identities: {len(ds.identities)} "
        f"({status['active']} active, {status['disabled']} disabled, "
        f"{status['terminated']} terminated)"
    )
    add(
        f"- Entitlements / groups / roles: "
        f"{len(ds.entitlements)} / {len(ds.groups)} / {len(ds.roles)}"
    )
    add(
        f"- Violações de SoD: {len(violations)} "
        f"(critical {sev['critical']}, high {sev['high']}, "
        f"medium {sev['medium']}, low {sev['low']})"
    )
    add(f"- Caminhos de escalonamento: {len(escalations)} ({len(cross)} cross-account)")
    add(
        f"- JML: {len(creep)} com privilege creep, "
        f"{len(orphaned)} orphaned, {len(dormant)} dormant"
    )
    add(f"- Recertification: {len(worklist)} revogações recomendadas")
    add("")

    add("## Violações de SoD")
    add("")
    if not violations:
        add("Nenhuma.")
    for v in violations:
        a = ", ".join(f"{m.entitlement_name} [{m.grant_reason}]" for m in v.side_a)
        b = ", ".join(f"{m.entitlement_name} [{m.grant_reason}]" for m in v.side_b)
        add(f"- **{v.severity.value.upper()}** {v.identity_name}: {v.rule_name}")
        add(f"    - A: {a}")
        add(f"    - B: {b}")
    add("")

    add("## Privilege escalation cross-account")
    add("")
    if not cross:
        add("Nenhum.")
    for p in cross:
        add(f"- {p.identity_name} alcança **{p.target_label}** (len {p.length}):")
        add(f"    - {_render_path(p.steps)}")
    add("")

    add("## Recertification e worklist de revogação")
    add("")
    if not worklist:
        add("Nenhuma.")
    for item in worklist[:50]:
        flags = [
            name
            for name, on in (
                ("SoD", item.in_sod),
                ("dormant", item.dormant),
                ("escalation", item.enables_escalation),
            )
            if on
        ]
        flag_str = f" ({', '.join(flags)})" if flags else ""
        add(
            f"- score {item.score} [{item.bucket}] {item.identity_id} -> "
            f"{item.entitlement_name}{flag_str}"
        )
    add("")
    return "\n".join(lines)
