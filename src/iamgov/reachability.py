"""Privilege reachability: quem alcança o quê, atravessando N contas, e por qual caminho.

O grafo de acesso é dirigido, e uma aresta ``u -> v`` lê-se como "ter u permite obter v":

    identity   -> entitlement     grant direto (direct_grant) ou por atributo (abac_grant)
    identity   -> group           membership
    group      -> group           membership aninhada (filho -> pai)
    group      -> entitlement     o grupo carrega o entitlement
    entitlement-> role            o entitlement permite assumir o role (sts:AssumeRole),
                                  e a trust policy do role admite a conta de origem
    role       -> entitlement     o role carrega o entitlement depois de assumido

Duas noções derivadas:

* Standing access alcança um entitlement sem nunca atravessar uma aresta ``assume``.
* Escalonamento só alcança assumindo um ou mais roles. O escalonamento cross-account é o
  caso relevante para segurança: uma identity numa conta de development que consegue assumir
  role até um entitlement admin em produção.

Trust é modelado na granularidade de conta (ver docs/reachability.md): a aresta ``assume`` só
existe quando o lado identity-based (o entitlement lista o role) e o lado resource-based (o
role confia na conta de origem, ou confia em ``*``) concordam. Um trust ``*`` é alcançável por
qualquer conta e é reportado como um risco à parte.
"""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch

import networkx as nx

from .model import Dataset, PrivilegeLevel

ASSUME_EDGE = "assume"
SENSITIVE_LEVELS = frozenset({PrivilegeLevel.HIGH, PrivilegeLevel.CRITICAL})


def node_id(kind: str, item_id: str) -> str:
    return f"{kind}:{item_id}"


def _trust_admits(trusts: list[str], source_account_id: str) -> bool:
    return any(t == "*" or fnmatch(source_account_id, t) for t in trusts)


def build_graph(ds: Dataset) -> nx.DiGraph:
    """Monta o grafo de acesso dirigido com nós e arestas tipados."""
    g: nx.DiGraph = nx.DiGraph()

    for e in ds.entitlements:
        g.add_node(
            node_id("entitlement", e.id),
            kind="entitlement",
            ref=e.id,
            label=e.name,
            account=e.account_id,
            privilege=e.privilege_level.value,
        )
    for grp in ds.groups:
        g.add_node(
            node_id("group", grp.id),
            kind="group",
            ref=grp.id,
            label=grp.name,
            account=grp.account_id,
        )
    for r in ds.roles:
        g.add_node(
            node_id("role", r.id),
            kind="role",
            ref=r.id,
            label=r.name,
            account=r.account_id,
        )
    for i in ds.identities:
        g.add_node(
            node_id("identity", i.id),
            kind="identity",
            ref=i.id,
            label=i.name,
            account=i.home_account_id,
        )

    for i in ds.identities:
        src = node_id("identity", i.id)
        for eid in i.entitlement_ids:
            g.add_edge(src, node_id("entitlement", eid), kind="direct_grant")
        for gid in i.group_ids:
            g.add_edge(src, node_id("group", gid), kind="member_of")

    # ABAC: uma identity que casa uma regra de atributo alcança o entitlement direto, sem
    # passar por grupo nenhum. A aresta é tipada à parte (abac_grant) para o grafo mostrar o
    # acesso por atributo como um mecanismo distinto do RBAC de grupos.
    from .access import _identity_matches  # local: evita ciclo de import no topo do módulo

    for i in ds.identities:
        src = node_id("identity", i.id)
        for rule in ds.abac_rules:
            if _identity_matches(i, rule):
                for eid in rule.entitlement_ids:
                    g.add_edge(src, node_id("entitlement", eid), kind="abac_grant")

    for grp in ds.groups:
        src = node_id("group", grp.id)
        for eid in grp.entitlement_ids:
            g.add_edge(src, node_id("entitlement", eid), kind="group_grant")
        for parent in grp.member_of:
            g.add_edge(src, node_id("group", parent), kind="nested")

    for r in ds.roles:
        src = node_id("role", r.id)
        for eid in r.entitlement_ids:
            g.add_edge(src, node_id("entitlement", eid), kind="role_grant")

    # Arestas de assume exigem acordo entre o lado do entitlement e o lado do trust do role.
    for e in ds.entitlements:
        for target_role_id in e.assume_targets:
            role = ds.role(target_role_id)
            if _trust_admits(role.trusts, e.account_id):
                g.add_edge(
                    node_id("entitlement", e.id),
                    node_id("role", role.id),
                    kind=ASSUME_EDGE,
                )
    return g


@dataclass(frozen=True)
class PathStep:
    node: str
    kind: str
    ref: str
    label: str
    account: str
    edge_from_prev: str | None  # kind da aresta vinda do passo anterior; None no primeiro

    def to_dict(self) -> dict[str, str | None]:
        return {
            "kind": self.kind,
            "ref": self.ref,
            "label": self.label,
            "account": self.account,
            "edge": self.edge_from_prev,
        }


@dataclass(frozen=True)
class ReachPath:
    identity_id: str
    identity_name: str
    target_kind: str
    target_ref: str
    target_label: str
    steps: tuple[PathStep, ...]

    @property
    def length(self) -> int:
        return len(self.steps) - 1

    @property
    def uses_assume(self) -> bool:
        return any(s.edge_from_prev == ASSUME_EDGE for s in self.steps)

    @property
    def crosses_account(self) -> bool:
        accounts = {s.account for s in self.steps if s.account}
        return len(accounts) > 1

    def to_dict(self) -> dict[str, object]:
        return {
            "identity_id": self.identity_id,
            "identity_name": self.identity_name,
            "target_kind": self.target_kind,
            "target_ref": self.target_ref,
            "target_label": self.target_label,
            "length": self.length,
            "uses_assume": self.uses_assume,
            "crosses_account": self.crosses_account,
            "steps": [s.to_dict() for s in self.steps],
        }


def _path_steps(g: nx.DiGraph, nodes: list[str]) -> tuple[PathStep, ...]:
    steps: list[PathStep] = []
    prev: str | None = None
    for n in nodes:
        attrs = g.nodes[n]
        edge_kind = g.edges[prev, n]["kind"] if prev is not None else None
        steps.append(
            PathStep(
                node=n,
                kind=attrs["kind"],
                ref=attrs["ref"],
                label=attrs["label"],
                account=attrs.get("account", ""),
                edge_from_prev=edge_kind,
            )
        )
        prev = n
    return tuple(steps)


def who_can_reach(g: nx.DiGraph, ds: Dataset, target_node: str) -> list[ReachPath]:
    """Toda identity com caminho até ``target_node``, cada uma com seu caminho mais curto."""
    if target_node not in g:
        raise KeyError(f"unknown target node: {target_node}")
    sources = {n for n in nx.ancestors(g, target_node) if g.nodes[n]["kind"] == "identity"}
    target_attrs = g.nodes[target_node]
    paths: list[ReachPath] = []
    for src in sources:
        node_path = nx.shortest_path(g, src, target_node)
        identity = ds.identity(g.nodes[src]["ref"])
        paths.append(
            ReachPath(
                identity_id=identity.id,
                identity_name=identity.name,
                target_kind=target_attrs["kind"],
                target_ref=target_attrs["ref"],
                target_label=target_attrs["label"],
                steps=_path_steps(g, node_path),
            )
        )
    paths.sort(key=lambda p: (not p.uses_assume, p.length, p.identity_id))
    return paths


def reach_path(ds: Dataset, identity_id: str, target_node: str) -> ReachPath | None:
    """O caminho mais curto de uma identity até um target, ou None se inalcançável."""
    g = build_graph(ds)
    src = node_id("identity", identity_id)
    if src not in g or target_node not in g:
        raise KeyError("unknown identity or target node")
    if not nx.has_path(g, src, target_node):
        return None
    node_path = nx.shortest_path(g, src, target_node)
    target_attrs = g.nodes[target_node]
    identity = ds.identity(identity_id)
    return ReachPath(
        identity_id=identity.id,
        identity_name=identity.name,
        target_kind=target_attrs["kind"],
        target_ref=target_attrs["ref"],
        target_label=target_attrs["label"],
        steps=_path_steps(g, node_path),
    )


def reachable_entitlements(g: nx.DiGraph, identity_id: str) -> dict[str, bool]:
    """Mapeia cada entitlement ref alcançável -> uses_assume (True se só via escalonamento).

    Um entitlement alcançável por qualquer caminho sem assume é standing (valor False); um que
    exige assumir um role é escalonamento (valor True).
    """
    src = node_id("identity", identity_id)
    reachable = nx.descendants(g, src)
    out: dict[str, bool] = {}
    for n in reachable:
        if g.nodes[n]["kind"] != "entitlement":
            continue
        ref = g.nodes[n]["ref"]
        node_path = nx.shortest_path(g, src, n)
        uses_assume = any(
            g.edges[a, b]["kind"] == ASSUME_EDGE
            for a, b in zip(node_path, node_path[1:], strict=False)
        )
        out[ref] = uses_assume
    return out


@dataclass(frozen=True)
class TargetReachability:
    target_kind: str
    target_ref: str
    target_label: str
    account: str
    privilege: str
    paths: tuple[ReachPath, ...]

    @property
    def reachable_by_count(self) -> int:
        return len(self.paths)

    @property
    def escalation_count(self) -> int:
        return sum(1 for p in self.paths if p.uses_assume)

    @property
    def cross_account_count(self) -> int:
        return sum(1 for p in self.paths if p.crosses_account)

    def to_dict(self) -> dict[str, object]:
        return {
            "target_kind": self.target_kind,
            "target_ref": self.target_ref,
            "target_label": self.target_label,
            "account": self.account,
            "privilege": self.privilege,
            "reachable_by_count": self.reachable_by_count,
            "escalation_count": self.escalation_count,
            "cross_account_count": self.cross_account_count,
            "paths": [p.to_dict() for p in self.paths],
        }


def sensitive_target_nodes(g: nx.DiGraph) -> list[str]:
    """Nós de entitlement em privilege HIGH ou CRITICAL: os targets que valem auditar."""
    levels = {level.value for level in SENSITIVE_LEVELS}
    return sorted(
        n
        for n, a in g.nodes(data=True)
        if a["kind"] == "entitlement" and a.get("privilege") in levels
    )


def reachability_report(ds: Dataset) -> list[TargetReachability]:
    """Para cada entitlement sensível, quem consegue alcançá-lo e como."""
    g = build_graph(ds)
    report: list[TargetReachability] = []
    for target in sensitive_target_nodes(g):
        attrs = g.nodes[target]
        report.append(
            TargetReachability(
                target_kind=attrs["kind"],
                target_ref=attrs["ref"],
                target_label=attrs["label"],
                account=attrs.get("account", ""),
                privilege=attrs.get("privilege", ""),
                paths=tuple(who_can_reach(g, ds, target)),
            )
        )
    report.sort(key=lambda t: (-t.escalation_count, -t.reachable_by_count, t.target_ref))
    return report


def escalation_paths(ds: Dataset) -> list[ReachPath]:
    """Todos os caminhos mais curtos até targets sensíveis que exigem assumir um role.

    São os findings de privilege escalation: standing access sozinho não concede o target, mas
    a identity consegue assumir role até lá. Os cross-account são os piores.
    """
    out: list[ReachPath] = []
    for target in reachability_report(ds):
        out.extend(p for p in target.paths if p.uses_assume)
    out.sort(key=lambda p: (not p.crosses_account, p.length, p.identity_id))
    return out


def export_cytoscape(ds: Dataset, highlight_path: list[str] | None = None) -> dict[str, object]:
    """Serializa o grafo de acesso inteiro no formato de elements do Cytoscape.js.

    ``highlight_path`` é uma lista de node ids (como vêm nos steps do caminho) para marcar, de
    modo que o frontend consiga desenhar uma rota de escalonamento por cima do grafo.
    """
    g = build_graph(ds)
    highlight = set(highlight_path or [])
    highlight_edges: set[tuple[str, str]] = set()
    if highlight_path:
        highlight_edges = set(zip(highlight_path, highlight_path[1:], strict=False))

    nodes = [
        {
            "data": {
                "id": n,
                "label": a["label"],
                "kind": a["kind"],
                "account": a.get("account", ""),
                "privilege": a.get("privilege", ""),
                "ref": a["ref"],
            },
            "classes": "highlight" if n in highlight else "",
        }
        for n, a in g.nodes(data=True)
    ]
    edges = [
        {
            "data": {"id": f"{u}__{v}", "source": u, "target": v, "kind": a["kind"]},
            "classes": "assume" + (" highlight" if (u, v) in highlight_edges else "")
            if a["kind"] == ASSUME_EDGE
            else ("highlight" if (u, v) in highlight_edges else ""),
        }
        for u, v, a in g.edges(data=True)
    ]
    return {"nodes": nodes, "edges": edges}
