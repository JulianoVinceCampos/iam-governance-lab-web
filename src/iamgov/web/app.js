"use strict";

/* Dashboard do iam-governance-lab.
 * Chamadas same-origin ao backend FastAPI. Sem build step: ES puro + Cytoscape + Chart.
 * Tudo read-only; a UI só lê findings e os renderiza.
 */

const API = "";
const state = { reachability: null, cy: null, charts: {} };

/* --- helpers pequenos -----------------------------------------------------*/
async function getJSON(path) {
  const res = await fetch(API + path);
  if (!res.ok) throw new Error(`${path} -> ${res.status}`);
  return res.json();
}

async function sendJSON(method, path, body) {
  const res = await fetch(API + path, {
    method,
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || `${path} -> ${res.status}`);
  return data;
}

function esc(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function el(id) {
  return document.getElementById(id);
}

function sevBadge(sev) {
  return `<span class="badge ${esc(sev)}">${esc(sev)}</span>`;
}

function recBadge(rec) {
  return `<span class="badge rec-${esc(rec)}">${esc(rec)}</span>`;
}

function table(headers, rows) {
  if (!rows.length) return `<div class="empty">Nada a exibir.</div>`;
  const head = headers.map((h) => `<th>${esc(h)}</th>`).join("");
  const body = rows
    .map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join("")}</tr>`)
    .join("");
  return `<table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
}

/* --- navegação ------------------------------------------------------------*/
const VIEW_META = {
  overview: ["Visão geral", "Dataset sintético multi-conta. Nada aqui muta a fonte."],
  graph: ["Grafo de privilégio", "Quem alcança um target sensível, e por qual caminho entre contas."],
  sod: ["Violações de SoD", "Toxic combinations de standing access, com procedência."],
  jml: ["Lifecycle (JML)", "Privilege creep, orphaned access, dormancy e joiner gaps."],
  recert: ["Recertification", "Revisão de acesso com risk score e a worklist de revogação."],
  identities: ["Identities", "Cada principal, seu status e footprint de acesso."],
  editor: ["Editor de dados", "Cria, edita e remove objetos do dataset. Toda edição é validada e recalcula os findings."],
};

const loaded = new Set();

function switchView(name) {
  document.querySelectorAll(".nav-item").forEach((b) =>
    b.classList.toggle("active", b.dataset.view === name)
  );
  document.querySelectorAll(".view").forEach((v) =>
    v.classList.toggle("active", v.id === `view-${name}`)
  );
  const [title, sub] = VIEW_META[name];
  el("view-title").textContent = title;
  el("view-sub").textContent = sub;
  if (!loaded.has(name)) {
    loaded.add(name);
    loaders[name]();
  }
  if (name === "graph" && state.cy) {
    setTimeout(() => state.cy.resize(), 50);
  }
}

/* --- visão geral ----------------------------------------------------------*/
function card(value, label, sub, cls) {
  return `<div class="card ${cls || ""}">
    <div class="value">${esc(value)}</div>
    <div class="label">${esc(label)}</div>
    ${sub ? `<div class="sub">${esc(sub)}</div>` : ""}
  </div>`;
}

function renderRoute(steps) {
  const parts = [];
  steps.forEach((s) => {
    if (s.edge) {
      const cls = s.edge === "assume" ? "hop-edge assume" : "hop-edge";
      parts.push(`<span class="${cls}"> -[${esc(s.edge)}]-&gt; </span>`);
    }
    parts.push(`<span class="hop">${esc(s.label)} <span class="tag">${esc(s.account)}</span></span>`);
  });
  return parts.join("");
}

async function loadOverview() {
  const [metrics, escalation] = await Promise.all([
    getJSON("/api/metrics"),
    getJSON("/api/escalation"),
  ]);

  const idents = metrics.identities;
  const sod = metrics.sod;
  const jml = metrics.jml;
  el("cards").innerHTML = [
    card(idents.total, "Identities", `${idents.active} active / ${idents.disabled} disabled / ${idents.terminated} terminated`),
    card(sod.total, "Violações de SoD", `${sod.by_severity.critical} critical / ${sod.by_severity.high} high`, sod.total ? "alert" : ""),
    card(metrics.escalation.cross_account, "Escalonamentos cross-account", `${metrics.escalation.paths} caminhos no total`, metrics.escalation.cross_account ? "alert" : ""),
    card(metrics.recert.revocations_recommended, "Revogações recomendadas", `${jml.orphaned} orphaned / ${jml.dormant} dormant`, "warn"),
    card(metrics.accounts, "Contas", `${metrics.entitlements} entitlements / ${metrics.roles} roles`),
    card(jml.privilege_creep, "Privilege creep", `${jml.joiner_gaps} joiner gaps`),
  ].join("");

  drawSodChart(sod.by_severity);
  drawFindingsChart(metrics);

  const cross = escalation.filter((p) => p.crosses_account);
  el("escalation-list").innerHTML = cross.length
    ? cross
        .map(
          (p) => `<div class="path-item">
            <div class="path-head">
              <strong>${esc(p.identity_name)}</strong>
              <span>alcança ${esc(p.target_label)} ${sevBadge("critical")}</span>
            </div>
            <div class="path-route">${renderRoute(p.steps)}</div>
          </div>`
        )
        .join("")
    : `<div class="empty">Sem caminhos de escalonamento cross-account.</div>`;
}

function drawSodChart(bySeverity) {
  const ctx = el("chart-sod");
  state.charts.sod?.destroy();
  state.charts.sod = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: ["low", "medium", "high", "critical"],
      datasets: [
        {
          data: [bySeverity.low, bySeverity.medium, bySeverity.high, bySeverity.critical],
          backgroundColor: ["#4b9e6a", "#d6a53c", "#e0793b", "#e0556b"],
          borderColor: "#171d2b",
          borderWidth: 2,
        },
      ],
    },
    options: { plugins: { legend: { labels: { color: "#8b93a7" } } } },
  });
}

function drawFindingsChart(m) {
  const ctx = el("chart-findings");
  state.charts.findings?.destroy();
  state.charts.findings = new Chart(ctx, {
    type: "bar",
    data: {
      labels: ["SoD", "Escalonamento", "Creep", "Orphaned", "Dormant", "Revogações"],
      datasets: [
        {
          label: "contagem",
          data: [
            m.sod.total,
            m.escalation.paths,
            m.jml.privilege_creep,
            m.jml.orphaned,
            m.jml.dormant,
            m.recert.revocations_recommended,
          ],
          backgroundColor: "#5b8cff",
        },
      ],
    },
    options: {
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: "#8b93a7" }, grid: { color: "#2a3350" } },
        y: { ticks: { color: "#8b93a7" }, grid: { color: "#2a3350" }, beginAtZero: true },
      },
    },
  });
}

/* --- grafo de privilégio --------------------------------------------------*/
const GRAPH_STYLE = [
  {
    selector: "node",
    style: {
      label: "data(label)",
      color: "#e6e9f2",
      "font-size": 9,
      "text-valign": "bottom",
      "text-margin-y": 4,
      width: 22,
      height: 22,
      "background-color": "#5b8cff",
      "border-width": 0,
    },
  },
  { selector: 'node[kind="identity"]', style: { "background-color": "#5b8cff", shape: "ellipse" } },
  { selector: 'node[kind="group"]', style: { "background-color": "#46b1a6", shape: "round-rectangle" } },
  { selector: 'node[kind="role"]', style: { "background-color": "#b07aef", shape: "diamond", width: 26, height: 26 } },
  { selector: 'node[kind="entitlement"]', style: { "background-color": "#d6a53c", shape: "hexagon" } },
  { selector: 'node[privilege="critical"]', style: { "border-width": 3, "border-color": "#e0556b" } },
  { selector: 'node[privilege="high"]', style: { "border-width": 2, "border-color": "#e0793b" } },
  {
    selector: "edge",
    style: {
      width: 1.4,
      "line-color": "#2a3350",
      "target-arrow-color": "#2a3350",
      "target-arrow-shape": "triangle",
      "curve-style": "bezier",
      "arrow-scale": 0.8,
    },
  },
  {
    selector: 'edge[kind="assume"]',
    style: { "line-color": "#e0556b", "target-arrow-color": "#e0556b", "line-style": "dashed", width: 2 },
  },
  { selector: "node.highlight", style: { "border-width": 4, "border-color": "#ffffff" } },
  {
    selector: "edge.highlight",
    style: { "line-color": "#ffffff", "target-arrow-color": "#ffffff", width: 3, "line-style": "solid", "z-index": 99 },
  },
  { selector: ".faded", style: { opacity: 0.15 } },
];

const LEGEND = [
  ["identity", "#5b8cff"],
  ["group", "#46b1a6"],
  ["role", "#b07aef"],
  ["entitlement", "#d6a53c"],
  ["aresta assume", "#e0556b"],
];

function renderLegend() {
  el("graph-legend").innerHTML = LEGEND.map(
    ([label, color]) => `<span><i class="dot" style="background:${color}"></i>${label}</span>`
  ).join("");
}

function mountGraph(elements) {
  if (state.cy) {
    state.cy.destroy();
  }
  state.cy = cytoscape({
    container: el("cy"),
    elements,
    style: GRAPH_STYLE,
    layout: { name: "cose", animate: false, padding: 20, nodeRepulsion: 6000, idealEdgeLength: 70 },
    wheelSensitivity: 0.25,
  });
}

async function loadGraph() {
  renderLegend();
  const [graph, targets, reach] = await Promise.all([
    getJSON("/api/graph"),
    getJSON("/api/graph/targets"),
    getJSON("/api/reachability"),
  ]);
  state.reachability = reach;
  mountGraph([...graph.nodes, ...graph.edges]);

  const tsel = el("target-select");
  tsel.innerHTML = targets
    .map((t) => `<option value="${esc(t.node)}">${esc(t.label)} (${esc(t.account)})</option>`)
    .join("");
  tsel.onchange = fillIdentityOptions;
  fillIdentityOptions();

  el("trace-btn").onclick = tracePath;
  el("reset-btn-bind") || bindReset();
}

function bindReset() {
  el("reset-graph").onclick = async () => {
    const graph = await getJSON("/api/graph");
    mountGraph([...graph.nodes, ...graph.edges]);
    el("path-detail").innerHTML = "";
  };
  el("reset-graph").dataset.bound = "1";
}

function fillIdentityOptions() {
  const targetNode = el("target-select").value;
  const targetRef = targetNode.split(":").slice(1).join(":");
  const entry = (state.reachability || []).find((t) => t.target_ref === targetRef);
  const isel = el("identity-select");
  if (!entry || !entry.paths.length) {
    isel.innerHTML = `<option value="">(ninguém alcança isto)</option>`;
    return;
  }
  isel.innerHTML = entry.paths
    .map((p) => {
      const tag = p.uses_assume ? " [escalation]" : " [standing]";
      return `<option value="${esc(p.identity_id)}">${esc(p.identity_name)}${tag}</option>`;
    })
    .join("");
}

async function tracePath() {
  const identity = el("identity-select").value;
  const target = el("target-select").value;
  if (!identity) return;
  const result = await getJSON(`/api/graph/path?identity=${encodeURIComponent(identity)}&target=${encodeURIComponent(target)}`);
  mountGraph([...result.graph.nodes, ...result.graph.edges]);

  if (!result.reachable) {
    el("path-detail").innerHTML = `<div class="empty">${esc(identity)} não alcança ${esc(target)}.</div>`;
    return;
  }
  const p = result.path;
  const flags = [
    p.uses_assume ? sevBadge("critical") + " usa assunção de role" : "só standing access",
    p.crosses_account ? sevBadge("high") + " cruza fronteira de conta" : "conta única",
    `comprimento ${p.length}`,
  ].join(" &middot; ");
  el("path-detail").innerHTML = `<div class="path-item">
    <div class="path-head"><strong>${esc(p.identity_name)} &rarr; ${esc(p.target_label)}</strong></div>
    <div class="muted" style="margin:6px 0">${flags}</div>
    <div class="path-route">${renderRoute(p.steps)}</div>
  </div>`;
}

/* --- SoD ------------------------------------------------------------------*/
async function loadSod() {
  const violations = await getJSON("/api/sod");
  const rows = violations.map((v) => [
    sevBadge(v.severity),
    esc(v.identity_name),
    esc(v.rule_name),
    v.side_a.map((m) => `${esc(m.entitlement_name)} <span class="tag">${esc(m.grant_reason)}</span>`).join("<br>"),
    v.side_b.map((m) => `${esc(m.entitlement_name)} <span class="tag">${esc(m.grant_reason)}</span>`).join("<br>"),
    v.inherited_only ? `<span class="tag">conserto no grupo</span>` : `<span class="tag">tem grant direto</span>`,
  ]);
  el("sod-table").innerHTML = table(["Severidade", "Identity", "Rule", "Lado A", "Lado B", "Remediação"], rows);
}

/* --- JML ------------------------------------------------------------------*/
async function loadJml() {
  const jml = await getJSON("/api/jml");

  el("creep-table").innerHTML = table(
    ["Identity", "Título", "Entitlements extras"],
    jml.privilege_creep.map((c) => [
      esc(c.identity_name),
      esc(c.title),
      c.extra
        .map((e) => `<span class="badge ${esc(e.privilege)}">${esc(e.privilege)}</span> ${esc(e.entitlement_name)} <span class="tag">${esc(e.reason)}</span>`)
        .join("<br>"),
    ])
  );

  el("orphan-table").innerHTML = table(
    ["Identity", "Status", "Entitlements", "Groups"],
    jml.orphaned_access.map((o) => [esc(o.identity_name), sevBadge("high") + " " + esc(o.status), o.entitlement_count, o.group_ids.map(esc).join(", ") || "-"])
  );

  el("dormant-table").innerHTML = table(
    ["Identity", "Dias parada", "Entitlements"],
    jml.dormant.map((d) => [esc(d.identity_name), d.last_activity_days ?? "nunca", d.entitlement_count])
  );

  el("joiner-table").innerHTML = table(
    ["Identity", "Título", "Groups faltando", "Groups extras"],
    jml.joiner_gaps.map((g) => [
      esc(g.identity_name),
      esc(g.title),
      g.missing_group_ids.map(esc).join(", ") || "-",
      g.extra_group_ids.map(esc).join(", ") || "-",
    ])
  );
}

/* --- recertification ------------------------------------------------------*/
async function loadRecert() {
  const recert = await getJSON("/api/recert");

  el("worklist-table").innerHTML = table(
    ["Score", "Bucket", "Identity", "Entitlement", "Conta", "Flags"],
    recert.revocation_worklist.map((i) => [
      `<strong>${i.score}</strong>`,
      sevBadge(i.bucket),
      esc(i.identity_id),
      esc(i.entitlement_name),
      esc(i.account_id),
      [i.in_sod ? "SoD" : null, i.dormant ? "dormant" : null, i.enables_escalation ? "escalation" : null]
        .filter(Boolean)
        .map((f) => `<span class="tag">${f}</span>`)
        .join(" ") || "-",
    ])
  );

  el("campaigns").innerHTML = recert.campaigns
    .map((c) => {
      const reviewees = c.reviewees
        .map((r) => {
          const items = table(
            ["Score", "Rec", "Entitlement", "Grant", "Flags"],
            r.items.map((i) => [
              i.score,
              recBadge(i.recommendation),
              esc(i.entitlement_name),
              `<span class="tag">${esc(i.grant_reason)}</span>`,
              [i.in_sod ? "SoD" : null, i.dormant ? "dormant" : null, i.enables_escalation ? "esc" : null]
                .filter(Boolean)
                .join(", ") || "-",
            ])
          );
          return `<div style="margin:10px 0">
            <div><strong>${esc(r.identity_name)}</strong> <span class="tag">${esc(r.status)}</span> <span class="tag">max ${r.max_score}</span></div>
            ${items}
          </div>`;
        })
        .join("");
      return `<div class="acc-item">
        <button class="acc-head">
          <span>${esc(c.reviewer_name)}</span>
          <span class="tag">${c.reviewees.length} reviewee(s)</span>
        </button>
        <div class="acc-body">${reviewees}</div>
      </div>`;
    })
    .join("");

  document.querySelectorAll(".acc-head").forEach((h) => {
    h.onclick = () => h.nextElementSibling.classList.toggle("open");
  });
}

/* --- identities -----------------------------------------------------------*/
let allIdentities = [];

async function loadIdentities() {
  allIdentities = await getJSON("/api/identities");
  renderIdentities("");
  el("identity-filter").oninput = (e) => renderIdentities(e.target.value.toLowerCase());
}

function renderIdentities(q) {
  const rows = allIdentities
    .filter((i) =>
      [i.name, i.title, i.department, i.home_account_id, i.status].join(" ").toLowerCase().includes(q)
    )
    .map((i) => [
      esc(i.name),
      `<span class="tag">${esc(i.type)}</span>`,
      esc(i.title),
      esc(i.department),
      esc(i.home_account_id),
      i.status === "active" ? esc(i.status) : `<span class="badge high">${esc(i.status)}</span>`,
      i.last_activity_days ?? "nunca",
      i.entitlement_count,
      i.group_count,
    ]);
  el("identities-table").innerHTML = table(
    ["Nome", "Tipo", "Título", "Department", "Conta", "Status", "Dias parada", "Entitlements", "Groups"],
    rows
  );
}

/* --- ligação --------------------------------------------------------------*/
const loaders = {
  overview: loadOverview,
  graph: loadGraph,
  sod: loadSod,
  jml: loadJml,
  recert: loadRecert,
  identities: loadIdentities,
  editor: loadEditor,
};

/* --- editor de dados ------------------------------------------------------*/
const EDIT_KINDS = [
  ["accounts", "Accounts"],
  ["entitlements", "Entitlements"],
  ["groups", "Groups"],
  ["roles", "Roles"],
  ["identities", "Identities"],
  ["sod_rules", "SoD rules"],
];

const PRIV = ["low", "medium", "high", "critical"];

// Descritores de campo por kind. types: text, number, enum, list (vírgula), ref, multiref, selectors.
const FORMS = {
  accounts: [
    { k: "id", req: true },
    { k: "name" },
    { k: "environment", type: "enum", options: ["management", "production", "development", "security"] },
  ],
  entitlements: [
    { k: "id", req: true },
    { k: "account_id", type: "ref", ref: "accounts" },
    { k: "name" },
    { k: "actions", type: "list" },
    { k: "resource" },
    { k: "privilege_level", type: "enum", options: PRIV },
    { k: "assume_targets", type: "multiref", ref: "roles" },
    { k: "tags", type: "list" },
    { k: "description" },
  ],
  groups: [
    { k: "id", req: true },
    { k: "account_id", type: "ref", ref: "accounts" },
    { k: "name" },
    { k: "entitlement_ids", type: "multiref", ref: "entitlements" },
    { k: "member_of", type: "multiref", ref: "groups" },
    { k: "description" },
  ],
  roles: [
    { k: "id", req: true },
    { k: "account_id", type: "ref", ref: "accounts" },
    { k: "name" },
    { k: "entitlement_ids", type: "multiref", ref: "entitlements" },
    { k: "trusts", type: "list" },
    { k: "description" },
  ],
  identities: [
    { k: "id", req: true },
    { k: "name" },
    { k: "type", type: "enum", options: ["human", "service"] },
    { k: "department" },
    { k: "title" },
    { k: "home_account_id", type: "ref", ref: "accounts" },
    { k: "status", type: "enum", options: ["active", "disabled", "terminated"] },
    { k: "manager_id", type: "ref", ref: "identities", optional: true },
    { k: "hire_date" },
    { k: "last_activity_days", type: "number" },
    { k: "entitlement_ids", type: "multiref", ref: "entitlements" },
    { k: "group_ids", type: "multiref", ref: "groups" },
  ],
  sod_rules: [
    { k: "id", req: true },
    { k: "name" },
    { k: "severity", type: "enum", options: PRIV },
    { k: "set_a", type: "selectors" },
    { k: "set_b", type: "selectors" },
    { k: "rationale" },
  ],
};

const editor = { data: null, kind: "identities" };

function editorMsg(text, cls) {
  const box = el("editor-msg");
  box.className = "editor-msg " + (cls || "");
  box.textContent = text || "";
}

async function loadEditor() {
  editor.data = await getJSON("/api/data");
  renderKindTabs();
  renderEditorList();
  el("editor-form").innerHTML = "";
  editorMsg("");
  el("editor-new").onclick = () => openEditorForm(null);
  el("editor-restore").onclick = editorRestore;
}

function renderKindTabs() {
  el("kind-tabs").innerHTML = EDIT_KINDS.map(
    ([k, label]) =>
      `<button class="kind-tab ${k === editor.kind ? "active" : ""}" data-kind="${k}">${esc(label)}</button>`
  ).join("");
  el("kind-tabs")
    .querySelectorAll(".kind-tab")
    .forEach((b) => {
      b.onclick = () => {
        editor.kind = b.dataset.kind;
        renderKindTabs();
        renderEditorList();
        el("editor-form").innerHTML = "";
        editorMsg("");
      };
    });
}

function itemLabel(kind, item) {
  if (kind === "sod_rules") return item.name || item.id;
  return item.name ? `${item.name}` : item.id;
}

function renderEditorList() {
  const items = editor.data[editor.kind] || [];
  const rows = items.map((it) => [
    `<span class="mono">${esc(it.id)}</span>`,
    esc(itemLabel(editor.kind, it)),
    `<div class="row-actions">
       <button class="btn btn-sm" data-edit="${esc(it.id)}">Editar</button>
       <button class="btn btn-sm btn-danger" data-del="${esc(it.id)}">Excluir</button>
     </div>`,
  ]);
  el("editor-list").innerHTML = table(["ID", "Nome", ""], rows);
  el("editor-list")
    .querySelectorAll("[data-edit]")
    .forEach((b) => (b.onclick = () => openEditorForm(items.find((x) => x.id === b.dataset.edit))));
  el("editor-list")
    .querySelectorAll("[data-del]")
    .forEach((b) => (b.onclick = () => editorDelete(b.dataset.del)));
}

function refOptions(refKind, selected, includeEmpty) {
  const opts = (editor.data[refKind] || []).map(
    (x) => `<option value="${esc(x.id)}" ${x.id === selected ? "selected" : ""}>${esc(x.id)}</option>`
  );
  if (includeEmpty) opts.unshift(`<option value="" ${!selected ? "selected" : ""}>(nenhum)</option>`);
  return opts.join("");
}

function checkboxRef(refKind, name, selectedList) {
  const sel = new Set(selectedList || []);
  const items = editor.data[refKind] || [];
  if (!items.length) return `<div class="muted">sem ${esc(refKind)} ainda</div>`;
  return `<div class="checkbox-box">${items
    .map(
      (x) =>
        `<label><input type="checkbox" name="${name}" value="${esc(x.id)}" ${sel.has(x.id) ? "checked" : ""}>${esc(x.id)}</label>`
    )
    .join("")}</div>`;
}

function selectorsHtml(name, list) {
  const rows = (list && list.length ? list : [{ match: "tag", values: [] }])
    .map((s) => selectorRow(name, s))
    .join("");
  return `<div class="selectors" data-name="${name}">${rows}
    <button type="button" class="btn btn-sm" data-add-sel="${name}">+ selector</button></div>`;
}

function selectorRow(name, s) {
  const opts = ["entitlement", "action", "tag"]
    .map((m) => `<option value="${m}" ${s.match === m ? "selected" : ""}>${m}</option>`)
    .join("");
  return `<div class="selector-row">
    <select data-sel-match="${name}">${opts}</select>
    <input data-sel-values="${name}" placeholder="valores separados por vírgula" value="${esc((s.values || []).join(", "))}">
  </div>`;
}

function fieldHtml(kind, f, value) {
  const type = f.type || "text";
  let control = "";
  if (type === "enum") {
    control = `<select name="${f.k}">${f.options
      .map((o) => `<option value="${o}" ${o === value ? "selected" : ""}>${o}</option>`)
      .join("")}</select>`;
  } else if (type === "ref") {
    control = `<select name="${f.k}">${refOptions(f.ref, value, !!f.optional)}</select>`;
  } else if (type === "multiref") {
    control = checkboxRef(f.ref, f.k, value);
  } else if (type === "list") {
    control = `<input name="${f.k}" value="${esc((value || []).join(", "))}" placeholder="separados por vírgula">`;
  } else if (type === "number") {
    control = `<input name="${f.k}" type="number" value="${value ?? ""}">`;
  } else if (type === "selectors") {
    control = selectorsHtml(f.k, value);
  } else {
    control = `<input name="${f.k}" value="${esc(value ?? "")}" ${f.req ? "required" : ""}>`;
  }
  return `<div class="field"><label>${esc(f.k)}${f.req ? " *" : ""}</label>${control}</div>`;
}

function openEditorForm(item) {
  const kind = editor.kind;
  const isNew = !item;
  const data = item || {};
  const fields = FORMS[kind].map((f) => fieldHtml(kind, f, data[f.k])).join("");
  el("editor-form").innerHTML = `
    <h3>${isNew ? "Novo" : "Editar"} ${esc(kind)}</h3>
    <form id="entity-form">${fields}
      <div class="form-actions">
        <button type="submit" class="btn btn-primary">Salvar</button>
        <button type="button" class="btn" id="form-cancel">Cancelar</button>
      </div>
    </form>`;
  // ao editar, trava o id para o upsert mirar o mesmo objeto
  if (!isNew) {
    const idInput = el("editor-form").querySelector('[name="id"]');
    if (idInput) idInput.readOnly = true;
  }
  el("form-cancel").onclick = () => {
    el("editor-form").innerHTML = "";
    editorMsg("");
  };
  el("editor-form")
    .querySelectorAll("[data-add-sel]")
    .forEach((b) => (b.onclick = () => {
      const wrap = b.parentElement;
      b.insertAdjacentHTML("beforebegin", selectorRow(b.dataset.addSel, { match: "tag", values: [] }));
    }));
  el("entity-form").onsubmit = (e) => {
    e.preventDefault();
    submitEntity(kind);
  };
}

function readSelectors(name) {
  const container = el("editor-form").querySelector(`.selectors[data-name="${name}"]`);
  const out = [];
  container.querySelectorAll(".selector-row").forEach((row) => {
    const match = row.querySelector(`[data-sel-match="${name}"]`).value;
    const values = row
      .querySelector(`[data-sel-values="${name}"]`)
      .value.split(",")
      .map((v) => v.trim())
      .filter(Boolean);
    if (values.length) out.push({ match, values });
  });
  return out;
}

function buildEntity(kind) {
  const form = el("entity-form");
  const obj = {};
  for (const f of FORMS[kind]) {
    const type = f.type || "text";
    if (type === "multiref") {
      obj[f.k] = [...form.querySelectorAll(`input[name="${f.k}"]:checked`)].map((c) => c.value);
    } else if (type === "list") {
      obj[f.k] = form
        .querySelector(`[name="${f.k}"]`)
        .value.split(",")
        .map((v) => v.trim())
        .filter(Boolean);
    } else if (type === "selectors") {
      obj[f.k] = readSelectors(f.k);
    } else if (type === "number") {
      const raw = form.querySelector(`[name="${f.k}"]`).value.trim();
      if (raw !== "") obj[f.k] = Number(raw);
    } else {
      const raw = form.querySelector(`[name="${f.k}"]`).value;
      if (type === "ref" && f.optional && raw === "") {
        obj[f.k] = null;
      } else if (raw !== "" || f.req) {
        obj[f.k] = raw;
      }
    }
  }
  return obj;
}

async function submitEntity(kind) {
  const obj = buildEntity(kind);
  try {
    await sendJSON("POST", `/api/data/${kind}`, obj);
    editorMsg(`Salvo ${kind} "${obj.id}". Findings recalculados.`, "ok");
    invalidateAnalyses();
    editor.data = await getJSON("/api/data");
    renderEditorList();
    el("editor-form").innerHTML = "";
  } catch (err) {
    editorMsg("Rejeitado: " + err.message, "err");
  }
}

async function editorDelete(id) {
  if (!confirm(`Excluir ${editor.kind} "${id}"?`)) return;
  try {
    await sendJSON("DELETE", `/api/data/${editor.kind}/${encodeURIComponent(id)}`);
    editorMsg(`Excluído ${editor.kind} "${id}".`, "ok");
    invalidateAnalyses();
    editor.data = await getJSON("/api/data");
    renderEditorList();
  } catch (err) {
    editorMsg("Rejeitado: " + err.message, "err");
  }
}

async function editorRestore() {
  if (!confirm("Restaurar o dataset para o padrão? Isso substitui todos os dados atuais.")) return;
  try {
    await sendJSON("POST", "/api/data/restore", {});
    invalidateAnalyses();
    await loadEditor();
    editorMsg("Restaurado para o padrão.", "ok");
  } catch (err) {
    editorMsg("Falha ao restaurar: " + err.message, "err");
  }
}

function invalidateAnalyses() {
  // Força cada outra view a refazer o fetch na próxima abertura.
  ["overview", "graph", "sod", "jml", "recert", "identities"].forEach((v) => loaded.delete(v));
  Object.values(state.charts).forEach((c) => c?.destroy());
  state.charts = {};
}

async function renderAccountChips() {
  try {
    const accounts = await getJSON("/api/accounts");
    el("account-chips").innerHTML = accounts
      .map((a) => `<span class="chip">${esc(a.name)}</span>`)
      .join("");
  } catch {
    /* ignora */
  }
}

async function healthCheck() {
  try {
    await getJSON("/api/health");
    el("status-dot").classList.add("ok");
  } catch {
    el("status-dot").classList.add("bad");
  }
}

function refreshAll() {
  loaded.clear();
  Object.values(state.charts).forEach((c) => c?.destroy());
  state.charts = {};
  const current = document.querySelector(".nav-item.active")?.dataset.view || "overview";
  loaded.add(current);
  loaders[current]();
}

function init() {
  document.querySelectorAll(".nav-item").forEach((b) => {
    b.onclick = () => switchView(b.dataset.view);
  });
  el("refresh").onclick = refreshAll;
  renderAccountChips();
  healthCheck();
  loaded.add("overview");
  loadOverview();
}

window.addEventListener("DOMContentLoaded", init);
