const state = {
  dashboard: null,
  cases: [],
  selectedCase: null,
  selectedCaseData: {},
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || response.statusText);
  return payload;
}

function toast(message) {
  const node = $("#toast");
  node.textContent = message;
  node.classList.add("show");
  setTimeout(() => node.classList.remove("show"), 2600);
}

function setView(view) {
  $$(".view").forEach((node) => node.classList.toggle("active", node.id === view));
  $$("#nav button").forEach((button) => button.classList.toggle("active", button.dataset.view === view));
  if (view !== "dashboard" && view !== "search" && view !== "cases" && !state.selectedCase) {
    toast("Select an investigation first");
  }
}

function item(title, meta = "", data = null) {
  const node = document.createElement("button");
  node.className = "item";
  node.innerHTML = `<strong>${escapeHtml(title)}</strong>${meta ? `<small>${escapeHtml(meta)}</small>` : ""}`;
  if (data) node.addEventListener("click", () => inspect(title, data));
  return node;
}

function inspect(title, data) {
  $("#selectedTitle").textContent = title;
  $("#inspectorJson").textContent = JSON.stringify(data, null, 2);
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[char]);
}

function renderList(selector, rows, getTitle, getMeta) {
  const root = $(selector);
  root.innerHTML = "";
  if (!rows?.length) {
    root.append(item("No records yet", "Argus will populate this as you work."));
    return;
  }
  rows.forEach((row) => root.append(item(getTitle(row), getMeta(row), row)));
}

function renderMetrics(stats) {
  const metrics = [
    ["Investigations", stats.investigations],
    ["Entities", stats.entities],
    ["Relationships", stats.relationships],
    ["Evidence", stats.evidence],
    ["Findings", stats.intelligence],
    ["Jobs", stats.collection_jobs],
  ];
  $("#metrics").innerHTML = metrics.map(([label, value]) => (
    `<div class="metric"><strong>${value ?? 0}</strong><span>${label}</span></div>`
  )).join("");
}

function renderTable(selector, rows, columns) {
  const root = $(selector);
  if (!rows?.length) {
    root.innerHTML = `<div class="item"><strong>No records yet</strong><small>Nothing to show here.</small></div>`;
    return;
  }
  root.innerHTML = `<table><thead><tr>${columns.map(([, label]) => `<th>${label}</th>`).join("")}</tr></thead><tbody>${
    rows.map((row) => `<tr>${columns.map(([key]) => `<td>${escapeHtml(format(row[key]))}</td>`).join("")}</tr>`).join("")
  }</tbody></table>`;
  [...root.querySelectorAll("tbody tr")].forEach((tr, index) => tr.addEventListener("click", () => inspect("Record", rows[index])));
}

function format(value) {
  if (Array.isArray(value)) return value.join(", ");
  if (value && typeof value === "object") return JSON.stringify(value);
  return value ?? "";
}

async function loadDashboard() {
  state.dashboard = await api("/api/dashboard");
  state.cases = state.dashboard.recent_investigations || [];
  renderMetrics(state.dashboard.stats);
  $("#caseCount").textContent = `${state.cases.length} shown`;
  renderList("#recentCases", state.cases, (row) => row.title, (row) => `${row.status} · updated ${row.updated_at}`);
  renderList("#searchHistory", state.dashboard.search_history, (row) => row.query, (row) => `${row.result_count} results · ${row.created_at}`);
  renderList("#savedSearches", state.dashboard.saved_searches, (row) => row.name, (row) => row.query);
  renderList("#recentJobs", state.dashboard.recent_jobs, (row) => `${row.collector}: ${row.query}`, (row) => `${row.status} · ${row.created_at}`);
  $("#systemStatus").innerHTML = Object.entries(state.dashboard.system_status).map(([key, value]) => (
    `<div class="status"><span>${escapeHtml(key.replaceAll("_", " "))}</span><strong>${escapeHtml(value)}</strong></div>`
  )).join("");
  renderCases();
}

function renderCases() {
  renderTable("#casesTable", state.cases, [
    ["id", "ID"],
    ["title", "Investigation"],
    ["status", "Status"],
    ["investigator", "Investigator"],
    ["updated_at", "Updated"],
  ]);
  [...$("#casesTable").querySelectorAll("tbody tr")].forEach((tr, index) => {
    tr.addEventListener("dblclick", () => selectCase(state.cases[index].id));
  });
}

async function selectCase(caseId) {
  const [caseRecord, entities, evidence, graph, timeline, security] = await Promise.all([
    api(`/api/investigations/${caseId}`),
    api(`/api/investigations/${caseId}/entities`),
    api(`/api/investigations/${caseId}/evidence`),
    api(`/api/investigations/${caseId}/graph`),
    api(`/api/investigations/${caseId}/timeline`),
    api(`/api/investigations/${caseId}/security`),
  ]);
  state.selectedCase = caseRecord;
  state.selectedCaseData = { entities, evidence, graph, timeline, security };
  $("#selectedTitle").textContent = caseRecord.title;
  $("#selectedMeta").innerHTML = `
    <div class="status"><span>Status</span><strong>${escapeHtml(caseRecord.status)}</strong></div>
    <div class="status"><span>Entities</span><strong>${entities.length}</strong></div>
    <div class="status"><span>Timeline</span><strong>${timeline.length}</strong></div>
  `;
  $("#inspectorJson").textContent = JSON.stringify(caseRecord, null, 2);
  renderEntityCards();
  renderGraph(graph);
  renderTimeline(timeline);
  renderTable("#evidenceTable", evidence, [["title", "Title"], ["mime_type", "Type"], ["sha256", "SHA-256"], ["captured_at", "Captured"]]);
  $("#securityBrief").textContent = JSON.stringify(security, null, 2);
  toast(`Opened ${caseRecord.title}`);
}

function renderEntityCards() {
  const entities = state.selectedCaseData.entities || [];
  const profiles = entities.filter((entity) => ["person", "username", "email", "phone", "social_profile"].includes(entity.kind));
  const infra = entities.filter((entity) => ["domain", "ip", "url", "asn", "cve", "file_hash"].includes(entity.kind));
  renderCards("#profileCards", profiles);
  renderCards("#infraCards", infra);
}

function renderCards(selector, rows) {
  const root = $(selector);
  root.innerHTML = rows.length ? "" : `<div class="panel"><h2>No matching entities yet</h2><p class="muted">Archive collector findings or add entities to populate this view.</p></div>`;
  rows.forEach((row) => {
    const card = document.createElement("button");
    card.className = "item";
    card.innerHTML = `<strong>${escapeHtml(row.display_name || row.value)}</strong><small>${escapeHtml(row.kind)} · confidence ${Math.round((row.confidence || 0) * 100)}%</small>`;
    card.addEventListener("click", () => inspect(row.value, row));
    root.append(card);
  });
}

function renderGraph(graph) {
  const svg = $("#graphSvg");
  svg.innerHTML = "";
  const nodes = graph.nodes || [];
  const edges = graph.edges || [];
  const positions = new Map();
  const cx = 480, cy = 270, radius = Math.max(120, nodes.length * 16);
  nodes.forEach((node, index) => {
    const angle = (Math.PI * 2 * index) / Math.max(nodes.length, 1);
    positions.set(node.id, { x: cx + Math.cos(angle) * radius, y: cy + Math.sin(angle) * radius });
  });
  edges.forEach((edge) => {
    const source = positions.get(edge.source);
    const target = positions.get(edge.target);
    if (!source || !target) return;
    svg.insertAdjacentHTML("beforeend", `<line class="edge" x1="${source.x}" y1="${source.y}" x2="${target.x}" y2="${target.y}"></line>`);
  });
  nodes.forEach((node) => {
    const point = positions.get(node.id);
    svg.insertAdjacentHTML("beforeend", `<circle class="node" cx="${point.x}" cy="${point.y}" r="22"></circle><text class="node-label" x="${point.x}" y="${point.y + 38}">${escapeHtml(node.label).slice(0, 28)}</text>`);
  });
}

function renderTimeline(rows) {
  const root = $("#timelineList");
  root.innerHTML = "";
  if (!rows?.length) {
    root.append(item("No timeline records yet", "Events, evidence, jobs, and intelligence will appear here."));
    return;
  }
  rows.forEach((row) => root.append(item(row.title, `${row.kind} · ${row.time}`, row)));
}

async function runSearch() {
  const query = $("#globalSearch").value.trim();
  if (!query) return;
  const result = await api(`/api/search?q=${encodeURIComponent(query)}`);
  $("#searchSummary").textContent = `${result.local_result_count} local matches · ${result.plan.length} recommended collectors`;
  $("#localCount").textContent = `${result.local_result_count} results`;
  $("#inputKind").textContent = result.input.kind.replaceAll("_", " ");
  renderList("#localResults", result.local_results, (row) => row.title, (row) => `${row.object_type} · case ${row.investigation_id}`);
  renderList("#collectionPlan", result.plan, (row) => row.collector, (row) => `${row.query} · ${row.reason}`);
  setView("search");
}

async function newCase() {
  const title = prompt("Investigation title");
  if (!title) return;
  const created = await api("/api/investigations", {
    method: "POST",
    body: JSON.stringify({ title }),
  });
  await loadDashboard();
  await selectCase(created.id);
  setView("cases");
}

async function init() {
  $$("#nav button").forEach((button) => button.addEventListener("click", () => setView(button.dataset.view)));
  $$("[data-jump]").forEach((button) => button.addEventListener("click", () => setView(button.dataset.jump)));
  $("#runSearch").addEventListener("click", runSearch);
  $("#globalSearch").addEventListener("keydown", (event) => { if (event.key === "Enter") runSearch(); });
  $("#refresh").addEventListener("click", async () => { await loadDashboard(); toast("Dashboard refreshed"); });
  $("#newCase").addEventListener("click", newCase);
  const health = await api("/api/health");
  $("#health").textContent = "Local";
  $("#settingsInfo").innerHTML = Object.entries(health).map(([key, value]) => (
    `<div class="status"><span>${escapeHtml(key)}</span><strong>${escapeHtml(value)}</strong></div>`
  )).join("");
  await loadDashboard();
}

init().catch((error) => {
  console.error(error);
  toast(error.message);
  $("#health").textContent = "Error";
});
