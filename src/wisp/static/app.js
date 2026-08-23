const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const STORAGE_KEY = "wisp:web-ui:v1";

let nextId = 1;

// item: {id, kind: 'discovered'|'custom'|'upload'|'example', label, checked, path?, content?}
const state = {
  items: [],
  lastResult: null,
  activeFilters: new Set(SEVERITIES),
};

const el = {
  fileList: document.getElementById("file-list"),
  dropZone: document.getElementById("drop-zone"),
  fileInput: document.getElementById("file-input"),
  addForm: document.getElementById("add-path-form"),
  addInput: document.getElementById("add-path-input"),
  rediscoverBtn: document.getElementById("rediscover-btn"),
  scanBtn: document.getElementById("scan-btn"),
  downloadActions: document.getElementById("download-actions"),
  downloadJsonBtn: document.getElementById("download-json-btn"),
  downloadHtmlBtn: document.getElementById("download-html-btn"),
  summary: document.getElementById("summary"),
  errorBanner: document.getElementById("error-banner"),
  scoreBadge: document.getElementById("score-badge"),
  severityFilters: document.getElementById("severity-filters"),
  results: document.getElementById("results"),
  wisp: document.getElementById("wisp"),
  checkCveInput: document.getElementById("check-cve-input"),
  cveFeedMeta: document.getElementById("cve-feed-meta"),
  cveFeedList: document.getElementById("cve-feed-list"),
  cveFeedRefreshBtn: document.getElementById("cve-feed-refresh-btn"),
};

function showError(message) {
  if (!message) {
    el.errorBanner.hidden = true;
    el.errorBanner.textContent = "";
    return;
  }
  el.errorBanner.hidden = false;
  el.errorBanner.textContent = message;
}

function loadPersisted() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return;
    const data = JSON.parse(raw);
    (data.customPaths || []).forEach((path) => {
      state.items.push({ id: nextId++, kind: "custom", label: path, path, checked: true });
    });
    if (data.lastResult) {
      state.lastResult = data.lastResult;
    }
    if (typeof data.checkCve === "boolean") {
      el.checkCveInput.checked = data.checkCve;
    }
  } catch (err) {
    /* corrupted/unavailable storage: ignore, start fresh */
  }
}

function savePersisted() {
  try {
    const customPaths = state.items.filter((i) => i.kind === "custom").map((i) => i.path);
    localStorage.setItem(STORAGE_KEY, JSON.stringify({
      customPaths,
      lastResult: state.lastResult,
      checkCve: el.checkCveInput.checked,
    }));
  } catch (err) {
    /* storage unavailable (private mode, quota, etc): non-fatal */
  }
}

const TAG_LABEL = { discovered: "known", custom: "manual", upload: "uploaded", example: "example" };

function renderFileList() {
  if (state.items.length === 0) {
    el.fileList.innerHTML = '<p class="muted">No config files yet. Drop one below, load an example, or add a path.</p>';
    return;
  }
  el.fileList.innerHTML = "";
  state.items.forEach((item) => {
    const row = document.createElement("div");
    row.className = "file-item";

    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.checked = item.checked;
    checkbox.addEventListener("change", () => { item.checked = checkbox.checked; });

    const label = document.createElement("label");
    label.textContent = item.label;
    label.title = item.label;

    const tag = document.createElement("span");
    tag.className = "tag";
    tag.textContent = TAG_LABEL[item.kind];

    row.appendChild(checkbox);
    row.appendChild(label);
    row.appendChild(tag);

    if (item.kind !== "discovered") {
      const removeBtn = document.createElement("button");
      removeBtn.className = "remove-btn";
      removeBtn.textContent = "✕";
      removeBtn.title = "Remove";
      removeBtn.addEventListener("click", () => {
        state.items = state.items.filter((i) => i.id !== item.id);
        renderFileList();
      });
      row.appendChild(removeBtn);
    }

    el.fileList.appendChild(row);
  });
}

async function discover() {
  showError(null);
  try {
    const res = await fetch("/api/discover");
    if (!res.ok) throw new Error(`discover failed: ${res.status}`);
    const data = await res.json();
    state.items = state.items.filter((i) => i.kind !== "discovered");
    const discovered = data.files.map((path) => ({ id: nextId++, kind: "discovered", label: path, path, checked: true }));
    state.items = [...discovered, ...state.items];
    renderFileList();
  } catch (err) {
    showError(`Could not discover config files: ${err.message}`);
  }
}

function addPath(path) {
  if (state.items.some((i) => i.path === path)) return;
  state.items.push({ id: nextId++, kind: "custom", label: path, path, checked: true });
  renderFileList();
}

async function addFiles(fileList) {
  for (const file of fileList) {
    try {
      const content = await file.text();
      state.items.push({ id: nextId++, kind: "upload", label: file.name, content, checked: true });
    } catch (err) {
      showError(`Could not read ${file.name}: ${err.message}`);
    }
  }
  renderFileList();
}

async function loadExample(name) {
  showError(null);
  try {
    const res = await fetch(`/api/examples/${name}`);
    if (!res.ok) throw new Error(`example fetch failed: ${res.status}`);
    const data = await res.json();
    const label = `${data.name} (example)`;
    if (state.items.some((i) => i.label === label)) return;
    state.items.push({ id: nextId++, kind: "example", label, content: data.content, checked: true });
    renderFileList();
  } catch (err) {
    showError(`Could not load example: ${err.message}`);
  }
}

function selectedForScan() {
  const checked = state.items.filter((i) => i.checked);
  const paths = checked.filter((i) => i.kind === "discovered" || i.kind === "custom").map((i) => i.path);
  const files = checked
    .filter((i) => i.kind === "upload" || i.kind === "example")
    .map((i) => ({ name: i.label, content: i.content }));
  return { paths, files };
}

function scoreClass(score) {
  if (score >= 85) return "score-good";
  if (score >= 60) return "score-warn";
  if (score >= 35) return "score-bad";
  return "score-critical";
}

function renderScore(score) {
  const cls = scoreClass(score);
  el.scoreBadge.className = `score-badge ${cls}`;
  el.scoreBadge.querySelector(".score-value").textContent = score;
  el.wisp.className = `wisp state-${cls.replace("score-", "")}`;
}

function severityRank(sev) {
  return SEVERITIES.indexOf(sev);
}

function renderSeverityFilters(findings) {
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  findings.forEach((f) => { counts[f.severity] = (counts[f.severity] || 0) + 1; });

  el.severityFilters.innerHTML = "";
  SEVERITIES.forEach((sev) => {
    const chip = document.createElement("button");
    chip.className = "chip" + (state.activeFilters.has(sev) ? " active" : "");
    chip.dataset.severity = sev;
    chip.textContent = `${sev} (${counts[sev]})`;
    chip.addEventListener("click", () => {
      if (state.activeFilters.has(sev)) {
        state.activeFilters.delete(sev);
      } else {
        state.activeFilters.add(sev);
      }
      renderSeverityFilters(findings);
      renderFindings();
    });
    el.severityFilters.appendChild(chip);
  });
}

function escapeHtml(str) {
  const d = document.createElement("div");
  d.textContent = str ?? "";
  return d.innerHTML;
}

function findingHtml(f) {
  return `
    <div class="finding ${f.severity}">
      <div class="finding-title">
        <span class="badge ${f.severity}">${f.severity}</span>
        <strong>${escapeHtml(f.rule_id)} &middot; ${escapeHtml(f.title)}</strong>
      </div>
      <div class="finding-meta">${escapeHtml(f.source_file)}</div>
      <p>${escapeHtml(f.description)}</p>
      ${f.evidence ? `<div class="evidence">${escapeHtml(f.evidence)}</div>` : ""}
      ${f.remediation ? `<p class="remediation"><em>Fix:</em> ${escapeHtml(f.remediation)}</p>` : ""}
    </div>
  `;
}

function renderFindings() {
  if (!state.lastResult) return;
  const all = state.lastResult.findings;
  const filtered = all.filter((f) => state.activeFilters.has(f.severity));

  if (all.length === 0) {
    el.results.innerHTML = '<p class="muted">No findings. Configured servers look clean against current rules.</p>';
    return;
  }
  if (filtered.length === 0) {
    el.results.innerHTML = '<p class="muted">No findings match the active filters.</p>';
    return;
  }

  const groups = new Map();
  filtered.forEach((f) => {
    if (!groups.has(f.server_name)) groups.set(f.server_name, []);
    groups.get(f.server_name).push(f);
  });

  const servers = [...groups.keys()].sort((a, b) => {
    const ra = Math.min(...groups.get(a).map((f) => severityRank(f.severity)));
    const rb = Math.min(...groups.get(b).map((f) => severityRank(f.severity)));
    return ra - rb;
  });

  el.results.innerHTML = servers.map((server) => {
    const items = groups.get(server);
    const worst = items.reduce(
      (w, f) => (severityRank(f.severity) < severityRank(w) ? f.severity : w), items[0].severity,
    );
    return `
      <details class="server-group" open>
        <summary>
          <span class="badge ${worst}">${worst}</span>
          <strong>${escapeHtml(server)}</strong>
          <span class="muted">(${items.length} finding${items.length > 1 ? "s" : ""})</span>
        </summary>
        <div class="server-findings">${items.map(findingHtml).join("")}</div>
      </details>
    `;
  }).join("");
}

function renderSummary(result) {
  el.summary.innerHTML = `<strong>${result.servers_scanned}</strong> server(s) across
    <strong>${result.files_scanned.length}</strong> file(s) &middot;
    <strong>${result.findings.length}</strong> finding(s)`;
}

function renderAll() {
  if (!state.lastResult) return;
  renderScore(state.lastResult.score);
  renderSummary(state.lastResult);
  state.activeFilters = new Set(SEVERITIES);
  renderSeverityFilters(state.lastResult.findings);
  renderFindings();
  el.downloadActions.hidden = false;
}

function downloadBlob(content, filename, mime) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

async function runScan() {
  showError(null);
  const { paths, files } = selectedForScan();
  if (paths.length === 0 && files.length === 0) {
    showError("Select at least one config file, drop one in, or add a path.");
    return;
  }

  el.scanBtn.disabled = true;
  el.scanBtn.innerHTML = '<span class="spinner"></span> Scanning…';
  el.results.innerHTML = '<p class="muted">Scanning…</p>';
  el.wisp.classList.add("scanning");

  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        paths: paths.length ? paths : null,
        files: files.length ? files : null,
        check_cve: el.checkCveInput.checked,
      }),
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.detail || `scan failed: ${res.status}`);
    }
    state.lastResult = await res.json();
    renderAll();
    savePersisted();
  } catch (err) {
    showError(`Scan failed: ${err.message}`);
    el.results.innerHTML = '<p class="muted">Scan failed. See error above.</p>';
  } finally {
    el.scanBtn.disabled = false;
    el.scanBtn.textContent = "Scan";
    el.wisp.classList.remove("scanning");
  }
}

el.addForm.addEventListener("submit", (e) => {
  e.preventDefault();
  const path = el.addInput.value.trim();
  if (!path) return;
  addPath(path);
  el.addInput.value = "";
});

el.rediscoverBtn.addEventListener("click", discover);
el.scanBtn.addEventListener("click", runScan);

el.fileInput.addEventListener("change", () => {
  if (el.fileInput.files.length) addFiles(el.fileInput.files);
  el.fileInput.value = "";
});

el.dropZone.addEventListener("dragover", (e) => {
  e.preventDefault();
  el.dropZone.classList.add("dragover");
});
el.dropZone.addEventListener("dragleave", () => el.dropZone.classList.remove("dragover"));
el.dropZone.addEventListener("drop", (e) => {
  e.preventDefault();
  el.dropZone.classList.remove("dragover");
  if (e.dataTransfer.files.length) addFiles(e.dataTransfer.files);
});

document.querySelectorAll(".link-btn[data-example]").forEach((btn) => {
  btn.addEventListener("click", () => loadExample(btn.dataset.example));
});

el.downloadJsonBtn.addEventListener("click", () => {
  if (!state.lastResult) return;
  downloadBlob(JSON.stringify(state.lastResult, null, 2), "wisp-report.json", "application/json");
});

el.downloadHtmlBtn.addEventListener("click", async () => {
  if (!state.lastResult) return;
  const { paths, files } = selectedForScan();
  try {
    const res = await fetch("/api/scan/report.html", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        paths: paths.length ? paths : null,
        files: files.length ? files : null,
        check_cve: el.checkCveInput.checked,
      }),
    });
    if (!res.ok) throw new Error(`report failed: ${res.status}`);
    const html = await res.text();
    downloadBlob(html, "wisp-report.html", "text/html");
  } catch (err) {
    showError(`Could not generate HTML report: ${err.message}`);
  }
});

function timeAgo(isoString) {
  const then = new Date(isoString).getTime();
  if (Number.isNaN(then)) return "unknown";
  const diffMin = Math.round((Date.now() - then) / 60000);
  if (diffMin < 1) return "just now";
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.round(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  return `${Math.round(diffHr / 24)}d ago`;
}

function cveItemHtml(item) {
  const date = item.published ? new Date(item.published).toISOString().slice(0, 10) : "";
  const severity = item.severity || "UNKNOWN";
  return `
    <div class="cve-item sev-${severity}">
      <div class="cve-item-title">
        <span class="badge ${severity}">${severity}</span>
        <a href="${item.url}" target="_blank" rel="noopener noreferrer">${escapeHtml(item.id)}</a>
        <span class="cve-item-date">${date}</span>
      </div>
      <p>${escapeHtml(item.summary)}</p>
    </div>
  `;
}

async function loadCveFeed(refresh) {
  el.cveFeedMeta.textContent = refresh ? "Refreshing…" : "Loading…";
  try {
    const res = await fetch(`/api/cve-feed${refresh ? "?refresh=true" : ""}`);
    if (!res.ok) throw new Error(`feed failed: ${res.status}`);
    const data = await res.json();
    el.cveFeedMeta.textContent = `${data.source} · updated ${timeAgo(data.fetched_at)}`;
    if (data.items.length === 0) {
      el.cveFeedList.innerHTML =
        '<p class="muted">No published CVEs mention MCP yet — the protocol is still new. This list fills in as the ecosystem matures, and refreshes automatically.</p>';
      return;
    }
    el.cveFeedList.innerHTML = data.items.map(cveItemHtml).join("");
  } catch (err) {
    el.cveFeedMeta.textContent = "Could not load feed";
    el.cveFeedList.innerHTML = `<p class="muted">Failed to load CVE feed: ${escapeHtml(err.message)}</p>`;
  }
}

el.cveFeedRefreshBtn.addEventListener("click", () => loadCveFeed(true));
el.checkCveInput.addEventListener("change", savePersisted);

loadPersisted();
renderFileList();
if (state.lastResult) renderAll();
discover();
loadCveFeed(false);
