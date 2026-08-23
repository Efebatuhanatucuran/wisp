const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const STORAGE_KEY = "wisp:web-ui:v1";

let nextId = 1;

// item: {id, kind: 'discovered'|'custom'|'upload'|'example', label, checked, path?, content?}
const state = {
  items: [],
  lastResult: null,
  activeFilters: new Set(SEVERITIES),
  home: null,
  lang: "en",
};

const I18N = {
  en: {
    pageTitle: "Wisp — MCP config scanner",
    tagline: "static security scanner for MCP server configs",
    scoreLabel: "risk score",
    configFilesHeading: "Config files",
    loading: "Loading…",
    refreshing: "Refreshing…",
    dropZoneText: "Drag & drop a config file here",
    chooseFile: "Choose file…",
    tryExample: "Try an example:",
    exampleRisky: "risky config",
    exampleSafe: "safe config",
    exampleDemo: "all severities",
    addPathPlaceholder: "or type a path: /path/to/mcp.json",
    addBtn: "Add",
    checkCveLabel: "Check known CVEs (queries osv.dev)",
    rediscoverBtn: "Rediscover",
    scanBtn: "Scan",
    downloadJsonBtn: "Download JSON",
    downloadHtmlBtn: "Download HTML",
    downloadSarifBtn: "Download SARIF",
    findingsHeading: "Findings",
    resultsEmpty: "Select config files on the left and click Scan.",
    cveFeedHeading: "MCP CVE feed",
    refreshBtn: "Refresh",
    cveFeedLoading: "Loading recent MCP-related CVEs…",
    noConfigFiles: "No config files yet. Drop one below, load an example, or add a path.",
    tagKnown: "known",
    tagManual: "manual",
    tagUploaded: "uploaded",
    tagExample: "example",
    removeTitle: "Remove",
    discoverError: "Could not discover config files",
    readFileError: "Could not read",
    loadExampleError: "Could not load example",
    selectAtLeastOne: "Select at least one config file, drop one in, or add a path.",
    scanning: "Scanning…",
    scanFailed: "Scan failed",
    scanFailedSeeError: "Scan failed. See error above.",
    noFindings: "No findings. Configured servers look clean against current rules.",
    noFindingsFiltered: "No findings match the active filters.",
    fixLabel: "Fix:",
    reportHtmlError: "Could not generate HTML report",
    reportSarifError: "Could not generate SARIF report",
    justNow: "just now",
    unknownTime: "unknown",
    minAgo: (n) => `${n}m ago`,
    hourAgo: (n) => `${n}h ago`,
    dayAgo: (n) => `${n}d ago`,
    cveFeedEmpty: "No published CVEs mention MCP yet — the protocol is still new. This list fills in as the ecosystem matures, and refreshes automatically.",
    cveFeedCouldNotLoad: "Could not load feed",
    cveFeedFailed: "Failed to load CVE feed",
    metaLine: (source, ago) => `${source} · updated ${ago}`,
    summaryLine: (servers, files, findings) =>
      `<strong>${servers}</strong> server(s) across <strong>${files}</strong> file(s) &middot; <strong>${findings}</strong> finding(s)`,
    findingsCount: (n) => `${n} finding${n > 1 ? "s" : ""}`,
  },
  tr: {
    pageTitle: "Wisp — MCP config tarayıcı",
    tagline: "MCP sunucu konfigürasyonları için statik güvenlik tarayıcısı",
    scoreLabel: "risk skoru",
    configFilesHeading: "Config dosyaları",
    loading: "Yükleniyor…",
    refreshing: "Yenileniyor…",
    dropZoneText: "Bir config dosyasını buraya sürükle-bırak",
    chooseFile: "Dosya seç…",
    tryExample: "Bir örnek dene:",
    exampleRisky: "riskli config",
    exampleSafe: "güvenli config",
    exampleDemo: "tüm seviyeler",
    addPathPlaceholder: "veya bir yol yaz: /path/to/mcp.json",
    addBtn: "Ekle",
    checkCveLabel: "Bilinen CVE'leri kontrol et (osv.dev'e sorar)",
    rediscoverBtn: "Yeniden bul",
    scanBtn: "Tara",
    downloadJsonBtn: "JSON indir",
    downloadHtmlBtn: "HTML indir",
    downloadSarifBtn: "SARIF indir",
    findingsHeading: "Bulgular",
    resultsEmpty: "Soldan config dosyalarını seç ve Tara'ya bas.",
    cveFeedHeading: "MCP CVE akışı",
    refreshBtn: "Yenile",
    cveFeedLoading: "Güncel MCP ile ilgili CVE'ler yükleniyor…",
    noConfigFiles: "Henüz config dosyası yok. Aşağıya bir tane bırak, örnek yükle, ya da bir yol ekle.",
    tagKnown: "bilinen",
    tagManual: "manuel",
    tagUploaded: "yüklendi",
    tagExample: "örnek",
    removeTitle: "Kaldır",
    discoverError: "Config dosyaları bulunamadı",
    readFileError: "Okunamadı",
    loadExampleError: "Örnek yüklenemedi",
    selectAtLeastOne: "En az bir config dosyası seç, bir tane bırak, ya da bir yol ekle.",
    scanning: "Taranıyor…",
    scanFailed: "Tarama başarısız",
    scanFailedSeeError: "Tarama başarısız oldu. Yukarıdaki hataya bak.",
    noFindings: "Bulgu yok. Yapılandırılmış sunucular mevcut kurallara göre temiz görünüyor.",
    noFindingsFiltered: "Aktif filtrelere uyan bulgu yok.",
    fixLabel: "Çözüm:",
    reportHtmlError: "HTML rapor oluşturulamadı",
    reportSarifError: "SARIF rapor oluşturulamadı",
    justNow: "az önce",
    unknownTime: "bilinmiyor",
    minAgo: (n) => `${n} dk önce`,
    hourAgo: (n) => `${n} sa önce`,
    dayAgo: (n) => `${n} gün önce`,
    cveFeedEmpty: "MCP ile ilgili yayınlanmış bir CVE henüz yok — protokol çok yeni. Ekosistem büyüdükçe bu liste dolacak ve otomatik güncellenecek.",
    cveFeedCouldNotLoad: "Akış yüklenemedi",
    cveFeedFailed: "CVE akışı yüklenemedi",
    metaLine: (source, ago) => `${source} · ${ago} güncellendi`,
    summaryLine: (servers, files, findings) =>
      `<strong>${servers}</strong> sunucu, <strong>${files}</strong> dosya tarandı &middot; <strong>${findings}</strong> bulgu`,
    findingsCount: (n) => `${n} bulgu`,
  },
};

function t(key) {
  const val = (I18N[state.lang] && I18N[state.lang][key]) ?? I18N.en[key];
  return val;
}

const TAG_KEY = { discovered: "tagKnown", custom: "tagManual", upload: "tagUploaded", example: "tagExample" };

function maskHome(path, home) {
  if (!home || typeof path !== "string" || !path.startsWith(home)) return path;
  const parent = home.slice(0, home.lastIndexOf("/") + 1) || home.slice(0, home.lastIndexOf("\\") + 1);
  return `${parent}****${path.slice(home.length)}`;
}

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
  downloadSarifBtn: document.getElementById("download-sarif-btn"),
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
  pageTitle: document.getElementById("page-title"),
};

function applyStaticTranslations() {
  document.querySelectorAll("[data-i18n]").forEach((elm) => {
    const val = t(elm.dataset.i18n);
    if (typeof val === "string") elm.textContent = val;
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach((elm) => {
    const val = t(elm.dataset.i18nPlaceholder);
    if (typeof val === "string") elm.placeholder = val;
  });
  document.documentElement.lang = state.lang;
  el.pageTitle.textContent = t("pageTitle");
  document.querySelectorAll(".lang-btn").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.lang === state.lang);
  });
  if (!el.scanBtn.disabled) el.scanBtn.textContent = t("scanBtn");
}

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
  let savedLang = null;
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) {
      const data = JSON.parse(raw);
      (data.customPaths || []).forEach((path) => {
        state.items.push({ id: nextId++, kind: "custom", label: path, path, checked: true });
      });
      if (data.lastResult) state.lastResult = data.lastResult;
      if (typeof data.checkCve === "boolean") el.checkCveInput.checked = data.checkCve;
      if (data.lang) savedLang = data.lang;
    }
  } catch (err) {
    /* corrupted/unavailable storage: ignore, start fresh */
  }
  state.lang = savedLang || (navigator.language && navigator.language.toLowerCase().startsWith("tr") ? "tr" : "en");
}

function savePersisted() {
  try {
    const customPaths = state.items.filter((i) => i.kind === "custom").map((i) => i.path);
    localStorage.setItem(STORAGE_KEY, JSON.stringify({
      customPaths,
      lastResult: state.lastResult,
      checkCve: el.checkCveInput.checked,
      lang: state.lang,
    }));
  } catch (err) {
    /* storage unavailable (private mode, quota, etc): non-fatal */
  }
}

function renderFileList() {
  if (state.items.length === 0) {
    el.fileList.innerHTML = `<p class="muted">${t("noConfigFiles")}</p>`;
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
    const displayLabel = maskHome(item.label, state.home);
    label.textContent = displayLabel;
    label.title = displayLabel;

    const tag = document.createElement("span");
    tag.className = "tag";
    tag.textContent = t(TAG_KEY[item.kind]);

    row.appendChild(checkbox);
    row.appendChild(label);
    row.appendChild(tag);

    if (item.kind !== "discovered") {
      const removeBtn = document.createElement("button");
      removeBtn.className = "remove-btn";
      removeBtn.textContent = "✕";
      removeBtn.title = t("removeTitle");
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
    state.home = data.home || null;
    state.items = state.items.filter((i) => i.kind !== "discovered");
    const discovered = data.files.map((path) => ({ id: nextId++, kind: "discovered", label: path, path, checked: true }));
    state.items = [...discovered, ...state.items];
    renderFileList();
    if (state.lastResult) renderFindings(); // re-render with the now-known home path masked
  } catch (err) {
    showError(`${t("discoverError")}: ${err.message}`);
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
      showError(`${t("readFileError")} ${file.name}: ${err.message}`);
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
    showError(`${t("loadExampleError")}: ${err.message}`);
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
      <div class="finding-meta">${escapeHtml(maskHome(f.source_file, state.home))}</div>
      <p>${escapeHtml(f.description)}</p>
      ${f.evidence ? `<div class="evidence">${escapeHtml(f.evidence)}</div>` : ""}
      ${f.remediation ? `<p class="remediation"><em>${t("fixLabel")}</em> ${escapeHtml(f.remediation)}</p>` : ""}
    </div>
  `;
}

function renderFindings() {
  if (!state.lastResult) return;
  const all = state.lastResult.findings;
  const filtered = all.filter((f) => state.activeFilters.has(f.severity));

  if (all.length === 0) {
    el.results.innerHTML = `<p class="muted">${t("noFindings")}</p>`;
    return;
  }
  if (filtered.length === 0) {
    el.results.innerHTML = `<p class="muted">${t("noFindingsFiltered")}</p>`;
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
          <span class="muted">(${t("findingsCount")(items.length)})</span>
        </summary>
        <div class="server-findings">${items.map(findingHtml).join("")}</div>
      </details>
    `;
  }).join("");
}

function renderSummary(result) {
  el.summary.innerHTML = t("summaryLine")(
    result.servers_scanned, result.files_scanned.length, result.findings.length,
  );
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
    showError(t("selectAtLeastOne"));
    return;
  }

  el.scanBtn.disabled = true;
  el.scanBtn.innerHTML = `<span class="spinner"></span> ${t("scanning")}`;
  el.results.innerHTML = `<p class="muted">${t("scanning")}</p>`;
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
    showError(`${t("scanFailed")}: ${err.message}`);
    el.results.innerHTML = `<p class="muted">${t("scanFailedSeeError")}</p>`;
  } finally {
    el.scanBtn.disabled = false;
    el.scanBtn.textContent = t("scanBtn");
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

document.querySelectorAll(".lang-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    if (state.lang === btn.dataset.lang) return;
    state.lang = btn.dataset.lang;
    applyStaticTranslations();
    renderFileList();
    if (state.lastResult) renderAll();
    loadCveFeed(false);
    savePersisted();
  });
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
    showError(`${t("reportHtmlError")}: ${err.message}`);
  }
});

el.downloadSarifBtn.addEventListener("click", async () => {
  if (!state.lastResult) return;
  const { paths, files } = selectedForScan();
  try {
    const res = await fetch("/api/scan/report.sarif", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        paths: paths.length ? paths : null,
        files: files.length ? files : null,
        check_cve: el.checkCveInput.checked,
      }),
    });
    if (!res.ok) throw new Error(`report failed: ${res.status}`);
    const sarif = await res.text();
    downloadBlob(sarif, "wisp-report.sarif", "application/sarif+json");
  } catch (err) {
    showError(`${t("reportSarifError")}: ${err.message}`);
  }
});

function timeAgo(isoString) {
  const then = new Date(isoString).getTime();
  if (Number.isNaN(then)) return t("unknownTime");
  const diffMin = Math.round((Date.now() - then) / 60000);
  if (diffMin < 1) return t("justNow");
  if (diffMin < 60) return t("minAgo")(diffMin);
  const diffHr = Math.round(diffMin / 60);
  if (diffHr < 24) return t("hourAgo")(diffHr);
  return t("dayAgo")(Math.round(diffHr / 24));
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
  el.cveFeedMeta.textContent = refresh ? t("refreshing") : t("loading");
  try {
    const params = new URLSearchParams({ lang: state.lang });
    if (refresh) params.set("refresh", "true");
    const res = await fetch(`/api/cve-feed?${params.toString()}`);
    if (!res.ok) throw new Error(`feed failed: ${res.status}`);
    const data = await res.json();
    el.cveFeedMeta.textContent = t("metaLine")(data.source, timeAgo(data.fetched_at));
    if (data.items.length === 0) {
      el.cveFeedList.innerHTML = `<p class="muted">${t("cveFeedEmpty")}</p>`;
      return;
    }
    el.cveFeedList.innerHTML = data.items.map(cveItemHtml).join("");
  } catch (err) {
    el.cveFeedMeta.textContent = t("cveFeedCouldNotLoad");
    el.cveFeedList.innerHTML = `<p class="muted">${t("cveFeedFailed")}: ${escapeHtml(err.message)}</p>`;
  }
}

el.cveFeedRefreshBtn.addEventListener("click", () => loadCveFeed(true));
el.checkCveInput.addEventListener("change", savePersisted);

loadPersisted();
applyStaticTranslations();
renderFileList();
if (state.lastResult) renderAll();
discover();
loadCveFeed(false);
