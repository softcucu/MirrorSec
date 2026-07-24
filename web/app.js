"use strict";

const POLL_INTERVAL_MS = 2000;

const state = {
  activeTab: window.location.hash === "#findings" ? "findings" : "history",
  page: { history: 1, findings: 1 },
  pageSize: 20,
  query: "",
  severity: "",
  summary: null,
  records: null,
  controller: null,
  requestNumber: 0,
  pollTimer: null,
  toastTimer: null,
};

const elements = {
  connection: document.querySelector("#connection"),
  connectionLabel: document.querySelector("#connection-label"),
  refreshTime: document.querySelector("#refresh-time"),
  refreshButton: document.querySelector("#refresh-button"),
  databaseName: document.querySelector("#database-name"),
  databasePath: document.querySelector("#database-path"),
  databaseMeta: document.querySelector("#database-meta"),
  stats: document.querySelector("#stats"),
  historyCount: document.querySelector("#history-count"),
  findingsCount: document.querySelector("#findings-count"),
  tableTitle: document.querySelector("#table-title"),
  tableSubtitle: document.querySelector("#table-subtitle"),
  resultsView: document.querySelector("#results-view"),
  tableHead: document.querySelector("#table-head"),
  tableBody: document.querySelector("#table-body"),
  loadingOverlay: document.querySelector("#loading-overlay"),
  searchInput: document.querySelector("#search-input"),
  severityWrap: document.querySelector("#severity-wrap"),
  severitySelect: document.querySelector("#severity-select"),
  pageSize: document.querySelector("#page-size"),
  pageSummary: document.querySelector("#page-summary"),
  pageIndicator: document.querySelector("#page-indicator"),
  previousPage: document.querySelector("#previous-page"),
  nextPage: document.querySelector("#next-page"),
  dialog: document.querySelector("#detail-dialog"),
  dialogEyebrow: document.querySelector("#dialog-eyebrow"),
  dialogTitle: document.querySelector("#dialog-title"),
  dialogContent: document.querySelector("#dialog-content"),
  dialogClose: document.querySelector("#dialog-close"),
  toast: document.querySelector("#toast"),
};

const tableDefinitions = {
  history: {
    title: "Git 历史安全问题",
    subtitle: "从修复提交中确认的历史漏洞",
    placeholder: "搜索问题、提交或根因",
    columns: [
      ["历史问题", "160"],
      ["问题描述", "310"],
      ["根因摘要", "290"],
      ["提交作者", "150"],
      ["发现时间", "120"],
      ["", "70"],
    ],
  },
  findings: {
    title: "问题排查结果",
    subtitle: "基于历史问题在当前代码中确认的同类漏洞",
    placeholder: "搜索标题、代码位置或证据",
    columns: [
      ["级别", "72"],
      ["确认问题", "260"],
      ["代码位置", "210"],
      ["来源问题", "145"],
      ["置信度", "90"],
      ["发现时间", "120"],
      ["", "70"],
    ],
  },
};

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = text;
  return node;
}

function formatNumber(value) {
  return new Intl.NumberFormat("zh-CN").format(Number(value || 0));
}

function formatBytes(value) {
  const bytes = Number(value || 0);
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), 3);
  const result = bytes / 1024 ** index;
  return `${result.toFixed(result >= 10 || index === 0 ? 0 : 1)} ${units[index]}`;
}

function formatDate(value, includeTime = true) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: includeTime ? "2-digit" : undefined,
    minute: includeTime ? "2-digit" : undefined,
    hour12: false,
  }).format(date);
}

function severityLabel(value) {
  return (
    {
      critical: "严重",
      high: "高危",
      medium: "中危",
      low: "低危",
      info: "提示",
      none: "无",
    }[String(value || "").toLowerCase()] || value || "未知"
  );
}

function confidenceLabel(value) {
  return (
    { high: "高", medium: "中", low: "低" }[
      String(value || "").toLowerCase()
    ] || value || "未知"
  );
}

function setConnection(status, detail) {
  elements.connection.dataset.state = status;
  if (status === "online") {
    elements.connectionLabel.textContent = "数据库已连接";
    elements.refreshTime.textContent = detail || "刚刚同步";
  } else if (status === "offline") {
    elements.connectionLabel.textContent = "数据库连接中断";
    elements.refreshTime.textContent = detail || "稍后自动重试";
  } else {
    elements.connectionLabel.textContent = "正在连接数据库";
    elements.refreshTime.textContent = detail || "等待首次同步";
  }
}

function showToast(message) {
  elements.toast.textContent = message;
  elements.toast.classList.add("is-visible");
  window.clearTimeout(state.toastTimer);
  state.toastTimer = window.setTimeout(() => {
    elements.toast.classList.remove("is-visible");
  }, 3600);
}

function renderDatabase(summary) {
  const database = summary.database;
  elements.databaseName.textContent = database.name || "未指定数据库";
  elements.databasePath.textContent = database.path || "";
  elements.databasePath.title = database.path || "";
  elements.databaseMeta.textContent = database.exists
    ? `${formatBytes(database.size_bytes)} · SQLite / WAL 兼容`
    : "等待数据库创建";
}

function statCard(label, value, note, tone = "") {
  const card = element("article", "stat-card");
  if (tone) card.dataset.tone = tone;
  const labelNode = element("div", "stat-label");
  labelNode.append(element("span"), document.createTextNode(label));
  card.append(
    labelNode,
    element("div", "stat-value", formatNumber(value)),
    element("div", "stat-note", note),
  );
  return card;
}

function renderStats(summary) {
  const history = summary.history;
  const findings = summary.findings;
  elements.stats.replaceChildren();

  const cards =
    state.activeTab === "history"
      ? [
          ["历史安全问题", history.issues, "已写入漏洞样本库", "live"],
          ["已处理提交", history.commits, `完成分析 ${formatNumber(history.analyzed)}`],
          ["安全修复提交", history.fix_commits, "确认包含漏洞修复", "live"],
          ["分析失败", history.failed, "可在下次任务中重试", history.failed ? "alert" : ""],
        ]
      : [
          ["确认同类问题", findings.total, "当前代码中的有效发现", "alert"],
          ["正在排查", findings.running, `排查任务总数 ${formatNumber(findings.audits)}`, "live"],
          [
            "严重 / 高危",
            Number(findings.critical) + Number(findings.high),
            `严重 ${formatNumber(findings.critical)} · 高危 ${formatNumber(findings.high)}`,
            "alert",
          ],
          [
            "排查失败",
            findings.failed,
            `已完成 ${formatNumber(findings.completed)}`,
            findings.failed ? "alert" : "",
          ],
        ];

  for (const card of cards) {
    elements.stats.append(statCard(...card));
  }
  elements.historyCount.textContent = formatNumber(history.issues);
  elements.findingsCount.textContent = formatNumber(findings.total);
}

function renderHeader() {
  const definition = tableDefinitions[state.activeTab];
  elements.tableTitle.textContent = definition.title;
  elements.tableSubtitle.textContent = definition.subtitle;
  elements.searchInput.placeholder = definition.placeholder;
  elements.severityWrap.classList.toggle(
    "is-hidden",
    state.activeTab !== "findings",
  );
  elements.resultsView.setAttribute(
    "aria-labelledby",
    `${state.activeTab}-tab`,
  );

  const row = document.createElement("tr");
  for (const [label, width] of definition.columns) {
    const th = element("th", "", label);
    th.style.width = `${width}px`;
    row.append(th);
  }
  elements.tableHead.replaceChildren(row);
}

function appendTextCell(row, text, className = "") {
  const cell = element("td");
  const content = element("div", className, text || "—");
  cell.append(content);
  row.append(cell);
  return cell;
}

function historyRow(item) {
  const row = element("tr", "data-row");

  const idCell = element("td");
  const id = element("div", "id-cell");
  id.append(
    element("strong", "", item.issue_id),
    element("span", "", item.subject || item.commit_hash),
  );
  idCell.append(id);
  row.append(idCell);

  const descriptionCell = element("td");
  const description = element("div", "primary-cell");
  description.append(
    element("strong", "", item.description || "未提供问题描述"),
    element("span", "", item.subject || "Git 历史修复提交"),
  );
  descriptionCell.append(description);
  row.append(descriptionCell);

  appendTextCell(row, item.root_cause, "truncate-two");

  const authorCell = element("td");
  const author = element("div", "id-cell");
  author.append(
    element("strong", "", item.author_name || "未知"),
    element("span", "", item.author_email || "—"),
  );
  authorCell.append(author);
  row.append(authorCell);

  appendTextCell(row, formatDate(item.created_at), "mono");

  const actionCell = element("td");
  const button = element("button", "detail-button", "详情");
  button.type = "button";
  button.addEventListener("click", () => openHistoryDetail(item));
  actionCell.append(button);
  row.append(actionCell);
  return row;
}

function findingRow(item) {
  const row = element("tr", "data-row");

  const severityCell = element("td");
  const severity = element(
    "span",
    "severity",
    severityLabel(item.severity),
  );
  severity.dataset.severity = String(item.severity || "").toLowerCase();
  severityCell.append(severity);
  row.append(severityCell);

  const titleCell = element("td");
  const title = element("div", "primary-cell");
  title.append(
    element("strong", "", item.title || "未命名安全问题"),
    element("span", "", item.root_cause || "暂无根因摘要"),
  );
  titleCell.append(title);
  row.append(titleCell);

  const locationCell = element("td");
  const location = element("div", "id-cell");
  location.append(
    element("strong", "", item.code_location || "—"),
    element("span", "", item.code_path || "—"),
  );
  locationCell.append(location);
  row.append(locationCell);

  const sourceCell = element("td");
  const source = element("div", "id-cell");
  source.append(
    element("strong", "", item.source_issue_id),
    element("span", "", item.source_description || "历史问题"),
  );
  sourceCell.append(source);
  row.append(sourceCell);

  const confidenceCell = element("td");
  const confidence = element(
    "span",
    "confidence",
    confidenceLabel(item.confidence),
  );
  confidence.dataset.confidence = String(item.confidence || "").toLowerCase();
  confidenceCell.append(confidence);
  row.append(confidenceCell);

  appendTextCell(row, formatDate(item.created_at), "mono");

  const actionCell = element("td");
  const button = element("button", "detail-button", "详情");
  button.type = "button";
  button.addEventListener("click", () => openFindingDetail(item));
  actionCell.append(button);
  row.append(actionCell);
  return row;
}

function renderEmpty() {
  const row = document.createElement("tr");
  const cell = element("td", "empty-cell");
  cell.colSpan = tableDefinitions[state.activeTab].columns.length;
  const wrapper = element("div", "empty-state");
  const icon = element("span", "empty-icon");
  icon.innerHTML =
    '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h16M7 3h10l3 4v13H4V7l3-4Z"/><path d="M9 12h6"/></svg>';
  const hasFilter = Boolean(
    state.query || (state.activeTab === "findings" && state.severity),
  );
  wrapper.append(
    icon,
    element(
      "strong",
      "",
      hasFilter ? "没有匹配的记录" : "暂时没有结果",
    ),
    element(
      "p",
      "",
      hasFilter
        ? "换一个关键词或清除筛选条件后再试。"
        : "看板会持续读取数据库，任务写入新结果后会自动出现在这里。",
    ),
  );
  cell.append(wrapper);
  row.append(cell);
  elements.tableBody.replaceChildren(row);
}

function renderTable(records) {
  if (!records.items.length) {
    renderEmpty();
  } else {
    elements.tableBody.replaceChildren(
      ...records.items.map((item) =>
        state.activeTab === "history" ? historyRow(item) : findingRow(item),
      ),
    );
  }

  const start = records.total ? (records.page - 1) * records.page_size + 1 : 0;
  const end = Math.min(records.page * records.page_size, records.total);
  elements.pageSummary.textContent = `共 ${formatNumber(records.total)} 条记录 · 当前 ${start}–${end}`;
  elements.pageIndicator.textContent = `${records.page} / ${records.pages}`;
  elements.previousPage.disabled = records.page <= 1;
  elements.nextPage.disabled = records.page >= records.pages;
}

function detailMeta(entries) {
  const meta = element("div", "detail-meta");
  for (const [label, value] of entries) {
    const item = element("div");
    item.append(
      element("span", "", label),
      element("strong", "", value || "—"),
    );
    item.title = value || "";
    meta.append(item);
  }
  return meta;
}

function detailSection(label, content, code = false) {
  const section = element("section", "detail-section");
  section.append(
    element("h3", "", label),
    element(code ? "pre" : "p", "", content || "—"),
  );
  return section;
}

function openHistoryDetail(item) {
  elements.dialogEyebrow.textContent = "HISTORICAL ISSUE";
  elements.dialogTitle.textContent = item.description || "历史安全问题";
  elements.dialogContent.replaceChildren(
    detailMeta([
      ["问题编号", item.issue_id],
      ["提交作者", item.author_name || "未知"],
      ["提交时间", formatDate(item.authored_at)],
    ]),
    detailSection("提交主题", item.subject),
    detailSection("问题描述", item.description),
    detailSection("完整根因", item.root_cause),
    detailSection("修复前代码", item.original_code, true),
  );
  elements.dialog.showModal();
}

function openFindingDetail(item) {
  elements.dialogEyebrow.textContent = "SIMILAR ISSUE FINDING";
  elements.dialogTitle.textContent = item.title || "问题排查结果";
  elements.dialogContent.replaceChildren(
    detailMeta([
      ["严重级别", severityLabel(item.severity)],
      ["置信度", confidenceLabel(item.confidence)],
      ["来源问题", item.source_issue_id],
    ]),
    detailSection("代码位置", item.code_location),
    detailSection("问题根因", item.root_cause),
    detailSection("证据", item.evidence),
    detailSection("攻击路径", item.attack_path),
    detailSection("与历史问题的相似性", item.similarity_analysis),
    detailSection("差异分析", item.difference_analysis),
    detailSection("修复建议", item.recommendation),
  );
  elements.dialog.showModal();
}

async function fetchJson(url, signal) {
  const response = await fetch(url, {
    signal,
    cache: "no-store",
    headers: { Accept: "application/json" },
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.detail || payload.error || `HTTP ${response.status}`);
  }
  return payload;
}

async function loadData({ initial = false, notify = false } = {}) {
  const requestNumber = ++state.requestNumber;
  state.controller?.abort();
  state.controller = new AbortController();
  const signal = state.controller.signal;

  if (initial) elements.loadingOverlay.hidden = false;
  elements.refreshButton.classList.add("is-spinning");

  const parameters = new URLSearchParams({
    page: String(state.page[state.activeTab]),
    page_size: String(state.pageSize),
  });
  if (state.query) parameters.set("query", state.query);
  if (state.activeTab === "findings" && state.severity) {
    parameters.set("severity", state.severity);
  }

  try {
    const [summary, records] = await Promise.all([
      fetchJson("/api/summary", signal),
      fetchJson(`/api/${state.activeTab}?${parameters}`, signal),
    ]);
    if (requestNumber !== state.requestNumber) return;

    state.summary = summary;
    state.records = records;
    if (records.page > records.pages) {
      state.page[state.activeTab] = records.pages;
      await loadData();
      return;
    }

    renderDatabase(summary);
    renderStats(summary);
    renderTable(records);
    if (summary.database.exists) {
      setConnection(
        "online",
        `同步于 ${new Intl.DateTimeFormat("zh-CN", {
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
          hour12: false,
        }).format(new Date())}`,
      );
    } else {
      setConnection("loading", "每 2 秒自动检测");
      elements.connectionLabel.textContent = "等待数据库创建";
    }
    if (notify) showToast("已读取数据库最新内容");
  } catch (error) {
    if (error.name === "AbortError") return;
    setConnection("offline", "2 秒后自动重试");
    showToast(`读取失败：${error.message}`);
    if (initial && !state.records) renderEmpty();
  } finally {
    if (requestNumber === state.requestNumber) {
      elements.loadingOverlay.hidden = true;
      elements.refreshButton.classList.remove("is-spinning");
    }
  }
}

function schedulePolling() {
  window.clearInterval(state.pollTimer);
  if (!document.hidden) {
    state.pollTimer = window.setInterval(() => loadData(), POLL_INTERVAL_MS);
  }
}

function selectTab(tab) {
  if (!tableDefinitions[tab] || tab === state.activeTab) return;
  state.activeTab = tab;
  state.query = "";
  state.severity = "";
  elements.searchInput.value = "";
  elements.severitySelect.value = "";
  window.history.replaceState(null, "", `#${tab}`);

  document.querySelectorAll(".tab").forEach((button) => {
    const active = button.dataset.tab === tab;
    button.classList.toggle("is-active", active);
    button.setAttribute("aria-selected", String(active));
  });

  renderHeader();
  if (state.summary) renderStats(state.summary);
  elements.loadingOverlay.hidden = false;
  loadData({ initial: true });
}

function debounce(callback, delay) {
  let timer;
  return (...args) => {
    window.clearTimeout(timer);
    timer = window.setTimeout(() => callback(...args), delay);
  };
}

document.querySelectorAll(".tab").forEach((button) => {
  button.addEventListener("click", () => selectTab(button.dataset.tab));
  button.addEventListener("keydown", (event) => {
    if (!["ArrowLeft", "ArrowRight"].includes(event.key)) return;
    event.preventDefault();
    const next = state.activeTab === "history" ? "findings" : "history";
    selectTab(next);
    document.querySelector(`[data-tab="${next}"]`).focus();
  });
});

elements.searchInput.addEventListener(
  "input",
  debounce(() => {
    state.query = elements.searchInput.value.trim();
    state.page[state.activeTab] = 1;
    loadData({ initial: true });
  }, 320),
);

elements.severitySelect.addEventListener("change", () => {
  state.severity = elements.severitySelect.value;
  state.page.findings = 1;
  loadData({ initial: true });
});

elements.pageSize.addEventListener("change", () => {
  state.pageSize = Number(elements.pageSize.value);
  state.page.history = 1;
  state.page.findings = 1;
  loadData({ initial: true });
});

elements.previousPage.addEventListener("click", () => {
  state.page[state.activeTab] = Math.max(
    1,
    state.page[state.activeTab] - 1,
  );
  loadData({ initial: true });
});

elements.nextPage.addEventListener("click", () => {
  if (!state.records) return;
  state.page[state.activeTab] = Math.min(
    state.records.pages,
    state.page[state.activeTab] + 1,
  );
  loadData({ initial: true });
});

elements.refreshButton.addEventListener("click", () => {
  loadData({ notify: true });
});

elements.dialogClose.addEventListener("click", () => {
  elements.dialog.close();
});

elements.dialog.addEventListener("click", (event) => {
  if (event.target === elements.dialog) elements.dialog.close();
});

document.addEventListener("visibilitychange", () => {
  schedulePolling();
  if (!document.hidden) loadData();
});

window.addEventListener("hashchange", () => {
  selectTab(window.location.hash === "#findings" ? "findings" : "history");
});

document.querySelectorAll(".tab").forEach((button) => {
  const active = button.dataset.tab === state.activeTab;
  button.classList.toggle("is-active", active);
  button.setAttribute("aria-selected", String(active));
});
renderHeader();
loadData({ initial: true });
schedulePolling();
