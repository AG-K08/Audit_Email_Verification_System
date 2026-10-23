/**
 * Thunderbird Phishing Guard v2.2 — Popup Logic
 * AG-K08 (@And_8) © 2026
 */

"use strict";

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

let currentIncidents = [];
let currentHistory = [];
let activeFilter = null; // null | "CLEAN" | "SUSPICIOUS" | "MALICIOUS"
let currentDetailItem = null;
let sortDirection = -1; // -1: DESC (newest first), 1: ASC
let searchText = "";

let pollTimeout = null;
let pollAttempts = 0;
let currentPollingMessageId = null;
const MAX_POLL_ATTEMPTS = 15;

// ──────────────────────────── DATA LOADING ────────────────────────

async function loadStats() {
  try {
    const response = await browser.runtime.sendMessage({ action: "getStats" });
    const s = response.stats;
    $("#totalCount").textContent = s.total;
    $("#cleanCount").textContent = s.clean;
    $("#suspiciousCount").textContent = s.suspicious;
    $("#maliciousCount").textContent = s.malicious;
    if (s.lastScan) {
      $("#lastScan").textContent = `Последняя проверка: ${new Date(s.lastScan).toLocaleString("ru-RU")}`;
    }
  } catch (err) { console.error("loadStats:", err); }
}

async function loadIncidents() {
  try {
    const response = await browser.runtime.sendMessage({
      action: "getIncidents",
      limit: 500,
      statusFilter: activeFilter
    });
    currentIncidents = response.incidents || [];
    applyFiltersAndSort("incidentList");
  } catch (err) { console.error("loadIncidents:", err); }
}

async function loadHistory() {
  try {
    const response = await browser.runtime.sendMessage({
      action: "getHistory",
      limit: 500,
      statusFilter: activeFilter
    });
    currentHistory = response.history || [];
    applyFiltersAndSort("historyList");
  } catch (err) { console.error("loadHistory:", err); }
}

// ──────────────────────────── FILTERING ────────────────────────

function setFilter(filterStatus) {
  // filterStatus: "total"|"clean"|"suspicious"|"malicious"
  const statusMap = { total: null, clean: "CLEAN", suspicious: "SUSPICIOUS", malicious: "MALICIOUS" };
  const newFilter = statusMap[filterStatus] || null;
  activeFilter = activeFilter === newFilter ? null : newFilter; // toggle

  $$(".stat-card").forEach((c) => c.classList.remove("active"));
  if (activeFilter) {
    const cls = activeFilter.toLowerCase();
    const card = $(`.stat-card.${cls}`);
    if (card) card.classList.add("active");
  }

  // Reload from server with filter
  const activeTab = $(".tab.active")?.dataset?.tab;
  if (activeTab === "history") loadHistory();
  else loadIncidents();
}

// ──────────────────────────── SEARCH & SORT ────────────────────

function applyFiltersAndSort(containerId) {
  let items = containerId === "incidentList" ? [...currentIncidents] : [...currentHistory];

  // 1. Filter by text
  if (searchText) {
    const low = searchText.toLowerCase();
    items = items.filter((item) => 
      (item.subject || "").toLowerCase().includes(low) || 
      (item.author || "").toLowerCase().includes(low) ||
      (item.reasons || []).some(r => r.toLowerCase().includes(low))
    );
  }

  // 2. Sort by date
  // Prefer original message 'date', fall back to 'checkedAt'
  items.sort((a, b) => {
    const da = new Date(a.date || a.checkedAt).getTime();
    const db = new Date(b.date || b.checkedAt).getTime();
    return (da - db) * sortDirection;
  });

  renderList(containerId, items);
}

function toggleSort() {
  sortDirection *= -1;
  $("#sortDir").textContent = sortDirection === -1 ? "↓" : "↑";
  const activeTab = $(".tab.active")?.dataset?.tab || "incidents";
  applyFiltersAndSort(activeTab === "history" ? "historyList" : "incidentList");
}

function handleSearch(val) {
  searchText = val.trim();
  const activeTab = $(".tab.active")?.dataset?.tab || "incidents";
  applyFiltersAndSort(activeTab === "history" ? "historyList" : "incidentList");
}

// ──────────────────────────── RENDERING ────────────────────────

function esc(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

function renderList(containerId, items) {
  const container = $(`#${containerId}`);
  if (items.length === 0) {
    const filterName = activeFilter ? activeFilter : "";
    const msg = activeFilter
      ? `Нет писем с категорией ${filterName}`
      : (containerId === "incidentList" ? "Инцидентов не обнаружено ✅" : "История пуста");
    container.innerHTML = `<div class="empty-state">${msg}</div>`;
    return;
  }

  container.innerHTML = items.map((inc, idx) => {
    const badge = { MALICIOUS: "⛔", SUSPICIOUS: "⚠️", CLEAN: "✅" }[inc.status] || "❓";
    const cls = inc.status.toLowerCase();
    const reason = (inc.reasons || []).join("; ");
    // Display original message date if available, else check time
    const displayDate = new Date(inc.date || inc.checkedAt).toLocaleString("ru-RU", {
      day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit"
    });
    const showActions = inc.status !== "CLEAN";

    return `
      <div class="incident-item ${cls}" data-idx="${idx}" data-list="${containerId}">
        ${showActions ? `<label class="incident-check" onclick="event.stopPropagation()">
          <input type="checkbox" data-idx="${idx}" data-list="${containerId}" data-msg-id="${inc.messageId}" data-key="${inc.storageKey || ""}">
        </label>` : ""}
        <span class="incident-badge">${badge}</span>
        <div class="incident-body">
          <div class="incident-subject">${esc(inc.subject || "(без темы)")}</div>
          <div class="incident-reason" title="${esc(reason)}">${esc(reason)}</div>
          <div class="incident-meta">${esc(inc.author || "")} · ${displayDate} · Score: ${inc.score}${inc.autoMoved ? " · 🚀 авто-спам" : ""}</div>
        </div>
        ${showActions ? `<div class="incident-actions" onclick="event.stopPropagation()">
          <button class="act-btn" title="В спам" data-action="junk" data-idx="${idx}" data-list="${containerId}">🗑️</button>
          <button class="act-btn" title="Безопасно" data-action="safe" data-idx="${idx}" data-list="${containerId}">✅</button>
          <button class="act-btn" title="Удалить" data-action="delete" data-idx="${idx}" data-list="${containerId}">🚫</button>
        </div>` : ""}
      </div>`;
  }).join("");
}

// ──────────────────────────── DETAIL PANEL ────────────────────────

function showDetail(item, isTimeout = false) {
  currentDetailItem = item;
  const panel = $("#detailPanel");
  const content = $("#detailContent");

  const badge = { MALICIOUS: "⛔ ВРЕДОНОСНОЕ", SUSPICIOUS: "⚠️ ПОДОЗРИТЕЛЬНОЕ", CLEAN: "✅ БЕЗОПАСНОЕ" }[item.status] || item.status;
  const badgeCls = item.status.toLowerCase();
  const date = new Date(item.date || item.checkedAt).toLocaleString("ru-RU");
  const ioc = item.ioc || {};

  // Auth helpers
  const AUTH_ICON = { pass: "✅", fail: "❌", softfail: "⚠️", neutral: "➖", none: "➖", temperror: "⏳", permerror: "❓", bestguesspass: "✅" };
  const AUTH_RU   = { pass: "пройдено", fail: "провалено", softfail: "мягкий отказ", neutral: "нейтрально", none: "отсутствует", temperror: "ошибка", permerror: "ошибка", bestguesspass: "пройдено" };
  const authIcon = (s) => AUTH_ICON[s] || "➖";
  const authRu = (s) => AUTH_RU[s] || s;
  const authCls = (s) => s === "pass" || s === "bestguesspass" ? "auth-pass" : s === "fail" ? "auth-fail" : s === "softfail" ? "auth-warn" : "auth-neutral";
  function countryFlag(code) {
    if (!code || code.length !== 2) return "🌍";
    const base = 0x1F1E6;
    return String.fromCodePoint(base + code.charCodeAt(0) - 65, base + code.charCodeAt(1) - 65);
  }

  let html = `
    <h2>${esc(item.subject || "(без темы)")}</h2>
    <div class="detail-meta">${esc(item.author || "")} · ${date}</div>
    <div class="score-bar">
      <span class="score-badge ${badgeCls}">${badge}</span>
      <span style="color:#888;font-size:12px;">Score: ${item.score} / 100</span>
    </div>`;

  // Response action buttons
  if (item.status !== "CLEAN") {
    html += `<div class="detail-response-bar">
      <button class="drb-btn drb-junk" id="detailJunk">🗑️ В спам</button>
      <button class="drb-btn drb-safe" id="detailSafe">✅ Безопасно</button>
      <button class="drb-btn drb-delete" id="detailDelete">🚫 Удалить</button>
    </div>`;
    if (ioc.unsubscribe) {
      html += `<div style="background-color: rgba(231, 76, 60, 0.1); border: 1px solid #e74c3c; border-radius: 4px; padding: 8px; margin-bottom: 12px; font-size: 11px; color: #e74c3c; display: flex; flex-direction: column; gap: 4px; margin-top: 8px;">
        <div style="font-weight: bold; display: flex; align-items: center; gap: 4px;">🛡️ Отписка заблокирована</div>
        <div>Это письмо классифицировано как подозрительное или вредоносное. Отписка от спамеров подтвердит активность вашего ящика и приведет к увеличению объема спама. Рекомендуется использовать кнопку "В спам" или "Удалить".</div>
      </div>`;
    }
  } else if (ioc.unsubscribe) {
    html += `<div class="detail-response-bar" style="margin-bottom: 12px;">
      <button class="drb-btn drb-unsub" id="detailUnsubscribe" style="background-color: #3498db; color: white; border: none; padding: 8px 12px; border-radius: 4px; cursor: pointer; font-weight: bold; width: 100%; display: flex; align-items: center; justify-content: center; gap: 6px; font-size: 12px;">📭 Безопасная отписка от рассылки</button>
    </div>`;
  }

  // Always add Ask AI button
  html += `<div class="detail-response-bar" style="margin-top: 8px; margin-bottom: 12px;">
    <button class="drb-btn drb-ai" id="detailAskAi" style="background: linear-gradient(135deg, #8e44ad, #9b59b6); color: white; border: none; padding: 8px 12px; border-radius: 4px; cursor: pointer; font-weight: bold; width: 100%; display: flex; align-items: center; justify-content: center; gap: 6px; font-size: 12px;">💬 Спросить у ИИ-ассистента</button>
  </div>`;

  // Reasons
  if (item.reasons && item.reasons.length > 0) {
    html += `<div class="detail-section"><h3>🔍 Обнаруженные угрозы</h3><ul class="reason-list">`;
    for (const r of item.reasons) html += `<li>${esc(r)}</li>`;
    html += `</ul></div>`;
  }

  // IOC Section
  html += `<div class="detail-section"><h3>📋 Индикаторы компрометации (IOC)</h3>`;
  if (ioc.senderEmail) html += iocBlock("Отправитель", ioc.senderEmail);
  if (ioc.replyTo && ioc.replyTo !== ioc.senderEmail) html += iocBlock("Reply-To (отличается!)", ioc.replyTo);
  if (ioc.senderDomain) html += iocBlock("Домен отправителя", ioc.senderDomain);
  if (ioc.urls?.length) html += iocBlock("URL в письме", ioc.urls.join("\n"));
  if (ioc.shortenedUrls?.length) html += iocBlock("Сокращённые URL", ioc.shortenedUrls.join("\n"));
  if (ioc.homographDomains?.length) html += iocBlock("Homograph-домены", ioc.homographDomains.join("\n"));
  if (ioc.uncPaths?.length) html += iocBlock("UNC/SMB пути", ioc.uncPaths.join("\n"));
  if (ioc.hrefMismatches?.length) {
    const t = ioc.hrefMismatches.map((m) => `Текст: ${m.display}\nURL:   ${m.actual}`).join("\n---\n");
    html += iocBlock("Несовпадение ссылок (href)", t);
  }
  if (ioc.dangerousFiles?.length) html += iocBlock("Опасные вложения", ioc.dangerousFiles.join("\n"));
  if (ioc.doubleExtFiles?.length) html += iocBlock("Двойные расширения", ioc.doubleExtFiles.join("\n"));
  if (ioc.allAttachments?.length) html += iocBlock("Все вложения", ioc.allAttachments.join("\n"));
  html += `</div>`;

  // ── AUTHENTICATION ──
  const auth = ioc.authResults;
  if (auth) {
    html += `<div class="detail-section"><h3>🔐 Аутентификация почты</h3>
      <div class="auth-grid">
        <div class="auth-row ${authCls(auth.spf?.status)}">
          <span class="auth-label">SPF</span>
          <span>${authIcon(auth.spf?.status)} ${authRu(auth.spf?.status)}</span>
          <span class="auth-detail">${auth.spf?.domain ? `(${esc(auth.spf.domain)})` : ""}</span>
        </div>
        <div class="auth-row ${authCls(auth.dkim?.status)}">
          <span class="auth-label">DKIM</span>
          <span>${authIcon(auth.dkim?.status)} ${authRu(auth.dkim?.status)}</span>
          <span class="auth-detail">${auth.dkim?.domain ? `(${esc(auth.dkim.domain)})` : ""}</span>
        </div>
        <div class="auth-row ${authCls(auth.dmarc?.status)}">
          <span class="auth-label">DMARC</span>
          <span>${authIcon(auth.dmarc?.status)} ${authRu(auth.dmarc?.status)}</span>
          <span class="auth-detail">${auth.dmarc?.policy ? `политика: ${esc(auth.dmarc.policy)}` : ""}</span>
        </div>
      </div>
    </div>`;
  }

  // ── ROUTE (MailHops) ──
  if (ioc.route && ioc.route.length > 0) {
    const geoMap = {};
    (ioc.geoip || []).forEach(g => { geoMap[g.ip] = g; });
    html += `<div class="detail-section"><h3>🗺️ Маршрут письма</h3><div class="route-chain">`;
    for (let i = 0; i < ioc.route.length; i++) {
      const hop = ioc.route[i];
      const geo = geoMap[hop.ip];
      const flag = geo ? countryFlag(geo.countryCode) : "🌍";
      const loc = geo ? `${geo.country}, ${geo.city}` : "GeoIP недоступен";
      const isp = geo ? geo.isp : "";
      html += `<div class="route-hop">
        <div class="route-dot">${i === 0 ? "📤" : i === ioc.route.length - 1 ? "📥" : "⏺"}</div>
        <div class="route-info">
          <div class="route-ip">${esc(hop.ip)} ${flag}</div>
          <div class="route-geo">${esc(loc)}${isp ? " · " + esc(isp) : ""}</div>
        </div>
      </div>`;
      if (i < ioc.route.length - 1) html += `<div class="route-line"></div>`;
    }
    html += `</div></div>`;
  }

  // ── DEEP ANALYSIS v3.0 ──
  const deep = ioc.deepAnalysis;
  html += `<div class="detail-section"><h3>🧪 Глубокий анализ (сервер)</h3>`;
  if (deep) {
    if (deep.success === false) {
      html += `<div style="color:#e74c3c; font-size:12px; padding:8px 0; font-weight:bold;">Ошибка глубокого анализа:<br><span style="color:#aaa; font-weight:normal; font-family:monospace;">${esc(deep.error || "Неизвестная ошибка")}</span></div>`;
    } else {
      const vBadge = { malicious: "⛔ Вредоносное", suspicious: "⚠️ Подозрительное", clean: "✅ Безопасное" };
      html += `<div class="deep-summary">
        <span class="deep-verdict ${(deep.verdict || "").toLowerCase()}">${vBadge[(deep.verdict || "").toLowerCase()] || deep.verdict || "—"}</span>
        <span style="color:#888">Score: ${deep.score ?? "—"} / 100</span>
        <span style="color:#555;font-size:10px;margin-left:8px;">v${deep.version || "?"} • ${(deep.levels_completed || []).length} уровней</span>
      </div>`;

    // Reasons
    if (deep.reasons && deep.reasons.length > 0) {
      html += `<div class="ioc-block"><div class="ioc-label">🔍 Обнаруженные угрозы (${deep.reasons.length})</div>
        <ul style="margin:4px 0;padding-left:18px;font-size:12px;color:#f5c542;">`;
      for (const r of deep.reasons) html += `<li style="margin:2px 0">${esc(r)}</li>`;
      html += `</ul></div>`;
    }

    // Authentication details
    if (deep.authentication) {
      const a = deep.authentication;
      let authText = `SPF:   ${a.spf?.status || "N/A"}${a.spf?.domain ? " (" + a.spf.domain + ")" : ""}`;
      authText += `\nDKIM:  ${a.dkim?.status || "N/A"}${a.dkim?.domain ? " (" + a.dkim.domain + ")" : ""}`;
      authText += `\nDMARC: ${a.dmarc?.status || "N/A"}${a.dmarc?.policy ? " [политика: " + a.dmarc.policy + "]" : ""}`;
      html += iocBlock("🔐 Аутентификация (сервер)", authText);
    }

    // Body analysis
    if (deep.body_analysis) {
      const ba = deep.body_analysis;
      let baText = `Текст: ${ba.text_length || 0} символов`;
      if (ba.has_html) baText += `\nHTML: ${ba.html_length || 0} символов`;
      if (ba.empty_body) baText += `\n⚠️ Тело письма пустое!`;
      html += iocBlock("📝 Анализ тела", baText);
    }

    // Attachments with hashes
    if (deep.attachments && deep.attachments.length > 0) {
      const attText = deep.attachments.map(a => {
        let line = `📎 ${a.filename} (${a.content_type}, ${a.size} б)`;
        if (a.md5) line += `\n   MD5:    ${a.md5}`;
        if (a.sha256) line += `\n   SHA256: ${a.sha256}`;
        if (a.dangerous) line += `\n   ⚠️ ОПАСНОЕ РАСШИРЕНИЕ`;
        return line;
      }).join("\n\n");
      html += iocBlock("📦 Вложения и хэши", attText);
    }

    // LEVEL 4: Attachment deep analysis
    if (deep.attachment_analysis && deep.attachment_analysis.length > 0) {
      for (const aa of deep.attachment_analysis) {
        const riskCls = aa.risk_score >= 60 ? "color:#e74c3c" : aa.risk_score >= 25 ? "color:#f39c12" : "color:#2ecc71";
        let aaText = `Тип: ${aa.type.toUpperCase()} | Риск: `;
        aaText += `${aa.risk_score}/100`;
        aaText += `\n${aa.findings.join("\n")}`;
        html += `<div class="ioc-block"><div class="ioc-label">🔬 ${esc(aa.filename)} <span style="${riskCls};font-weight:700">[${aa.risk_score}]</span></div>
          <div class="ioc-value">${esc(aaText)}</div></div>`;
      }
    }

    // IOC from deep analysis
    if (deep.ioc) {
      if (deep.ioc.urls && deep.ioc.urls.length > 0) html += iocBlock("🔗 URL (сервер)", deep.ioc.urls.join("\n"));
      if (deep.ioc.domains && deep.ioc.domains.length > 0) html += iocBlock("🌐 Домены (сервер)", deep.ioc.domains.join("\n"));
      if (deep.ioc.emails && deep.ioc.emails.length > 0) html += iocBlock("📧 Email (сервер)", deep.ioc.emails.join("\n"));
      if (deep.ioc.ips && deep.ioc.ips.length > 0) html += iocBlock("🖥️ IP (сервер)", deep.ioc.ips.join("\n"));
      if (deep.ioc.suspicious_patterns && deep.ioc.suspicious_patterns.length > 0) {
        const spText = deep.ioc.suspicious_patterns.map(p =>
          typeof p === "object" ? `[${p.type}]: ${(p.matches || []).join(", ")}` : String(p)
        ).join("\n");
        html += iocBlock("⚠️ Подозрительные паттерны", spText);
      }
    }

    // LEVEL 5: Metadata, HEX & GPS carving
    if (deep.metadata_hex_analysis) {
      const metaHex = deep.metadata_hex_analysis;
      let metaHexParts = [];
      if (metaHex.hex_injections && metaHex.hex_injections.length > 0) {
        metaHexParts.push(`HEX-инъекции: ${metaHex.hex_injections.length}`);
        for (const hi of metaHex.hex_injections.slice(0, 5)) {
          metaHexParts.push(`  ${hi.raw?.slice(0, 60) || "..."} → ${hi.decoded_type || "?"}`);
        }
      }
      if (metaHex.gps_coordinates && metaHex.gps_coordinates.length > 0) {
        metaHexParts.push(`GPS-координаты: ${metaHex.gps_coordinates.length}`);
        for (const g of metaHex.gps_coordinates.slice(0, 5)) {
          metaHexParts.push(`  📍 ${g.lat}, ${g.lon}`);
        }
      }
      if (metaHex.suspicious_strings && metaHex.suspicious_strings.length > 0) {
        metaHexParts.push(`Подозрительные строки: ${metaHex.suspicious_strings.length}`);
        for (const ss of metaHex.suspicious_strings.slice(0, 5)) {
          metaHexParts.push(`  [${ss.type}] ${ss.value}`);
        }
      }
      if (metaHexParts.length > 0) {
        html += iocBlock("🔬 Карвинг метаданных, HEX и GPS", metaHexParts.join("\n"));
      }
    }

    // LEVEL 6: Carved images
    if (deep.carved_images && deep.carved_images.total_count > 0) {
      const ci = deep.carved_images;
      const typesStr = Object.entries(ci.types || {}).map(([t, c]) => `${t}: ${c}`).join(", ");
      let ciText = `Найдено: ${ci.total_count} изображений (${typesStr})`;
      if (ci.items && ci.items.length > 0) {
        for (const item of ci.items.slice(0, 10)) {
          ciText += `\n  ${item.type} @ offset ${item.offset}, ${item.size} байт, MD5: ${item.md5}`;
        }
      }
      html += iocBlock("🖼️ Карвинг изображений", ciText);
    }

    // EML file
    if (deep.eml_file) html += iocBlock("📁 Файл .eml", deep.eml_file);
    }
  } else if (isTimeout) {
    html += `<div style="color:#777; font-size:12px; padding:8px 0;">Глубокий анализ недоступен (превышено время ожидания или сервер выключен).</div>`;
  } else {
    html += `<div class="deep-loading" id="deepLoading" style="color:#f39c12; font-size:12px; padding: 8px 0; display:flex; align-items:center; gap:8px;">
      <span class="spinner" style="display:inline-block; width:12px; height:12px; border:2px solid #f39c12; border-top-color:transparent; border-radius:50%; animation:spin 1s linear infinite;"></span>
      <span>Выполняется глубокий сигнатурно-эвристический анализ (уровни 1-7)...</span>
    </div>`;
  }
  html += `</div>`;

  // Export & copy buttons
  html += `<div class="detail-actions">
    <button class="copy-all-btn" id="copyFullReport">📄 Скопировать весь отчёт</button>
    <button class="copy-all-btn" id="copyAllIoc">📋 Скопировать все IOC</button>
    <button class="copy-all-btn export-eml-btn" id="exportEml">📧 Экспорт .eml</button>
  </div>`;

  content.innerHTML = html;
  panel.style.display = "block";

  // Wire up copy/export
  $("#copyFullReport").addEventListener("click", () => {
    navigator.clipboard.writeText(buildFullReport(item)).then(() => showToast("📄 Отчёт скопирован")).catch(() => {});
  });
  $("#copyAllIoc").addEventListener("click", () => {
    navigator.clipboard.writeText(buildIocText(item)).then(() => showToast("📋 IOC скопированы")).catch(() => {});
  });
  $("#exportEml").addEventListener("click", () => exportEml(item.messageId, item.subject));

  // Wire up response actions
  async function detailAction(action) {
    let result;
    if (action === "junk") {
      result = await browser.runtime.sendMessage({ action: "moveToJunk", messageId: item.messageId });
      if (result.ok) showToast("📨 В спам");
    } else if (action === "safe") {
      result = await browser.runtime.sendMessage({ action: "markSafe", messageId: item.messageId, storageKey: item.storageKey });
      if (result.ok) showToast("✅ Безопасно");
    } else if (action === "delete") {
      result = await browser.runtime.sendMessage({ action: "deleteMessage", messageId: item.messageId });
      if (result.ok) showToast("🚫 Удалено");
    } else if (action === "unsubscribe") {
      showToast("⏳ Отправка запроса на отписку...");
      result = await browser.runtime.sendMessage({ action: "unsubscribe", messageId: item.messageId });
      if (result && result.ok) {
        showToast("✅ " + result.message);
      } else {
        showToast("❌ " + (result?.error || "Ошибка отписки"), "error");
      }
      return; // Don't hide detail immediately for unsubscribe feedback
    }
    if (result && !result.ok) showToast("❌ " + (result.error || "Ошибка"), "error");
    hideDetail();
    await refreshAll();
  }
  if ($("#detailJunk")) $("#detailJunk").addEventListener("click", () => detailAction("junk"));
  if ($("#detailSafe")) $("#detailSafe").addEventListener("click", () => detailAction("safe"));
  if ($("#detailDelete")) $("#detailDelete").addEventListener("click", () => detailAction("delete"));
  if ($("#detailUnsubscribe")) $("#detailUnsubscribe").addEventListener("click", () => detailAction("unsubscribe"));
  if ($("#detailAskAi")) $("#detailAskAi").addEventListener("click", () => initAiChat(item));

  // Start polling if deepAnalysis is missing
  if (item && item.ioc && !item.ioc.deepAnalysis && !isTimeout) {
    startPolling(item.messageId);
  } else if (item && item.ioc && item.ioc.deepAnalysis) {
    stopPolling();
  }
}

// ──────────────────────────── POLLING FOR DEEP ANALYSIS ────────────────────────

function startPolling(messageId) {
  if (pollTimeout) {
    if (currentPollingMessageId === messageId) return;
    clearTimeout(pollTimeout);
  }
  currentPollingMessageId = messageId;
  pollAttempts = 0;

  async function poll() {
    pollAttempts++;
    try {
      const response = await browser.runtime.sendMessage({ action: "getSingleAnalysis", messageId });
      if (response && response.report) {
        const item = response.report;
        const ioc = item.ioc || {};
        if (ioc.deepAnalysis) {
          stopPolling();
          showDetail(item);
        } else if (pollAttempts >= MAX_POLL_ATTEMPTS) {
          stopPolling();
          showDetail(item, true); // Render with timeout
        } else {
          pollTimeout = setTimeout(poll, 1500);
        }
      } else {
        pollTimeout = setTimeout(poll, 1500);
      }
    } catch (e) {
      console.error("Polling error:", e);
      if (pollAttempts >= MAX_POLL_ATTEMPTS) {
        stopPolling();
      } else {
        pollTimeout = setTimeout(poll, 1500);
      }
    }
  }

  pollTimeout = setTimeout(poll, 1500);
}

function stopPolling() {
  if (pollTimeout) {
    clearTimeout(pollTimeout);
    pollTimeout = null;
  }
  currentPollingMessageId = null;
}

function iocBlock(label, value) {
  const id = "ioc_" + Math.random().toString(36).slice(2, 8);
  return `<div class="ioc-block">
    <div class="ioc-label">${esc(label)}</div>
    <div class="ioc-value" id="${id}">${esc(value)}</div>
    <button class="ioc-copy" onclick="copyIoc('${id}')">📋</button>
  </div>`;
}

function buildFullReport(item) {
  const ioc = item.ioc || {};
  const deep = ioc.deepAnalysis || {};
  const auth = ioc.authResults || deep.authentication || {};
  
  const status = (item.status || "CLEAN").toUpperCase();
  const score = item.score ?? 0;
  
  let verdictBadge = "🟢 Legitimate / Clean Business Email (Легитимная корреспонденция)";
  let criticality = "Low / Informational (Низкая)";
  if (status === "MALICIOUS" || score >= 70) {
    verdictBadge = "🔴 True Positive / Malicious Spearphishing (Вредоносная целевая атака)";
    criticality = "High / Critical (Высокая / Критическая)";
  } else if (status === "SUSPICIOUS" || score >= 35) {
    verdictBadge = "🟡 Suspicious / Unsolicited Spam / EDM (Подозрительное сообщение / Спам)";
    criticality = "Medium (Средняя)";
  }
  
  const dateStr = item.date || item.checkedAt || new Date().toISOString();
  let formattedDate = dateStr;
  try {
    formattedDate = new Date(dateStr).toLocaleString("ru-RU", { timeZoneName: "short" });
  } catch (e) {}
  
  const L = [];
  L.push("# 🛡️ Комплексный отчет криминалистического анализа почтового сообщения (NIST SP 800-61r2 / SANS PICERL)");
  L.push("");
  L.push(`**Дата и время исследования:** ${formattedDate}`);
  L.push(`**Ответственный аналитик / Модуль:** Thunderbird Phishing Guard v2.4 (Security Operations)`);
  L.push(`**Исследованный объект:** \`${item.subject || "(без темы)"}\``);
  L.push(`**Финальный вердикт:** **${verdictBadge}**`);
  L.push(`**Оценка риска (Threat Score):** **${score} / 100**`);
  L.push("");
  L.push("---");
  L.push("");
  L.push("## 1. Сводные результаты и вердикты (Executive Summary)");
  L.push("");
  L.push("| Параметр анализа | Значение |");
  L.push("| :--- | :--- |");
  L.push(`| **Тема письма (Subject)** | ${item.subject || "*(отсутствует)*"} |`);
  L.push(`| **Отправитель (From)** | \`${item.author || ioc.senderEmail || "N/A"}\` |`);
  L.push(`| **Финальный вердикт** | **${status}** (Score: ${score}/100) |`);
  L.push(`| **Уровень критичности** | **${criticality}** |`);
  
  const threatsList = [...(item.reasons || []), ...(deep.reasons || [])];
  const threatSummary = threatsList.length > 0 ? threatsList.join("; ") : "Прямых угроз безопасности не обнаружено";
  L.push(`| **Выявленные аномалии / Угрозы** | ${threatSummary} |`);
  
  const allAtts = deep.attachments || (ioc.allAttachments || []).map(f => ({ filename: f, size: 0, content_type: "attachment" }));
  const attSummary = allAtts.length > 0 ? allAtts.map(a => `\`${a.filename}\``).join(", ") : "*Вложения отсутствуют*";
  L.push(`| **Вложения в сообщении** | ${attSummary} |`);
  L.push("");
  L.push("---");
  L.push("");
  L.push("## 2. Анализ заголовков и сетевой аутентификации (SPF / DKIM / DMARC)");
  L.push("");
  L.push(`* **Отправитель (From):** \`${item.author || "N/A"}\``);
  if (ioc.replyTo && ioc.replyTo !== ioc.senderEmail) {
    L.push(`* **Reply-To:** \`${ioc.replyTo}\` ⚠️ *(не совпадает с адресом отправителя)*`);
  }
  if (ioc.senderDomain) {
    L.push(`* **Домен отправителя:** \`${ioc.senderDomain}\``);
  }
  
  // SPF / DKIM / DMARC
  const spfVal = (auth.spf?.status || ioc.spf || "none").toLowerCase();
  const dkimVal = (auth.dkim?.status || ioc.dkim || "none").toLowerCase();
  const dmarcVal = (auth.dmarc?.status || ioc.dmarc || "none").toLowerCase();
  
  L.push(`* **Результаты аутентификации почтового шлюза:**`);
  L.push(`  * **SPF:** \`${spfVal}\` ${auth.spf?.domain ? `(domain: ${auth.spf.domain})` : ""}`);
  L.push(`  * **DKIM:** \`${dkimVal}\` ${auth.dkim?.domain ? `(domain: ${auth.dkim.domain})` : ""}`);
  L.push(`  * **DMARC:** \`${dmarcVal}\` ${auth.dmarc?.policy ? `[policy: ${auth.dmarc.policy}]` : ""}`);
  
  // Route
  if (ioc.route && ioc.route.length > 0) {
    L.push("");
    L.push("### Маршрут передачи сообщения (Mail Routing / Hops):");
    ioc.route.forEach((r, idx) => {
      L.push(`${idx + 1}. \`${r.ip}\` ➔ \`${r.by || "mail-gateway"}\` *(от ${r.from || "unknown"} / delay: ${r.delay || "0s"})*`);
    });
  }
  
  L.push("");
  L.push("---");
  L.push("");
  L.push("## 3. Статический и сигнатурный анализ вложений");
  L.push("");
  if (allAtts.length === 0) {
    L.push("*В исследуемом письме отсутствуют бинарные или архивированные вложения.*");
  } else {
    L.push("| Файл вложения | MIME-тип / Размер | SHA-256 / MD5 | Статус безопасности |");
    L.push("| :--- | :--- | :--- | :--- |");
    allAtts.forEach(att => {
      const sha = att.sha256 ? `\`${att.sha256}\`` : (att.md5 ? `MD5: \`${att.md5}\`` : "*N/A*");
      const isDangerous = att.dangerous || (ioc.dangerousFiles || []).includes(att.filename);
      const statusStr = isDangerous ? "🔴 **Опасное расширение**" : "🟢 Легитимный файл";
      L.push(`| **\`${att.filename}\`** | ${att.content_type || "file"} (${att.size || 0} б) | ${sha} | ${statusStr} |`);
    });
    
    if (deep.attachment_analysis && deep.attachment_analysis.length > 0) {
      L.push("");
      L.push("### Результаты детальной форензики вложений:");
      deep.attachment_analysis.forEach(aa => {
        L.push(`* 🔬 **\`${aa.filename}\`** [${(aa.type || "FILE").toUpperCase()}] (Оценка риска: **${aa.risk_score}/100**):`);
        (aa.findings || []).forEach(f => L.push(`  * ⚠️ ${f}`));
      });
    }
  }
  
  L.push("");
  L.push("---");
  L.push("");
  L.push("## 4. Анализ содержимого письма, ссылок и текста");
  L.push("");
  if (threatsList.length > 0) {
    L.push("### Зафиксированные индикаторы угроз и аномалий:");
    threatsList.forEach(t => L.push(`* ⚠️ ${t}`));
    L.push("");
  }
  
  const urls = [...(ioc.urls || []), ...(deep.ioc?.urls || [])];
  const uniqueUrls = Array.from(new Set(urls));
  if (uniqueUrls.length > 0) {
    L.push("### Извлеченные сетевые гиперссылки (URLs):");
    uniqueUrls.forEach(u => L.push(`* \`${u}\``));
  } else {
    L.push("*Внешних гиперссылок в теле письма не обнаружено.*");
  }
  
  L.push("");
  L.push("---");
  L.push("");
  L.push("## 5. Сводная таблица индикаторов компрометации (IoC)");
  L.push("");
  L.push("| Тип артефакта | Значение / Индикатор | Описание |");
  L.push("| :--- | :--- | :--- |");
  if (ioc.senderEmail) L.push(`| **Email отправителя** | \`${ioc.senderEmail}\` | Адрес почтового ящика отправителя |`);
  if (ioc.senderDomain) L.push(`| **Домен отправителя** | \`${ioc.senderDomain}\` | Доменная зона источника |`);
  if (ioc.replyTo && ioc.replyTo !== ioc.senderEmail) L.push(`| **Reply-To** | \`${ioc.replyTo}\` | Альтернативный адрес для ответа |`);
  
  if (ioc.route && ioc.route.length > 0) {
    const ips = Array.from(new Set(ioc.route.map(r => r.ip).filter(Boolean)));
    ips.forEach(ip => {
      L.push(`| **IP-адрес узла** | \`${ip}\` | Узел в цепочке доставки письма |`);
    });
  }
  
  uniqueUrls.slice(0, 15).forEach(u => {
    L.push(`| **URL / Ссылка** | \`${u}\` | Гиперссылка из тела письма |`);
  });
  
  allAtts.forEach(a => {
    if (a.sha256) L.push(`| **SHA-256** | \`${a.sha256}\` | Хэш-сигнатура файла \`${a.filename}\` |`);
    if (a.md5) L.push(`| **MD5** | \`${a.md5}\` | Хэш-сигнатура файла \`${a.filename}\` |`);
  });
  
  L.push("");
  L.push("---");
  L.push("");
  L.push("## 6. Картографирование MITRE ATT&CK");
  L.push("");
  const mitreTactics = [];
  if (status === "MALICIOUS" || status === "SUSPICIOUS" || score >= 30) {
    if (allAtts.some(a => a.dangerous || (ioc.dangerousFiles || []).includes(a.filename))) {
      mitreTactics.push("* **Initial Access:** `T1566.001` — Spearphishing Attachment (доставка потенциально опасных вложений).");
    }
    if (uniqueUrls.length > 0) {
      mitreTactics.push("* **Initial Access:** `T1566.002` — Spearphishing Link (доставка внешних URL-ссылок).");
    }
    if (threatsList.some(t => t.toLowerCase().includes("mismatch") || t.toLowerCase().includes("domain alignment"))) {
      mitreTactics.push("* **Defense Evasion:** `T1036` — Masquerading (несовпадение отображаемого домена и целевого URL).");
    }
    if (threatsList.some(t => t.toLowerCase().includes("homograph") || t.toLowerCase().includes("punycode"))) {
      mitreTactics.push("* **Defense Evasion:** `T1036.007` — Double File Extension / Homoglyph Domain.");
    }
    if (mitreTactics.length === 0) {
      mitreTactics.push("* **Initial Access:** `T1566` — Phishing (попытка доставки нежелательной корреспонденции).");
    }
  } else {
    mitreTactics.push("* *Атак или вредоносных техник по матрице MITRE ATT&CK не зафиксировано (сообщение легитимно).*");
  }
  L.push(mitreTactics.join("\n"));
  
  L.push("");
  L.push("---");
  L.push("");
  L.push("## 7. Практические рекомендации и действия по реагированию");
  L.push("");
  if (status === "MALICIOUS" || score >= 70) {
    L.push("1. **Сетевой периметр (CheckPoint / DNS):** Заблокировать выявленные IP-адреса отправителей и внешние URL/домены на сетевом шлюзе и DNS-серверах.");
    L.push("2. **Почтовый шлюз:** Добавить домен отправителя в черный список (Blacklist) и удалить аналогичные письма из почтовых ящиков пользователей.");
    L.push("3. **Конечные узлы (Endpoint):** Провести проверку рабочих станций получателей антивирусным средством KES.");
  } else if (status === "SUSPICIOUS" || score >= 35) {
    L.push("1. **Почтовый фильтр:** При необходимости настроить фильтрацию нежелательных маркетинговых рассылок (EDM/Спам).");
    L.push("2. **Пользовательский контроль:** Не переходить по сторонним ссылкам и не вводить учетные данные на непроверенных внешних ресурсах.");
  } else {
    L.push("1. **Статус:** Дополнительных мер реагирования не требуется, письмо признано безопасным.");
  }
  
  L.push("");
  L.push("---");
  L.push(`*Отчет сформирован автоматически модулем **Thunderbird Phishing Guard** в соответствии со стандартами NIST SP 800-61r2 и SANS PICERL.*`);
  
  return L.join("\n");
}

function buildIocText(item) {
  const ioc = item.ioc || {};
  const L = [];
  L.push("=== Phishing Guard IOC Report ===");
  L.push(`Subject: ${item.subject}`);
  L.push(`From: ${item.author}`);
  L.push(`Score: ${item.score} | Status: ${item.status}`);
  L.push(`Date: ${item.checkedAt}`);
  L.push("\n--- Threats ---");
  (item.reasons || []).forEach((r) => L.push(`• ${r}`));
  L.push("\n--- IOC ---");
  if (ioc.senderEmail) L.push(`Sender: ${ioc.senderEmail}`);
  if (ioc.senderDomain) L.push(`Domain: ${ioc.senderDomain}`);
  if (ioc.replyTo) L.push(`Reply-To: ${ioc.replyTo}`);
  if (ioc.urls?.length) L.push(`URLs:\n${ioc.urls.join("\n")}`);
  if (ioc.shortenedUrls?.length) L.push(`Shortened:\n${ioc.shortenedUrls.join("\n")}`);
  if (ioc.homographDomains?.length) L.push(`Homograph:\n${ioc.homographDomains.join("\n")}`);
  if (ioc.uncPaths?.length) L.push(`UNC:\n${ioc.uncPaths.join("\n")}`);
  if (ioc.dangerousFiles?.length) L.push(`Dangerous files:\n${ioc.dangerousFiles.join("\n")}`);
  if (ioc.allAttachments?.length) L.push(`Attachments:\n${ioc.allAttachments.join("\n")}`);
  if (ioc.hrefMismatches?.length) {
    L.push("Href mismatches:");
    ioc.hrefMismatches.forEach((m) => L.push(`  Display: ${m.display}\n  Actual: ${m.actual}`));
  }
  return L.join("\n");
}

async function exportEml(messageId, subject) {
  try {
    const raw = await browser.messages.getRaw(messageId);
    const safeName = (subject || "email").replace(/[^\w\s\-а-яА-ЯёЁ]/g, "").slice(0, 60).trim();
    const blob = new Blob([raw], { type: "message/rfc822" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${safeName}.eml`;
    a.click();
    URL.revokeObjectURL(url);
    showToast("📧 .eml экспортирован");
  } catch (err) {
    showToast("❌ Ошибка экспорта: " + err.message, "error");
  }
}

function hideDetail() {
  $("#detailPanel").style.display = "none";
  currentDetailItem = null;
  stopPolling();
}

window.copyIoc = function(id) {
  const el = document.getElementById(id);
  if (el) navigator.clipboard.writeText(el.textContent).then(() => showToast("📋 Скопировано")).catch(() => {});
};

// ──────────────────────────── ACTIONS ────────────────────────

function getListData(listId) {
  return listId === "incidentList" ? currentIncidents : currentHistory;
}

async function handleItemAction(action, idx, listId) {
  const item = getListData(listId)[idx];
  if (!item) return;
  let result;
  if (action === "junk") {
    result = await browser.runtime.sendMessage({ action: "moveToJunk", messageId: item.messageId });
    if (result.ok) showToast("📨 В спам");
  } else if (action === "safe") {
    result = await browser.runtime.sendMessage({ action: "markSafe", messageId: item.messageId, storageKey: item.storageKey });
    if (result.ok) showToast("✅ Безопасно");
  } else if (action === "delete") {
    result = await browser.runtime.sendMessage({ action: "deleteMessage", messageId: item.messageId });
    if (result.ok) showToast("🚫 Удалено");
  }
  if (result && !result.ok) showToast("❌ " + (result.error || "Ошибка"), "error");
  await refreshAll();
}

async function handleBulkAction(bulkType) {
  const checked = [...$$('.incident-check input:checked')];
  if (checked.length === 0) { showToast("Выберите письма чекбоксами", "error"); return; }
  const items = checked.map((cb) => ({ messageId: parseInt(cb.dataset.msgId, 10), storageKey: cb.dataset.key }));
  const result = await browser.runtime.sendMessage({ action: "bulkAction", bulkType, items });
  if (result.ok) showToast(`${items.length} писем: ${{ junk: "в спам", safe: "безопасны", delete: "удалены" }[bulkType]}`);
  await refreshAll();
}

// ──────────────────────────── BULK BAR ────────────────

function updateBulkBar() {
  const checked = [...$$('.incident-check input:checked')];
  const bar = $("#bulkBar");
  if (checked.length > 0) {
    bar.classList.add("has-selection");
    $("#bulkCount").textContent = `${checked.length} выбрано`;
  } else {
    bar.classList.remove("has-selection");
    $("#bulkCount").textContent = "Выбрать все";
  }
}

function toggleSelectAll(checked) {
  $$('.incident-check input').forEach((cb) => { cb.checked = checked; });
  updateBulkBar();
}

// ──────────────────────────── TABS ────────────────────────

function switchTab(tabName) {
  $$(".tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === tabName));
  $$(".tab-content").forEach((tc) => tc.classList.toggle("active", tc.dataset.tab === tabName));
  if (tabName === "history") loadHistory();
  else loadIncidents();
  $("#bulkBar").style.display = tabName === "incidents" ? "flex" : "none";
}

// ──────────────────────────── SCAN & EXPORT ────────────────────

async function handleScan() {
  const btn = $("#btnScan");
  btn.disabled = true;
  btn.innerHTML = '<span class="btn-icon">⏳</span> Сканирую...';
  document.body.classList.add("scanning");
  try {
    const r = await browser.runtime.sendMessage({ action: "scanNow" });
    btn.innerHTML = `<span class="btn-icon">✅</span> +${r.scannedCount || 0}`;
    await refreshAll();
  } catch { btn.innerHTML = '<span class="btn-icon">❌</span> Ошибка'; }
  finally {
    document.body.classList.remove("scanning");
    setTimeout(() => { btn.disabled = false; btn.innerHTML = '<span class="btn-icon">🔍</span> Сканировать'; }, 2000);
  }
}

function handleUnsubscribeAll() {
  const modal = $("#confirmModal");
  if (modal) {
    modal.style.display = "flex";
  }
}

async function startUnsubscribeProcess() {
  const modal = $("#confirmModal");
  if (modal) modal.style.display = "none";

  try {
    const result = await browser.runtime.sendMessage({ action: "startUnsubscribeAll" });
    if (result && result.ok) {
      $("#unsubPanel").style.display = "flex";
      $("#unsubProgressText").textContent = "Подготовка...";
      $("#unsubPercentText").textContent = "0%";
      $("#unsubProgressBar").style.width = "0%";
      $("#unsubLog").innerHTML = '<div style="color: #888;">Запуск процесса отписки...</div>';
      $("#unsubStop").style.display = "block";
      $("#unsubClose").style.display = "none";
    } else {
      showToast("❌ Ошибка запуска: " + (result?.error || "Неизвестная ошибка"), "error");
    }
  } catch (err) {
    console.error("startUnsubscribeProcess error:", err);
    showToast("❌ Ошибка: " + err.message, "error");
  }
}

async function handleExport() {
  try {
    const r = await browser.runtime.sendMessage({ action: "exportReport" });
    const blob = new Blob([JSON.stringify(r.data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `phishing_guard_report_${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
    showToast("📄 Отчёт JSON");
  } catch (err) { console.error("Export:", err); }
}

// ──────────────────────────── UTILS ────────────────────────

async function refreshAll() {
  await loadStats();
  const activeTab = $(".tab.active")?.dataset?.tab;
  if (activeTab === "history") await loadHistory();
  else await loadIncidents();
  updateBulkBar();
}

function showToast(text, type = "success") {
  const toast = $("#toast");
  toast.textContent = text;
  toast.className = `toast ${type} visible`;
  setTimeout(() => toast.classList.remove("visible"), 2200);
}

// ──────────────────────────── INIT ────────────────────────

document.addEventListener("DOMContentLoaded", () => {
  loadStats();
  loadIncidents();

  $("#btnScan").addEventListener("click", handleScan);
  if ($("#btnUnsubscribeAll")) $("#btnUnsubscribeAll").addEventListener("click", handleUnsubscribeAll);
  $("#btnExport").addEventListener("click", handleExport);
  $("#btnSortDate").addEventListener("click", toggleSort);
  $("#searchInput").addEventListener("input", (e) => handleSearch(e.target.value));

  $$(".tab").forEach((t) => t.addEventListener("click", () => switchTab(t.dataset.tab)));

  // Stat card filters
  $$(".stat-card").forEach((card) => {
    card.style.cursor = "pointer";
    card.addEventListener("click", () => {
      const filter = [...card.classList].find((c) => ["total", "clean", "suspicious", "malicious"].includes(c));
      if (filter) setFilter(filter);
    });
  });

  // Bulk
  $("#selectAll").addEventListener("change", (e) => toggleSelectAll(e.target.checked));
  $("#bulkJunk").addEventListener("click", () => handleBulkAction("junk"));
  $("#bulkSafe").addEventListener("click", () => handleBulkAction("safe"));
  $("#bulkDelete").addEventListener("click", () => handleBulkAction("delete"));

  // Detail panel
  $("#detailBack").addEventListener("click", hideDetail);
  
  // AI Chat actions
  if ($("#aiChatClose")) {
    $("#aiChatClose").addEventListener("click", () => {
      $("#aiChatPanel").style.display = "none";
      aiMessages = [];
      currentAiEmailItem = null;
    });
  }
  if ($("#aiChatSend")) {
    $("#aiChatSend").addEventListener("click", sendChatToLLM);
  }
  if ($("#aiChatInput")) {
    $("#aiChatInput").addEventListener("keypress", (e) => {
      if (e.key === "Enter") {
        sendChatToLLM();
      }
    });
  }

  $("#detailOpenInWindow").addEventListener("click", () => {
    if (currentDetailItem?.messageId) {
      browser.windows.create({
        url: browser.runtime.getURL(`popup/message.html?messageId=${currentDetailItem.messageId}`),
        type: "popup",
        width: 850,
        height: 700
      });
    }
  });
  $("#detailOpen").addEventListener("click", async () => {
    if (currentDetailItem?.messageId) {
      try { await browser.messageDisplay.open({ messageId: currentDetailItem.messageId }); }
      catch { showToast("Не удалось открыть", "error"); }
    }
  });

  // Delegate clicks
  document.addEventListener("click", (e) => {
    const actBtn = e.target.closest(".act-btn");
    if (actBtn) {
      handleItemAction(actBtn.dataset.action, parseInt(actBtn.dataset.idx, 10), actBtn.dataset.list);
      return;
    }
    const item = e.target.closest(".incident-item");
    if (item && !e.target.closest(".incident-check") && !e.target.closest(".incident-actions")) {
      const idx = parseInt(item.dataset.idx, 10);
      const data = getListData(item.dataset.list);
      if (data[idx]) {
        // Fetch fresh data with deep analysis via getSingleAnalysis
        const cached = data[idx];
        browser.runtime.sendMessage({ action: "getSingleAnalysis", messageId: cached.messageId })
          .then(resp => {
            if (resp && resp.report) showDetail(resp.report);
            else showDetail(cached); // fallback to cached
          })
          .catch(() => showDetail(cached));
      }
    }
  });

  document.addEventListener("change", (e) => {
    if (e.target.closest(".incident-check")) {
      updateBulkBar();
      const all = [...$$('.incident-check input')];
      $("#selectAll").checked = all.length > 0 && all.every((cb) => cb.checked);
    }
  });

  // Unsubscribe panel actions
  if ($("#unsubStop")) {
    $("#unsubStop").addEventListener("click", async () => {
      await browser.runtime.sendMessage({ action: "stopUnsubscribeAll" });
    });
  }
  if ($("#unsubClose")) {
    $("#unsubClose").addEventListener("click", async () => {
      $("#unsubPanel").style.display = "none";
      await browser.runtime.sendMessage({ action: "resetUnsubscribeState" });
      await refreshAll();
    });
  }

  // Custom modal actions
  if ($("#confirmYes")) {
    $("#confirmYes").addEventListener("click", startUnsubscribeProcess);
  }
  if ($("#confirmNo")) {
    $("#confirmNo").addEventListener("click", () => {
      const modal = $("#confirmModal");
      if (modal) modal.style.display = "none";
    });
  }

  // Check if unsubscription is already running or has results
  browser.runtime.sendMessage({ action: "getUnsubscribeState" }).then((response) => {
    if (response && response.state && (response.state.running || response.state.log.length > 0)) {
      updateUnsubscribeProgressUI(response.state);
    }
  }).catch(err => console.error("Error getting unsubscribe state:", err));
});

function updateUnsubscribeProgressUI(state) {
  if (!state) return;

  const panel = $("#unsubPanel");
  if (!panel) return;

  if (panel.style.display !== "flex") {
    panel.style.display = "flex";
  }

  const progressText = $("#unsubProgressText");
  const percentText = $("#unsubPercentText");
  const progressBar = $("#unsubProgressBar");

  if (state.running) {
    progressText.textContent = `Обработка: ${state.current} из ${state.total}`;
    const pct = state.total > 0 ? Math.round((state.current / state.total) * 100) : 0;
    percentText.textContent = `${pct}%`;
    progressBar.style.width = `${pct}%`;
    $("#unsubStop").style.display = "block";
    $("#unsubClose").style.display = "none";
  } else {
    progressText.textContent = "Завершено";
    percentText.textContent = "100%";
    progressBar.style.width = "100%";
    $("#unsubStop").style.display = "none";
    $("#unsubClose").style.display = "block";
  }

  const logDiv = $("#unsubLog");
  if (logDiv) {
    logDiv.innerHTML = state.log.map(item => {
      let color = "#ccc";
      if (item.type === "success") color = "#2ecc71";
      else if (item.type === "warn") color = "#f1c40f";
      else if (item.type === "error") color = "#e74c3c";
      
      const textEscaped = item.text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");
      return `<div style="color: ${color}; margin-bottom: 3px;">${textEscaped}</div>`;
    }).join("");
    
    logDiv.scrollTop = logDiv.scrollHeight;
  }
}

browser.runtime.onMessage.addListener((request) => {
  if (request.action === "unsubProgressUpdate") {
    updateUnsubscribeProgressUI(request.state);
  }
});

// ──────────────────────────── AI CHAT ASSISTANT ────────────────────────

let aiMessages = [];
let currentAiEmailItem = null;

const AI_TOOLS = [
  {
    type: "function",
    function: {
      name: "list_session_files",
      description: "Получить список всех файлов в текущей сессии анализа (включая EML-файл письма и все извлеченные из него вложения).",
      parameters: {
        type: "object",
        properties: {}
      }
    }
  },
  {
    type: "function",
    function: {
      name: "read_playbook",
      description: "Прочитать содержимое одного из плейбуков или инструкций из папки Docs проекта.",
      parameters: {
        type: "object",
        properties: {
          playbook_name: {
            type: "string",
            description: "Имя файла плейбука (например, 'ИНСТРУКЦИЯ_АНАЛИЗ_ПИСЕМ.md' или 'METHODOLOGY.md').",
            enum: ["ИНСТРУКЦИЯ_АНАЛИЗ_ПИСЕМ.md", "METHODOLOGY.md", "ТЗ_Office_Macro_Security_Analyzer.md"]
          }
        },
        required: ["playbook_name"]
      }
    }
  },
  {
    type: "function",
    function: {
      name: "execute_project_script",
      description: "Запустить один из Python-скриптов анализа проекта на выбранном файле из текущей сессии.",
      parameters: {
        type: "object",
        properties: {
          script_name: {
            type: "string",
            description: "Имя скрипта для запуска.",
            enum: ["full_doc_scan.py", "metadata_hex_scanner.py", "carve_images.py", "analyze_threats.py"]
          },
          file_name: {
            type: "string",
            description: "Имя файла из сессии для анализа (например, 'message.eml' или имя вложения)."
          }
        },
        required: ["script_name", "file_name"]
      }
    }
  }
];

async function getActiveModel() {
  try {
    const response = await fetch("http://localhost:1234/v1/models");
    if (response.ok) {
      const data = await response.json();
      if (data && data.data && data.data.length > 0) {
        return data.data[0].id;
      }
    }
  } catch (err) {
    console.warn("Failed to fetch active model from LM Studio:", err);
  }
  return "Локальная модель";
}

async function initAiChat(item, fallbackMessageId = null) {
  currentAiEmailItem = item;
  aiMessages = [];
  
  const panel = $("#aiChatPanel");
  if (!panel) return;
  panel.style.display = "flex";
  
  const history = $("#aiChatHistory");
  history.innerHTML = "";
  
  const modelSpan = $("#aiModelName");
  modelSpan.textContent = "определение модели...";
  
  // Try to get active model
  const modelName = await getActiveModel();
  modelSpan.textContent = `(${modelName})`;
  
  appendAiChatMessage("system", "⏳ Подготовка сессии ИИ (извлечение вложений и сохранение EML)...");
  
  const targetMsgId = item?.messageId || fallbackMessageId;
  try {
    const resp = await browser.runtime.sendMessage({ action: "prepare_ai_session", messageId: targetMsgId });
    if (resp && resp.ok) {
      // Clear the loading message
      history.innerHTML = "";
      
      // Add initial greeting
      const filesList = resp.files && resp.files.length > 0 
        ? "\n\n**Доступные файлы для анализа:**\n" + resp.files.map(f => `- \`${f.name}\` (${f.size} байт)`).join("\n")
        : "";
        
      appendAiChatMessage("assistant", `Привет! Я ваш локальный ИИ-ассистент по безопасности. 🛡️\n\nЯ готов проанализировать это письмо и вложения с помощью плейбуков и скриптов проекта.\n\nТема письма: **${item.subject || "(без темы)"}**\nОтправитель: \`${item.author || ""}\`${filesList}\n\nВы можете попросить меня запустить скрипты анализа (например, \`full_doc_scan.py\`, \`metadata_hex_scanner.py\`, \`carve_images.py\`) или задать любые уточняющие вопросы по письму.`);
      
      // Initialize system prompt in conversation history
      aiMessages = [
        {
          role: "system",
          content: `Вы — профессиональный ИИ-ассистент по кибербезопасности и анализу фишинга для расширения "Phishing Guard" в почтовом клиенте Thunderbird.
Ваша цель — помогать аналитику исследовать подозрительные электронные письма и вложения.
Вы работаете локально на компьютере пользователя и имеете доступ к инструментам для автоматического запуска скриптов анализа и чтения плейбуков/инструкций.

Текущее анализируемое письмо:
Тема: ${item.subject || "(без темы)"}
Отправитель: ${item.author || ""}
Дата: ${item.date || ""}
Score: ${item.score || 0}
Вердикт: ${item.status || "CLEAN"}

Всегда отвечайте на русском языке. Будьте точны, профессиональны и следуйте инструкциям из плейбуков проекта. При анализе результатов скриптов объясняйте технические детали понятным языком, выделяя красные флаги и угрозы.`
        }
      ];
    } else {
      appendAiChatMessage("error", "Ошибка при подготовке сессии ИИ: " + (resp.error || "Неизвестная ошибка"));
    }
  } catch (err) {
    appendAiChatMessage("error", "Не удалось подготовить сессию ИИ: " + err.message);
  }
}

function appendAiChatMessage(role, text) {
  const history = $("#aiChatHistory");
  if (!history) return;
  
  const bubble = document.createElement("div");
  bubble.className = "ai-msg-bubble";
  
  if (role === "user") {
    bubble.classList.add("ai-user-msg");
  } else if (role === "assistant") {
    bubble.classList.add("ai-assistant-msg");
  } else if (role === "system") {
    bubble.classList.add("ai-system-msg");
  } else if (role === "error") {
    bubble.classList.add("ai-error-msg");
  } else if (role === "tool") {
    bubble.classList.add("ai-tool-call-msg");
  }
  
  // Basic markdown rendering for bold, inline code, and lists
  let html = text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>")
    .replace(/\*(.*?)\*/g, "<em>$1</em>")
    .replace(/`(.*?)`/g, "<code>$1</code>")
    .replace(/\n/g, "<br>");
    
  bubble.innerHTML = html;
  history.appendChild(bubble);
  history.scrollTop = history.scrollHeight;
}

async function sendChatToLLM() {
  const input = $("#aiChatInput");
  const sendBtn = $("#aiChatSend");
  if (!input || !sendBtn) return;
  
  const userText = input.value.trim();
  if (!userText) return;
  
  // Append user message
  appendAiChatMessage("user", userText);
  aiMessages.push({ role: "user", content: userText });
  
  input.value = "";
  input.disabled = true;
  sendBtn.disabled = true;
  
  // Append temporary loading message
  appendAiChatMessage("system", "ИИ думает...");
  const history = $("#aiChatHistory");
  const loadingBubble = history.lastChild;
  
  try {
    await runLLMCompletionLoop(loadingBubble);
  } catch (err) {
    if (loadingBubble) loadingBubble.remove();
    appendAiChatMessage("error", "Ошибка при запросе к ИИ: " + err.message);
    input.disabled = false;
    sendBtn.disabled = false;
  }
}

async function runLLMCompletionLoop(loadingBubble) {
  const modelName = await getActiveModel();
  
  const requestBody = {
    model: modelName,
    messages: aiMessages,
    tools: AI_TOOLS,
    tool_choice: "auto"
  };
  
  const response = await fetch("http://localhost:1234/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(requestBody)
  });
  
  if (!response.ok) {
    throw new Error(`LM Studio вернул статус ${response.status}`);
  }
  
  const data = await response.json();
  if (loadingBubble) loadingBubble.remove();
  
  const choice = data.choices && data.choices[0];
  if (!choice) {
    throw new Error("Пустой ответ от LM Studio");
  }
  
  const assistantMessage = choice.message;
  
  // Add assistant message to history array
  aiMessages.push(assistantMessage);
  
  // Case 1: Assistant wants to call tools
  if (assistantMessage.tool_calls && assistantMessage.tool_calls.length > 0) {
    for (const toolCall of assistantMessage.tool_calls) {
      const func = toolCall.function;
      const args = JSON.parse(func.arguments || "{}");
      
      appendAiChatMessage("tool", `⚙️ ИИ вызывает инструмент: ${func.name}(${JSON.stringify(args)})`);
      
      // Execute tool via background script
      try {
        const toolResult = await browser.runtime.sendMessage({
          action: "execute_tool",
          tool: func.name,
          arguments: args
        });
        
        // Append tool result to messages
        aiMessages.push({
          role: "tool",
          tool_call_id: toolCall.id,
          name: func.name,
          content: JSON.stringify(toolResult)
        });
        
        appendAiChatMessage("system", `📥 Получен результат от ${func.name}`);
      } catch (toolErr) {
        aiMessages.push({
          role: "tool",
          tool_call_id: toolCall.id,
          name: func.name,
          content: JSON.stringify({ error: toolErr.message })
        });
        appendAiChatMessage("error", `Ошибка выполнения ${func.name}: ${toolErr.message}`);
      }
    }
    
    // Re-append loading bubble and continue loop
    appendAiChatMessage("system", "ИИ анализирует результаты...");
    const history = $("#aiChatHistory");
    const newLoadingBubble = history.lastChild;
    await runLLMCompletionLoop(newLoadingBubble);
  } 
  // Case 2: Assistant responded with text
  else if (assistantMessage.content) {
    appendAiChatMessage("assistant", assistantMessage.content);
    $("#aiChatInput").disabled = false;
    $("#aiChatSend").disabled = false;
    $("#aiChatInput").focus();
  } else {
    // Fallback if no content and no tool calls
    appendAiChatMessage("assistant", "(пустой ответ)");
    $("#aiChatInput").disabled = false;
    $("#aiChatSend").disabled = false;
  }
}
