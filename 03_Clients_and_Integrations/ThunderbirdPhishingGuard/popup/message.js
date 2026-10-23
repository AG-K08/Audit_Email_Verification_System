const $ = (q) => document.querySelector(q);

let aiMessages = [];
let currentAiEmailItem = null;
let activeMessage = null;

function esc(text) {
  const d = document.createElement("div");
  d.textContent = text;
  return d.innerHTML;
}

function iocBlock(title, content) {
  const id = "ioc_" + Math.random().toString(36).slice(2, 8);
  return `<div class="ioc-block">
    <div class="ioc-label">${title}</div>
    <div class="ioc-value" id="${id}">${esc(content)}</div>
    <button class="ioc-copy" data-target="${id}" onclick="navigator.clipboard.writeText(document.getElementById('${id}').textContent).then(()=>this.textContent='✓').catch(()=>{})">копир.</button>
  </div>`;
}

// ─────────────── STATUS HELPERS ───────────────

const STATUS_ICON = { pass: "✅", fail: "❌", softfail: "⚠️", neutral: "➖", none: "➖", temperror: "⏳", permerror: "❓", bestguesspass: "✅" };
const STATUS_CLS  = { pass: "auth-pass", fail: "auth-fail", softfail: "auth-warn", neutral: "auth-neutral", none: "auth-neutral" };
const STATUS_RU   = { pass: "пройдено", fail: "провалено", softfail: "мягкий отказ", neutral: "нейтрально", none: "отсутствует", temperror: "временная ошибка", permerror: "постоянная ошибка", bestguesspass: "пройдено (предположительно)" };

function authIcon(st) { return STATUS_ICON[st] || "➖"; }
function authCls(st)  { return STATUS_CLS[st]  || "auth-neutral"; }
function authRu(st)   { return STATUS_RU[st]   || st; }

// ─────────────── COUNTRY FLAG ───────────────

function countryFlag(code) {
  if (!code || code.length !== 2) return "🌍";
  const base = 0x1F1E6;
  return String.fromCodePoint(base + code.charCodeAt(0) - 65, base + code.charCodeAt(1) - 65);
}

// ─────────────── NIST SP 800-61r2 / SANS PICERL MARKDOWN REPORT ───────────────

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
  const lines = [`[ Phishing Guard — Отчёт IOC ]`];
  if (item.subject) lines.push(`Тема: ${item.subject}`);
  if (item.author) lines.push(`Отправитель: ${item.author}`);
  if (item.date || item.checkedAt) lines.push(`Дата: ${item.date || item.checkedAt}`);
  lines.push(`Вердикт: ${item.status}`, `Score: ${item.score}`, ``);
  const ioc = item.ioc || {};
  if (ioc.senderEmail) lines.push(`[Email отправителя]\n${ioc.senderEmail}\n`);
  if (ioc.senderDomain) lines.push(`[Домен отправителя]\n${ioc.senderDomain}\n`);
  if (ioc.urls?.length) lines.push(`[URL]\n${ioc.urls.join("\n")}\n`);
  if (ioc.shortenedUrls?.length) lines.push(`[Сокращённые URL]\n${ioc.shortenedUrls.join("\n")}\n`);
  if (ioc.allAttachments?.length) lines.push(`[Вложения]\n${ioc.allAttachments.join("\n")}\n`);
  if (ioc.authResults) {
    const a = ioc.authResults;
    lines.push(`[Аутентификация]`);
    lines.push(`SPF: ${a.spf?.status || "none"} (${a.spf?.domain || ""})`);
    lines.push(`DKIM: ${a.dkim?.status || "none"} (${a.dkim?.domain || ""})`);
    lines.push(`DMARC: ${a.dmarc?.status || "none"} (${a.dmarc?.policy || ""})\n`);
  }
  if (ioc.route?.length) {
    lines.push(`[Маршрут письма]`);
    const geoMap = {};
    (ioc.geoip || []).forEach(g => { geoMap[g.ip] = g; });
    for (const h of ioc.route) {
      const geo = geoMap[h.ip];
      lines.push(`${h.ip} → ${geo ? `${geo.country}, ${geo.city} (${geo.isp})` : "GeoIP н/д"}`);
    }
    lines.push("");
  }
  return lines.join("\n");
}

async function exportEml(messageId, subject) {
  try {
    const raw = await browser.messages.getRaw(messageId);
    const blob = new Blob([raw], { type: "message/rfc822" });
    const url = URL.createObjectURL(blob);
    const safeSubj = (subject || "email").replace(/[^a-z0-9_-]/gi, "_").substring(0, 50);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${safeSubj}.eml`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (err) {
    alert("Ошибка экспорта: " + err);
  }
}

// ─────────────── RENDER ───────────────

async function renderDetail(item, isTimeout = false) {
  const content = $("#detailContent");
  $("#loading").style.display = "none";

  if (!item) {
    content.innerHTML = `<div style="text-align:center; padding: 20px; color:#aaa;">Письмо не найдено в базе Phishing Guard.<br>Возможно, оно ещё не проанализировано.</div>`;
    return;
  }

  const ioc = item.ioc || {};
  const deep = ioc.deepAnalysis || {};
  const auth = ioc.authResults || deep.authentication || {};

  const status = (item.status || "CLEAN").toUpperCase();
  const score = item.score ?? 0;
  
  let verdictBadge = "🟢 Legitimate / Clean Business Email (Легитимная корреспонденция)";
  let criticality = "Low / Informational (Низкая)";
  let badgeCls = "clean";
  if (status === "MALICIOUS" || score >= 70) {
    verdictBadge = "🔴 True Positive / Malicious Spearphishing (Вредоносная целевая атака)";
    criticality = "High / Critical (Высокая / Критическая)";
    badgeCls = "malicious";
  } else if (status === "SUSPICIOUS" || score >= 35) {
    verdictBadge = "🟡 Suspicious / Unsolicited Spam / EDM (Подозрительное сообщение / Спам)";
    criticality = "Medium (Средняя)";
    badgeCls = "suspicious";
  }

  const dateStr = item.date || item.checkedAt || new Date().toISOString();
  let formattedDate = dateStr;
  try {
    formattedDate = new Date(dateStr).toLocaleString("ru-RU", { timeZoneName: "short" });
  } catch (e) {}

  const threatsList = [...(item.reasons || []), ...(deep.reasons || [])];
  const allAtts = deep.attachments || (ioc.allAttachments || []).map(f => ({ filename: f, size: 0, content_type: "attachment" }));
  const urls = [...(ioc.urls || []), ...(deep.ioc?.urls || [])];
  const uniqueUrls = Array.from(new Set(urls));

  // ── HTML REPORT CONTAINER ──
  let html = `
    <div style="margin-bottom: 12px;">
      <h2 style="font-size: 15px; font-weight: 700; color: #fff; margin-bottom: 4px;">${esc(item.subject || "(без темы)")}</h2>
      <div style="font-size: 11px; color: #888;">${esc(item.author || "")} · ${formattedDate}</div>
      <div style="margin-top: 6px; display: flex; align-items: center; gap: 8px;">
        <span class="nist-badge ${badgeCls}">${verdictBadge}</span>
        <span style="font-size: 11px; color: #aaa; font-weight: 600;">Score: ${score} / 100</span>
      </div>
    </div>`;

  // ── RESPONSE & AI ACTIONS ──
  if (item.status !== "CLEAN") {
    html += `<div class="detail-response-bar">
      <button class="drb-btn drb-junk" id="detailJunk">🗑️ В спам</button>
      <button class="drb-btn drb-safe" id="detailSafe">✅ Безопасно</button>
      <button class="drb-btn drb-delete" id="detailDelete">🚫 Удалить</button>
    </div>`;
  } else if (ioc.unsubscribe) {
    html += `<div class="detail-response-bar" style="margin-bottom: 10px;">
      <button class="drb-btn drb-unsub" id="detailUnsubscribe" style="background-color: #3498db; color: white; border: none; padding: 8px 12px; border-radius: 4px; cursor: pointer; font-weight: bold; width: 100%; display: flex; align-items: center; justify-content: center; gap: 6px; font-size: 12px;">📭 Безопасная отписка от рассылки</button>
    </div>`;
  }

  html += `<div class="detail-response-bar" style="margin-top: 6px; margin-bottom: 14px;">
    <button class="drb-btn drb-ai" id="detailAskAi" style="background: linear-gradient(135deg, #8e44ad, #9b59b6); color: white; border: none; padding: 8px 12px; border-radius: 6px; cursor: pointer; font-weight: bold; width: 100%; display: flex; align-items: center; justify-content: center; gap: 6px; font-size: 12px; box-shadow: 0 2px 8px rgba(142, 68, 173, 0.3);">💬 Спросить у ИИ-ассистента</button>
  </div>`;

  // ── 1. EXECUTIVE SUMMARY TABLE ──
  html += `<div class="nist-section">
    <h3>📊 1. Сводные результаты и вердикты (Executive Summary)</h3>
    <table class="nist-table">
      <tr><th style="width: 35%;">Параметр анализа</th><th>Значение</th></tr>
      <tr><td><strong>Тема письма</strong></td><td>${esc(item.subject || "—")}</td></tr>
      <tr><td><strong>Отправитель</strong></td><td><span class="nist-code">${esc(item.author || ioc.senderEmail || "—")}</span></td></tr>
      <tr><td><strong>Финальный вердикт</strong></td><td><span class="nist-badge ${badgeCls}">${esc(status)}</span> (Score: ${score}/100)</td></tr>
      <tr><td><strong>Уровень критичности</strong></td><td>${esc(criticality)}</td></tr>
      <tr><td><strong>Выявленные аномалии</strong></td><td>${threatsList.length > 0 ? threatsList.map(t => `⚠️ ${esc(t)}`).join("<br>") : "Прямых угроз безопасности не обнаружено"}</td></tr>
      <tr><td><strong>Вложения в письме</strong></td><td>${allAtts.length > 0 ? allAtts.map(a => `<span class="nist-code">${esc(a.filename)}</span>`).join("<br>") : "<em>Вложения отсутствуют</em>"}</td></tr>
    </table>
  </div>`;

  // ── 2. АУТЕНТИФИКАЦИЯ И МАРШРУТ (SPF / DKIM / DMARC) ──
  const spfVal = (auth.spf?.status || ioc.spf || "none").toLowerCase();
  const dkimVal = (auth.dkim?.status || ioc.dkim || "none").toLowerCase();
  const dmarcVal = (auth.dmarc?.status || ioc.dmarc || "none").toLowerCase();

  html += `<div class="nist-section">
    <h3>🔐 2. Анализ заголовков и сетевой аутентификации</h3>
    <div class="auth-grid" style="margin-bottom: 10px;">
      <div class="auth-row ${authCls(spfVal)}">
        <span class="auth-label">SPF</span>
        <span>${authIcon(spfVal)} ${authRu(spfVal)}</span>
        <span class="auth-detail">${auth.spf?.domain ? `(${esc(auth.spf.domain)})` : (ioc.senderDomain ? `(${esc(ioc.senderDomain)})` : "")}</span>
      </div>
      <div class="auth-row ${authCls(dkimVal)}">
        <span class="auth-label">DKIM</span>
        <span>${authIcon(dkimVal)} ${authRu(dkimVal)}</span>
        <span class="auth-detail">${auth.dkim?.domain ? `(${esc(auth.dkim.domain)})` : ""}</span>
      </div>
      <div class="auth-row ${authCls(dmarcVal)}">
        <span class="auth-label">DMARC</span>
        <span>${authIcon(dmarcVal)} ${authRu(dmarcVal)}</span>
        <span class="auth-detail">${auth.dmarc?.policy ? `политика: ${esc(auth.dmarc.policy)}` : ""}</span>
      </div>
    </div>`;

  if (ioc.route && ioc.route.length > 0) {
    const geoMap = {};
    (ioc.geoip || []).forEach(g => { geoMap[g.ip] = g; });
    html += `<div style="font-size: 11px; font-weight: 700; color: #ccc; margin: 8px 0 4px;">Маршрут передачи сообщения (Mail Routing / Hops):</div><div class="route-chain">`;
    for (let i = 0; i < ioc.route.length; i++) {
      const hop = ioc.route[i];
      const geo = geoMap[hop.ip];
      const flag = geo ? countryFlag(geo.countryCode) : "🌍";
      const loc = geo ? `${geo.country}, ${geo.city}` : "GeoIP н/д";
      html += `<div class="route-hop">
        <div class="route-dot">${i === 0 ? "📤" : i === ioc.route.length - 1 ? "📥" : "⏺"}</div>
        <div class="route-info">
          <div class="route-ip"><span class="nist-code">${esc(hop.ip)}</span> ${flag} ${esc(loc)}</div>
          <div class="route-host">${hop.from ? esc(hop.from) : ""} → ${hop.by ? esc(hop.by) : "?"}</div>
        </div>
      </div>`;
      if (i < ioc.route.length - 1) html += `<div class="route-line"></div>`;
    }
    html += `</div>`;
  }
  html += `</div>`;

  // ── 3. СТАТИЧЕСКИЙ И СИГНАТУРНЫЙ АНАЛИЗ ВЛОЖЕНИЙ ──
  html += `<div class="nist-section">
    <h3>📦 3. Статический и сигнатурный анализ вложений</h3>`;
  if (allAtts.length === 0) {
    html += `<div style="color:#aaa; font-size:12px;">В исследуемом письме отсутствуют бинарные или архивированные вложения.</div>`;
  } else {
    html += `<table class="nist-table">
      <tr><th>Файл вложения</th><th>Тип / Размер</th><th>SHA-256 / MD5</th><th>Статус</th></tr>`;
    allAtts.forEach(att => {
      const isDangerous = att.dangerous || (ioc.dangerousFiles || []).includes(att.filename);
      const stBadge = isDangerous ? `<span class="nist-badge malicious">Опасное</span>` : `<span class="nist-badge clean">Легитимный</span>`;
      const hashStr = att.sha256 ? `<span class="nist-code" style="font-size:10px;">${esc(att.sha256)}</span>` : (att.md5 ? `<span class="nist-code" style="font-size:10px;">MD5: ${esc(att.md5)}</span>` : "—");
      html += `<tr>
        <td><strong>${esc(att.filename)}</strong></td>
        <td>${esc(att.content_type || "attachment")}<br><span style="color:#888;font-size:11px;">${att.size || 0} байт</span></td>
        <td>${hashStr}</td>
        <td>${stBadge}</td>
      </tr>`;
    });
    html += `</table>`;

    if (deep.attachment_analysis && deep.attachment_analysis.length > 0) {
      html += `<div style="font-size: 11px; font-weight: 700; color: #f5c542; margin-top: 8px;">🔬 Детальные находки анализаторов вложений:</div>`;
      deep.attachment_analysis.forEach(aa => {
        html += `<div style="margin: 4px 0; font-size: 12px;">
          <strong>${esc(aa.filename)}</strong> [${esc(aa.type)}] (Риск: ${aa.risk_score}/100)
          <ul style="margin: 2px 0 6px 18px; color: #f39c12;">
            ${(aa.findings || []).map(f => `<li>${esc(f)}</li>`).join("")}
          </ul>
        </div>`;
      });
    }
  }
  html += `</div>`;

  // ── 4. АНАЛИЗ СОДЕРЖИМОГО, ССЫЛОК И ТЕКСТА ──
  html += `<div class="nist-section">
    <h3>🔍 4. Анализ содержимого письма, ссылок и текста</h3>`;
  if (threatsList.length > 0) {
    html += `<div style="font-size: 11px; font-weight: 700; color: #e74c3c; margin-bottom: 4px;">Зафиксированные угрозы и аномалии:</div>
    <ul style="margin: 0 0 10px 18px; color: #ff6b6b; font-size: 12px;">
      ${threatsList.map(t => `<li style="margin: 2px 0;">${esc(t)}</li>`).join("")}
    </ul>`;
  }
  if (uniqueUrls.length > 0) {
    html += `<div style="font-size: 11px; font-weight: 700; color: #ccc; margin-bottom: 4px;">Извлеченные сетевые гиперссылки (URLs):</div>`;
    uniqueUrls.slice(0, 10).forEach(u => {
      html += `<div style="margin: 3px 0;"><span class="nist-code">${esc(u)}</span></div>`;
    });
    if (uniqueUrls.length > 10) {
      html += `<div style="color: #888; font-size: 11px; margin-top: 4px;">...и ещё ${uniqueUrls.length - 10} ссылок</div>`;
    }
  } else {
    html += `<div style="color:#aaa; font-size:12px;">Внешних гиперссылок в теле письма не обнаружено.</div>`;
  }
  html += `</div>`;

  // ── 5. СВОДНАЯ ТАБЛИЦА IOC ──
  html += `<div class="nist-section">
    <h3>📋 5. Сводная таблица индикаторов компрометации (IoC)</h3>
    <table class="nist-table">
      <tr><th>Тип артефакта</th><th>Значение</th><th>Действие</th></tr>`;
  if (ioc.senderEmail) {
    html += `<tr><td><strong>Email отправителя</strong></td><td><span class="nist-code">${esc(ioc.senderEmail)}</span></td><td><button class="ioc-copy" onclick="navigator.clipboard.writeText('${esc(ioc.senderEmail)}').then(()=>this.textContent='✓')">копир.</button></td></tr>`;
  }
  if (ioc.senderDomain) {
    html += `<tr><td><strong>Домен отправителя</strong></td><td><span class="nist-code">${esc(ioc.senderDomain)}</span></td><td><button class="ioc-copy" onclick="navigator.clipboard.writeText('${esc(ioc.senderDomain)}').then(()=>this.textContent='✓')">копир.</button></td></tr>`;
  }
  if (ioc.route && ioc.route.length > 0) {
    const ips = Array.from(new Set(ioc.route.map(r => r.ip).filter(Boolean)));
    ips.forEach((ip, idx) => {
      html += `<tr><td><strong>IP узла #${idx+1}</strong></td><td><span class="nist-code">${esc(ip)}</span></td><td><button class="ioc-copy" onclick="navigator.clipboard.writeText('${esc(ip)}').then(()=>this.textContent='✓')">копир.</button></td></tr>`;
    });
  }
  uniqueUrls.slice(0, 5).forEach((u, idx) => {
    html += `<tr><td><strong>URL #${idx+1}</strong></td><td><span class="nist-code" style="font-size:10px;">${esc(u)}</span></td><td><button class="ioc-copy" onclick="navigator.clipboard.writeText('${esc(u)}').then(()=>this.textContent='✓')">копир.</button></td></tr>`;
  });
  allAtts.forEach(a => {
    if (a.sha256) {
      html += `<tr><td><strong>SHA-256 (${esc(a.filename)})</strong></td><td><span class="nist-code" style="font-size:10px;">${esc(a.sha256)}</span></td><td><button class="ioc-copy" onclick="navigator.clipboard.writeText('${esc(a.sha256)}').then(()=>this.textContent='✓')">копир.</button></td></tr>`;
    }
  });
  html += `</table></div>`;

  // ── 6. MITRE ATT&CK ──
  html += `<div class="nist-section">
    <h3>🎯 6. Картографирование MITRE ATT&CK</h3>`;
  if (status === "MALICIOUS" || status === "SUSPICIOUS" || score >= 30) {
    if (allAtts.some(a => a.dangerous || (ioc.dangerousFiles || []).includes(a.filename))) {
      html += `<div class="mitre-item"><strong>Initial Access:</strong> <code>T1566.001</code> — Spearphishing Attachment</div>`;
    }
    if (uniqueUrls.length > 0) {
      html += `<div class="mitre-item"><strong>Initial Access:</strong> <code>T1566.002</code> — Spearphishing Link</div>`;
    }
    if (threatsList.some(t => t.toLowerCase().includes("mismatch") || t.toLowerCase().includes("domain alignment"))) {
      html += `<div class="mitre-item"><strong>Defense Evasion:</strong> <code>T1036</code> — Masquerading (Domain Alignment Mismatch)</div>`;
    }
    if (threatsList.some(t => t.toLowerCase().includes("homograph") || t.toLowerCase().includes("punycode"))) {
      html += `<div class="mitre-item"><strong>Defense Evasion:</strong> <code>T1036.007</code> — Homoglyph / Punycode Domain</div>`;
    }
  } else {
    html += `<div style="color:#aaa; font-size:12px;">Атак или вредоносных техник по матрице MITRE ATT&CK не зафиксировано.</div>`;
  }
  html += `</div>`;

  // ── 7. РЕКОМЕНДАЦИИ ПО РЕАГИРОВАНИЮ ──
  html += `<div class="nist-section">
    <h3>🛡️ 7. Практические рекомендации и реагирование</h3>`;
  if (status === "MALICIOUS" || score >= 70) {
    html += `
      <div class="rec-item">1. <strong>Сетевой периметр (CheckPoint / DNS):</strong> Заблокировать IP отправителя и внешние URL на шлюзе и DNS.</div>
      <div class="rec-item">2. <strong>Почтовый шлюз:</strong> Добавить домен отправителя в черный список (Blacklist) и удалить аналогичные письма.</div>
      <div class="rec-item">3. <strong>Конечные узлы:</strong> Провести внеплановое сканирование рабочей станции антивирусом KES.</div>`;
  } else if (status === "SUSPICIOUS" || score >= 35) {
    html += `
      <div class="rec-item">1. <strong>Почтовый фильтр:</strong> Настроить правила фильтрации для спам-маркетинга при необходимости.</div>
      <div class="rec-item">2. <strong>Контроль:</strong> Не переходить по сторонним ссылкам и не вводить корпоративные учетные данные.</div>`;
  } else {
    html += `<div class="rec-item">✅ Дополнительных мер реагирования не требуется, письмо безопасно.</div>`;
  }
  html += `</div>`;

  // ── EXPORT ACTIONS ──
  html += `<div class="detail-actions" style="margin-top: 14px;">
    <button class="copy-all-btn" id="copyFullReport">📄 Скопировать весь отчёт (Markdown)</button>
    <button class="copy-all-btn" id="copyAllIoc">📋 Скопировать все IOC</button>
    <button class="copy-all-btn export-eml-btn" id="exportEml">📧 Экспорт .eml</button>
  </div>`;

  content.innerHTML = html;

  // ── WIRE UP EVENTS ──
  let reportBtn = $("#copyFullReport");
  if (reportBtn) {
    reportBtn.addEventListener("click", () => {
      navigator.clipboard.writeText(buildFullReport(item))
        .then(() => alert("Отчёт скопирован в буфер обмена"))
        .catch(() => {});
    });
  }

  let copyBtn = $("#copyAllIoc");
  if (copyBtn) {
    copyBtn.addEventListener("click", () => {
      navigator.clipboard.writeText(buildIocText(item))
        .then(() => alert("IOC скопированы в буфер обмена"))
        .catch(() => {});
    });
  }

  let exportBtn = $("#exportEml");
  if (exportBtn) {
    exportBtn.addEventListener("click", () => exportEml(item.messageId, item.subject));
  }

  async function detailAction(action) {
    if (action === "junk") {
      await browser.runtime.sendMessage({ action: "moveToJunk", messageId: item.messageId });
      window.close();
    } else if (action === "safe") {
      await browser.runtime.sendMessage({ action: "markSafe", messageId: item.messageId, storageKey: item.storageKey });
      window.close();
    } else if (action === "delete") {
      await browser.runtime.sendMessage({ action: "deleteMessage", messageId: item.messageId });
      window.close();
    } else if (action === "unsubscribe") {
      const btn = $("#detailUnsubscribe");
      if (btn) {
        btn.disabled = true;
        btn.innerText = "⏳ Отписка...";
      }
      const result = await browser.runtime.sendMessage({ action: "unsubscribe", messageId: item.messageId });
      if (btn) {
        btn.disabled = false;
        btn.innerText = "📭 Безопасная отписка от рассылки";
      }
      if (result && result.ok) {
        alert(result.message);
      } else {
        alert("Ошибка отписки: " + (result?.error || "Неизвестная ошибка"));
      }
    }
  }

  if ($("#detailJunk")) $("#detailJunk").addEventListener("click", () => detailAction("junk"));
  if ($("#detailSafe")) $("#detailSafe").addEventListener("click", () => detailAction("safe"));
  if ($("#detailDelete")) $("#detailDelete").addEventListener("click", () => detailAction("delete"));
  if ($("#detailUnsubscribe")) $("#detailUnsubscribe").addEventListener("click", () => detailAction("unsubscribe"));
  if ($("#detailAskAi")) $("#detailAskAi").addEventListener("click", () => initAiChat(item, activeMessage?.id));
}

// ─────────────── POLLING FOR DEEP ANALYSIS ───────────────

let pollTimeout = null;
let pollAttempts = 0;
const MAX_POLL_ATTEMPTS = 15; // 15 attempts * 1.5s = ~22.5s total timeout

async function resolveDisplayedMessage() {
  if (!browser.messageDisplay?.getDisplayedMessage) return null;

  try {
    const direct = await browser.messageDisplay.getDisplayedMessage();
    if (direct?.id != null) return direct;
  } catch (e) {
    console.warn("getDisplayedMessage() without tabId failed:", e);
  }

  for (const query of [{ active: true, lastFocusedWindow: true }, { active: true, currentWindow: true }]) {
    const tabs = await browser.tabs.query(query);
    for (const tab of tabs) {
      try {
        const msg = await browser.messageDisplay.getDisplayedMessage(tab.id);
        if (msg?.id != null) return msg;
      } catch (e) {
        // try next tab
      }
    }
  }

  const allTabs = await browser.tabs.query({});
  for (const tab of allTabs) {
    try {
      const msg = await browser.messageDisplay.getDisplayedMessage(tab.id);
      if (msg?.id != null) return msg;
    } catch (e) {
      // try next tab
    }
  }

  return null;
}

async function fetchAnalysis(messageId, messageHeader) {
  return browser.runtime.sendMessage({
    action: "getSingleAnalysis",
    messageId,
    messageHeader: messageHeader || undefined
  });
}

function stopPolling() {
  if (pollTimeout) {
    clearTimeout(pollTimeout);
    pollTimeout = null;
  }
}

function startPolling(messageId, messageHeader, options = {}) {
  const { requireDeep = false } = options;
  stopPolling();
  pollAttempts = 0;

  async function poll() {
    pollAttempts++;
    try {
      const response = await fetchAnalysis(messageId, messageHeader);
      const item = response?.report;

      if (!item) {
        if (pollAttempts >= MAX_POLL_ATTEMPTS) {
          stopPolling();
          renderDetail(null);
        } else {
          pollTimeout = setTimeout(poll, 1500);
        }
        return;
      }

      const hasDeep = !!(item.ioc && item.ioc.deepAnalysis);
      if (!requireDeep) {
        stopPolling();
        renderDetail(item);
        if (!hasDeep) {
          startPolling(messageId, messageHeader, { requireDeep: true });
        }
        return;
      }

      if (hasDeep) {
        stopPolling();
        renderDetail(item);
      } else if (pollAttempts >= MAX_POLL_ATTEMPTS) {
        stopPolling();
        renderDetail(item, true);
      } else {
        pollTimeout = setTimeout(poll, 1500);
      }
    } catch (e) {
      console.error("Polling error:", e);
      if (pollAttempts >= MAX_POLL_ATTEMPTS) {
        stopPolling();
        renderDetail(null);
      } else {
        pollTimeout = setTimeout(poll, 1500);
      }
    }
  }

  pollTimeout = setTimeout(poll, 1500);
}

// ─────────────── INIT ───────────────

async function init() {
  try {
    const urlParams = new URLSearchParams(window.location.search);
    let messageId = urlParams.get("messageId");
    let message = null;

    if (messageId) {
      messageId = Number(messageId);
      try {
        message = await browser.messages.get(messageId);
      } catch (e) {
        console.error("Failed to get message by ID from URL:", e);
      }
    }

    if (!message) {
      message = await resolveDisplayedMessage();
    }

    if (!message) {
      $("#loading").textContent = "Нет активного сообщения.";
      return;
    }

    activeMessage = message;

    // Show "Open in window" button only if we are in the transient popup
    if (!urlParams.has("messageId")) {
      const headerActions = $("#headerActions");
      const btnPin = $("#btnPinWindow");
      if (headerActions && btnPin) {
        headerActions.style.display = "flex";
        btnPin.addEventListener("click", () => {
          browser.windows.create({
            url: browser.runtime.getURL(`popup/message.html?messageId=${message.id}`),
            type: "popup",
            width: 850,
            height: 700
          });
          window.close();
        });
      }
    }

    const response = await fetchAnalysis(message.id, message);
    const item = response?.report;

    if (!item) {
      $("#loading").style.display = "block";
      $("#loading").textContent = "Выполняется анализ письма...";
      startPolling(message.id, message, { requireDeep: false });
      return;
    }

    renderDetail(item);
    if (item.ioc && !item.ioc.deepAnalysis) {
      startPolling(message.id, message, { requireDeep: true });
    }
  } catch (err) {
    console.error(err);
    $("#loading").textContent = "Ошибка загрузки: " + err.message;
  }
}

// ──────────────────────────── AI CHAT ASSISTANT ──────────────────────────

const AI_TOOLS = [
  {
    type: "function",
    function: {
      name: "list_session_files",
      description: "Получить список файлов, вложений и EML-содержимого, доступных в текущей сессии анализа.",
      parameters: { type: "object", properties: {} }
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

// Wire up AI Chat UI actions
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

init();
