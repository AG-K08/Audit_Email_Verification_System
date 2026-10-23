/**
 * Thunderbird Phishing Guard v2.4.0
 * Developed by AG-K08 (@And_8)
 *
 * Automatic static analysis of incoming emails:
 *  - Header checks (SPF/DKIM/DMARC, From/Reply-To)
 *  - Free email provider detection
 *  - Body analysis (phishing keywords, URL inspection)
 *  - HTML href mismatch detection
 *  - UNC/SMB path detection (NTLM theft)
 *  - Homograph / punycode domain detection
 *  - Attachment analysis (dangerous extensions, double extensions)
 *  - Empty body with attachment heuristic
 *  - Whitelist support via user settings
 */

"use strict";

// ──────────────────────────── CONSTANTS ────────────────────────────

const STORAGE_KEY = "analysisByMessage";
const SETTINGS_KEY = "userSettings";
const SCAN_ALARM = "scan-unchecked-inbox-mail";

let activeUnsubscribeState = {
  running: false,
  total: 0,
  current: 0,
  log: [],
  results: null
};

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function broadcastUnsubscribeState() {
  try {
    browser.runtime.sendMessage({
      action: "unsubProgressUpdate",
      state: activeUnsubscribeState
    }).catch(() => {
      // Ignore errors when receiving end (popup) is closed
    });
  } catch (err) {
    // Ignore
  }
}

const DEFAULT_SETTINGS = {
  scanIntervalMinutes: 5,
  notifySuspicious: false,
  notifyMalicious: false,
  autoMoveToJunk: false,
  autoMoveThreshold: "MALICIOUS",
  whitelistDomains: ["xn--c1adaxli.xn--90ais"]
};

const DANGEROUS_EXTENSIONS = [
  ".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".bat", ".cmd",
  ".ps1", ".psm1", ".hta", ".jar", ".com", ".pif", ".cpl", ".lnk",
  ".iso", ".img", ".zip", ".rar", ".7z", ".ace", ".docm", ".xlsm",
  ".msi", ".wsf", ".reg", ".inf", ".application", ".appref-ms"
];

const PHISHING_KEYWORDS = [
  // Russian
  "срочно", "заблокирован", "подтвердите", "подтвердить", "верификация",
  "аккаунт заблокирован", "немедленно", "ваш аккаунт", "смена пароля",
  "обновите данные", "подозрительная активность", "безопасность аккаунта",
  "пройдите верификацию", "введите пароль", "разблокировать",
  "ваша учётная запись", "несанкционированный доступ", "ограничен доступ",
  "действует 24 часа", "истекает сегодня", "перейдите по ссылке",
  // English
  "verify", "urgent", "account suspended", "password expired", "act now",
  "confirm your identity", "unusual activity", "verify your account",
  "click here immediately", "your account will be", "update your payment",
  "security alert", "unauthorized access", "confirm your password",
  "limited time", "suspended account", "action required",
  "we noticed suspicious", "reset your password"
];

const SHORTENER_DOMAINS = [
  "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly",
  "ow.ly", "rebrand.ly", "clck.ru", "vk.cc", "go.su"
];

const FREE_EMAIL_PROVIDERS = [
  "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "mail.ru",
  "yandex.ru", "yandex.com", "rambler.ru", "inbox.ru", "bk.ru",
  "list.ru", "aol.com", "protonmail.com", "tutanota.com", "zoho.com",
  "icloud.com", "gmx.com", "gmx.de"
];

// ──────────────────────────── UTILITIES ────────────────────────────

function normalize(value) {
  return String(value || "").toLowerCase();
}

function extractEmailAddress(text) {
  const match = String(text || "").match(/([a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})/i);
  return match ? match[1].toLowerCase() : "";
}

function extractDomain(email) {
  const parts = email.split("@");
  return parts.length === 2 ? parts[1].toLowerCase() : "";
}

function isInboxFolder(folder) {
  return normalize(folder?.name) === "inbox" || normalize(folder?.type) === "inbox";
}

function messageKey(message) {
  return `${message.folder?.accountId || "no-account"}:${message.id}`;
}

function normalizeMessageId(messageId) {
  if (messageId === undefined || messageId === null || messageId === "") return messageId;
  if (typeof messageId === "number") return messageId;
  if (typeof messageId === "string") {
    const trimmed = messageId.trim();
    if (trimmed !== "" && /^-?\d+$/.test(trimmed)) {
      const num = Number(trimmed);
      if (String(num) === trimmed) return num;
    }
    return messageId;
  }
  return messageId;
}

function toIsoDate(value) {
  if (!value) return new Date().toISOString();
  if (value instanceof Date) return value.toISOString();
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? new Date().toISOString() : parsed.toISOString();
}

function findAnalysisEntry(analysisMap, messageId) {
  const idStr = String(messageId);
  for (const [key, entry] of Object.entries(analysisMap)) {
    if (entry && String(entry.messageId) === idStr) {
      return { item: entry, key };
    }
  }
  return { item: null, key: null };
}

function withStorageKey(item, key) {
  if (!item) return null;
  return key ? { ...item, storageKey: key } : item;
}

function stripHtmlTags(html) {
  if (!html || typeof html !== "string") return "";
  return html.replace(/<[^>]+>/g, "");
}

// ──────────────────────────── SETTINGS ────────────────────────────

async function loadSettings() {
  const data = await browser.storage.local.get(SETTINGS_KEY);
  return { ...DEFAULT_SETTINGS, ...(data[SETTINGS_KEY] || {}) };
}

async function saveSettings(settings) {
  await browser.storage.local.set({ [SETTINGS_KEY]: settings });
}

// ──────────────────────────── BODY PARSING ────────────────────────

function flattenParts(parts, output = { plain: [], html: [] }) {
  if (!Array.isArray(parts)) return output;

  for (const part of parts) {
    if (part?.contentType === "text/plain" && typeof part?.body === "string") {
      output.plain.push(part.body);
    } else if (part?.contentType === "text/html" && typeof part?.body === "string") {
      output.html.push(part.body);
    }
    if (Array.isArray(part?.parts) && part.parts.length > 0) {
      flattenParts(part.parts, output);
    }
  }
  return output;
}

function extractUrls(text) {
  if (!text || typeof text !== "string") return [];
  const urls = [];
  
  // 1. Regex for matching standard http/https links
  const httpRegex = /https?:\/\/[^\s<>'"]+/gi;
  let match;
  while ((match = httpRegex.exec(text)) !== null) {
    let url = match[0];
    // Strip trailing punctuation often captured by regex
    url = url.replace(/[.,;:!?)]+$/, "");
    urls.push(url);
  }

  // 2. Extract from href="..." in HTML context
  const hrefRegex = /href\s*=\s*["'](https?:\/\/[^"']+)["']/gi;
  while ((match = hrefRegex.exec(text)) !== null) {
    urls.push(match[1]);
  }

  // Filter out technical XML namespaces/schemas and invalid/empty URLs
  const technicalDomains = [
    "w3.org", "xmlsoap.org", "openxmlformats.org", "purl.org", "iana.org", "schemas.microsoft.com", "opengraph.org", "schema.org"
  ];

  const filteredUrls = urls.filter(u => {
    const lowerUrl = u.toLowerCase();
    // Filter out namespace/schema markers
    if (lowerUrl.includes("/2008/fbml") || lowerUrl.includes("/schema/") || lowerUrl.includes("/schemas/") || lowerUrl.endsWith(".xsd") || lowerUrl.endsWith(".dtd")) {
      return false;
    }
    try {
      const hostname = new URL(u).hostname.toLowerCase();
      // Skip if it is a technical schema/namespace domain
      if (technicalDomains.some(td => hostname === td || hostname.endsWith("." + td))) {
        return false;
      }
      return true;
    } catch {
      // If URL parsing fails, check if the string contains any technical domains as substring
      if (technicalDomains.some(td => lowerUrl.includes(td))) {
        return false;
      }
      return true;
    }
  });

  return [...new Set(filteredUrls)];
}

// ──────────────────────────── CHECK FUNCTIONS ────────────────────────

function hasPhishingKeywords(content) {
  const normalized = normalize(content);
  return PHISHING_KEYWORDS.filter((keyword) => normalized.includes(keyword));
}

function hasDangerousExtension(name) {
  const lower = normalize(name);
  return DANGEROUS_EXTENSIONS.some((ext) => lower.endsWith(ext));
}

function hasDoubleExtension(name) {
  const lower = normalize(name);
  const parts = lower.split(".");
  if (parts.length < 3) return false;
  const lastExt = "." + parts[parts.length - 1];
  const secondLastExt = "." + parts[parts.length - 2];
  const docExtensions = [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf", ".jpg", ".png"];
  return docExtensions.includes(secondLastExt) && DANGEROUS_EXTENSIONS.includes(lastExt);
}

function checkDisplayNameSpoofing(author, senderAddress) {
  const authorStr = String(author || "");
  const match = authorStr.match(/["']?([^"']+)["']?\s*<([^>]+)>/i);
  if (!match) return null;

  const displayName = match[1].trim().toLowerCase();
  const actualEmail = match[2].trim().toLowerCase();
  
  const brandKeywords = [
    "paypal", "google", "microsoft", "apple", "netflix", "facebook", "instagram",
    "amazon", "steam", "office365", "sberbank", "sber", "tinkoff", "vtb", "gosuslugi",
    "госуслуги", "поддержка", "администрация", "security", "support", "admin", "billing",
    "secure", "invoice", "verification", "payment", "bank"
  ];

  const matchedKeywords = brandKeywords.filter(keyword => displayName.includes(keyword));
  if (matchedKeywords.length > 0) {
    const isPublic = /@(gmail\.com|yandex\..+|mail\.ru|outlook\.com|live\.com|yahoo\.com|hotmail\.com|rambler\.ru|bk\.ru|inbox\.ru|list\.ru)$/i.test(actualEmail);
    if (isPublic) {
      return `Подмена имени (Spoofing): Имя содержит бренд/сервис (${matchedKeywords.join(", ")}) при отправке с публичной почты ${actualEmail}`;
    }
  }
  return null;
}

function checkDomainAlignment(senderAddress, urls) {
  if (!senderAddress || !urls || urls.length === 0) return null;

  const senderDomain = senderAddress.split('@')[1];
  if (!senderDomain) return null;

  const isPublicSender = /^(gmail\.com|yandex\..+|mail\.ru|outlook\.com|live\.com|yahoo\.com|hotmail\.com|rambler\.ru|bk\.ru|inbox\.ru|list\.ru)$/i.test(senderDomain);
  if (isPublicSender) return null;

  const trustedDomains = [
    "google.com", "google.ru", "yandex.ru", "mail.ru", "vk.com", "github.com",
    "microsoft.com", "apple.com", "facebook.com", "twitter.com", "t.co", "linkedin.com",
    "instagram.com", "youtube.com", "telegram.org", "t.me", "zoom.us", "adobe.com",
    "cloudflare.com", "amazon.com", "aws.amazon.com", "wikipedia.org"
  ];

  function extractDomain(url) {
    try {
      const parsed = new URL(url);
      return parsed.hostname.replace(/^www\./i, "").toLowerCase();
    } catch (e) {
      const match = url.match(/https?:\/\/([^/:\s]+)/i);
      return match ? match[1].replace(/^www\./i, "").toLowerCase() : "";
    }
  }

  const mismatchedDomains = [];
  for (const url of urls) {
    const linkDomain = extractDomain(url);
    if (!linkDomain) continue;

    if (linkDomain === senderDomain || linkDomain.endsWith("." + senderDomain)) {
      continue;
    }

    const isTrusted = trustedDomains.some(td => linkDomain === td || linkDomain.endsWith("." + td));
    if (isTrusted) {
      continue;
    }

    if (!mismatchedDomains.includes(linkDomain)) {
      mismatchedDomains.push(linkDomain);
    }
  }

  if (mismatchedDomains.length > 0) {
    return {
      reason: `Несовпадение доменов (Domain Alignment): Корпоративный отправитель '${senderDomain}' присылает внешние ссылки на невыровненные домены: ${mismatchedDomains.join(", ")}`,
      score: 20
    };
  }

  return null;
}

// ──────────────── DETAILED SPF / DKIM / DMARC PARSING ────────────────
// Ref: https://www.anti-malware.ru/practice/methods/SPF-DKIM-DMARC-email-protection

function parseListUnsubscribe(headerVal) {
  if (!headerVal) return null;
  const mailtoMatch = headerVal.match(/<mailto:([^>]+)>/i);
  const httpMatch = headerVal.match(/<(https?:\/\/[^>]+)>/i);
  return {
    mailto: mailtoMatch ? mailtoMatch[1] : null,
    http: httpMatch ? httpMatch[1] : null
  };
}

function parseAuthResults(authResultsRaw) {
  const result = {
    spf:   { status: "none", domain: null },
    dkim:  { status: "none", domain: null, selector: null },
    dmarc: { status: "none", policy: null }
  };
  if (!authResultsRaw) return result;
  const text = authResultsRaw.toLowerCase();

  // SPF
  const spfMatch = text.match(/spf\s*=\s*(pass|fail|softfail|neutral|temperror|permerror|none)/i);
  if (spfMatch) result.spf.status = spfMatch[1];
  const spfDomain = text.match(/spf\s*=\s*\S+[^;]*smtp\.(?:mailfrom|helo)\s*=\s*([^\s;]+)/i);
  if (spfDomain) result.spf.domain = spfDomain[1];

  // DKIM
  const dkimMatch = text.match(/dkim\s*=\s*(pass|fail|neutral|temperror|permerror|none)/i);
  if (dkimMatch) result.dkim.status = dkimMatch[1];
  const dkimDomain = text.match(/dkim\s*=\s*\S+[^;]*header\.d\s*=\s*([^\s;]+)/i);
  if (dkimDomain) result.dkim.domain = dkimDomain[1];
  const dkimSel = text.match(/dkim\s*=\s*\S+[^;]*header\.s\s*=\s*([^\s;]+)/i);
  if (dkimSel) result.dkim.selector = dkimSel[1];

  // DMARC
  const dmarcMatch = text.match(/dmarc\s*=\s*(pass|fail|bestguesspass|none|temperror|permerror)/i);
  if (dmarcMatch) result.dmarc.status = dmarcMatch[1];
  const dmarcPolicy = text.match(/dmarc\s*=\s*\S+[^;]*p\s*=\s*(reject|quarantine|none)/i);
  if (dmarcPolicy) result.dmarc.policy = dmarcPolicy[1];

  return result;
}

// ──────────────── RECEIVED HEADER PARSING (MailHops‐style) ────────────────

const PRIVATE_IP_REGEX = /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1|fc|fd|fe80)/;

function parseReceivedHeaders(receivedArray) {
  const hops = [];
  if (!Array.isArray(receivedArray)) return hops;

  for (const line of receivedArray) {
    const ipv4 = line.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g) || [];
    const fromMatch = line.match(/from\s+([^\s(]+)/i);
    const byMatch = line.match(/by\s+([^\s(]+)/i);
    const dateMatch = line.match(/;\s*(.+)$/);

    const publicIps = ipv4.filter(ip => !PRIVATE_IP_REGEX.test(ip) && ip !== "0.0.0.0");
    if (publicIps.length === 0) continue;

    hops.push({
      ip: publicIps[0],
      from: fromMatch ? fromMatch[1] : null,
      by: byMatch ? byMatch[1] : null,
      date: dateMatch ? dateMatch[1].trim() : null
    });
  }
  // Deduplicate by IP
  const seen = new Set();
  return hops.filter(h => { if (seen.has(h.ip)) return false; seen.add(h.ip); return true; });
}

// ──────────────── GeoIP (ip-api.com, free, no key) ────────────────

async function resolveGeoIP(ips) {
  if (!ips || ips.length === 0) return [];
  try {
    const batch = ips.slice(0, 10).map(ip => ({ query: ip, fields: "query,status,country,countryCode,city,isp,lat,lon" }));
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000); // 5s timeout
    const resp = await fetch("http://ip-api.com/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(batch),
      signal: controller.signal
    });
    clearTimeout(timeout);
    if (!resp.ok) return [];
    const data = await resp.json();
    return data.filter(d => d.status === "success").map(d => ({
      ip: d.query, country: d.country, countryCode: d.countryCode,
      city: d.city, isp: d.isp, lat: d.lat, lon: d.lon
    }));
  } catch { return []; }
}

function isFreeEmailProvider(domain) {
  return FREE_EMAIL_PROVIDERS.includes(domain);
}

function isWhitelisted(domain, whitelistDomains) {
  if (!domain || !Array.isArray(whitelistDomains)) return false;
  return whitelistDomains.some((wd) => {
    const dn = normalize(wd).trim();
    return dn && (domain === dn || domain.endsWith("." + dn));
  });
}

function findShortenedUrls(urls) {
  return urls.filter((u) => {
    try {
      const hostname = new URL(u).hostname.toLowerCase();
      return SHORTENER_DOMAINS.some((sd) => hostname === sd || hostname.endsWith("." + sd));
    } catch {
      return false;
    }
  });
}

function findUncSmb(content) {
  const patterns = [
    /file:\/\/\\\\[^\s"'<>]+/gi,
    /\\\\[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\\[^\s"'<>]+/gi,
    /\\\\[a-z0-9._-]+\\[^\s"'<>]+/gi
  ];
  const matches = [];
  for (const pattern of patterns) {
    const found = content.match(pattern);
    if (found) matches.push(...found);
  }
  return [...new Set(matches)];
}

function findHomographDomains(urls, whitelistDomains = []) {
  const suspicious = [];
  for (const u of urls) {
    try {
      const hostname = new URL(u).hostname;
      // Skip whitelisted domains
      if (isWhitelisted(hostname, whitelistDomains)) continue;
      if (hostname.startsWith("xn--") || hostname.includes(".xn--")) {
        suspicious.push(hostname);
      }
      // Cyrillic characters in hostname (non-ASCII)
      if (/[^\x00-\x7F]/.test(hostname)) {
        suspicious.push(hostname);
      }
    } catch {
      // skip malformed URLs
    }
  }
  return [...new Set(suspicious)];
}

function findHrefMismatches(htmlContent) {
  if (!htmlContent || typeof htmlContent !== "string") return [];
  const mismatches = [];
  
  // To prevent catastrophic backtracking on huge HTML bodies (e.g. 350KB of binary data),
  // we find <a> tags by index and extract small substrings to parse.
  let pos = 0;
  const maxLinkLength = 2000; // A link tag + text is rarely longer than 2KB
  
  while (true) {
    const startIdx = htmlContent.toLowerCase().indexOf("<a ", pos);
    if (startIdx === -1) break;
    
    // Find the closing </a> tag within maxLinkLength characters
    const endIdx = htmlContent.toLowerCase().indexOf("</a>", startIdx);
    if (endIdx === -1) {
      // No closing tag found, skip this <a
      pos = startIdx + 3;
      continue;
    }
    
    // If the closing tag is too far away, it's likely a malformed tag or binary data, skip it
    if (endIdx - startIdx > maxLinkLength) {
      pos = startIdx + 3;
      continue;
    }
    
    const linkHtml = htmlContent.substring(startIdx, endIdx + 4);
    pos = endIdx + 4;
    
    // Now we can safely run a simple regex on this short substring (max 2KB)
    const linkRegex = /<a\s[^>]*href\s*=\s*["']([^"']+)["'][^>]*>(.*?)<\/a>/i;
    const match = linkRegex.exec(linkHtml);
    if (match) {
      const href = match[1].trim();
      const innerText = stripHtmlTags(match[2]).trim();
      // Check if inner text looks like a URL but differs from href
      if (/^https?:\/\//i.test(innerText)) {
        try {
          const hrefHost = new URL(href).hostname.toLowerCase();
          const textHost = new URL(innerText).hostname.toLowerCase();
          if (hrefHost !== textHost) {
            mismatches.push({ display: innerText, actual: href });
          }
        } catch {
          // If we can't parse, flag it
          if (innerText.length > 10) {
            mismatches.push({ display: innerText, actual: href });
          }
        }
      }
    }
  }
  return mismatches;
}

function isEmptyBody(plainText, htmlText) {
  const stripped = stripHtmlTags(htmlText);
  const combined = (plainText + " " + stripped).trim();
  return combined.length < 30;
}

// ──────────────────────────── FOLDER OPERATIONS ────────────────────

async function getAllInboxFolders() {
  const accounts = await browser.accounts.list(true);
  const inboxFolders = [];

  function walkFolders(folder) {
    if (!folder) return;
    if (isInboxFolder(folder)) {
      inboxFolders.push(folder);
    }
    if (Array.isArray(folder.subFolders)) {
      for (const subFolder of folder.subFolders) {
        walkFolders(subFolder);
      }
    }
  }

  for (const account of accounts) {
    if (Array.isArray(account.folders)) {
      for (const folder of account.folders) {
        walkFolders(folder);
      }
    }
  }
  return inboxFolders;
}

async function getAllMessagesFromFolder(folder) {
  const allMessages = [];
  let page = await browser.messages.list(folder.id);
  allMessages.push(...(page.messages || []));
  while (page.id) {
    page = await browser.messages.continueList(page.id);
    allMessages.push(...(page.messages || []));
  }
  return allMessages;
}

// ──────────────────────────── STORAGE ────────────────────────────

async function loadAnalysisMap() {
  const data = await browser.storage.local.get(STORAGE_KEY);
  return data[STORAGE_KEY] || {};
}

async function saveAnalysisMap(analysisMap) {
  await browser.storage.local.set({ [STORAGE_KEY]: analysisMap });
}

// ──────────────────────────── SCORING ────────────────────────────

function classifyScore(score) {
  if (score >= 70) return "MALICIOUS";
  if (score >= 35) return "SUSPICIOUS";
  return "CLEAN";
}

// ──────────────────────────── CORE ANALYSIS ────────────────────────

async function analyzeMessage(message, settings) {
  const reasons = [];
  let score = 0;

  const full = await browser.messages.getFull(message.id);
  const parts = flattenParts(full?.parts || []);
  const plainText = parts.plain.join("\n");
  const htmlText = parts.html.join("\n");
  const bodyText = `${plainText}\n${htmlText}`;
  const urls = extractUrls(bodyText);

  const headerFrom = message.author || "";
  const senderAddress = extractEmailAddress(headerFrom);
  const senderDomain = extractDomain(senderAddress);
  const headers = full?.headers || {};
  const replyToRaw = (headers["reply-to"] || []).join(" ");
  const replyToAddress = extractEmailAddress(replyToRaw);
  const authResults = (headers["authentication-results"] || []).join(" ");
  const spfHeader = (headers["received-spf"] || []).join(" ");

  // ── Whitelist check ──
  const listUnsubHeader = headers["list-unsubscribe"] ? headers["list-unsubscribe"].join(" ") : "";
  const listUnsubPostHeader = headers["list-unsubscribe-post"] ? headers["list-unsubscribe-post"].join(" ") : "";
  const unsubscribeData = parseListUnsubscribe(listUnsubHeader);
  const supportsOneClick = /One-Click/i.test(listUnsubPostHeader);

  if (isWhitelisted(senderDomain, settings.whitelistDomains)) {
    return {
      messageId: message.id,
      checkedAt: new Date().toISOString(),
      subject: message.subject || "",
      author: message.author || "",
      date: toIsoDate(message.date),
      score: 0,
      status: "CLEAN",
      reasons: ["Домен отправителя в белом списке: " + senderDomain],
      urlCount: urls.length,
      attachmentCount: 0,
      whitelisted: true,
      ioc: { authResults: null, route: [], geoip: [], deepAnalysis: null, unsubscribe: unsubscribeData, unsubscribeOneClick: supportsOneClick }
    };
  }

  // ── ПРОВЕРКА 1: Несовпадение From / Reply-To ──
  if (replyToAddress && senderAddress && replyToAddress !== senderAddress) {
    reasons.push(`Несовпадение From/Reply-To: ${senderAddress} ≠ ${replyToAddress}`);
    score += 25;
  }

  // ── ПРОВЕРКА 2: Детальный анализ SPF/DKIM/DMARC ──
  const authParsed = parseAuthResults(authResults || spfHeader);
  if (authParsed.spf.status === "fail") {
    reasons.push(`SPF: ПРОВАЛЕНО — домен ${authParsed.spf.domain || senderDomain} не авторизовал отправляющий сервер`);
    score += 20;
  } else if (authParsed.spf.status === "softfail") {
    reasons.push(`SPF: мягкий отказ (softfail) — сервер не в списке разрешённых, но не запрещён`);
    score += 10;
  }
  if (authParsed.dkim.status === "fail") {
    reasons.push(`DKIM: ПРОВАЛЕНО — цифровая подпись письма недействительна (домен: ${authParsed.dkim.domain || "?"})`);
    score += 25;
  }
  if (authParsed.dmarc.status === "fail") {
    reasons.push(`DMARC: ПРОВАЛЕНО — политика домена: ${authParsed.dmarc.policy || "не указана"}`);
    score += 30;
  }

  // ── ПРОВЕРКА 3: Бесплатный почтовый провайдер ──
  if (isFreeEmailProvider(senderDomain)) {
    reasons.push(`Отправитель использует бесплатный почтовый сервис: ${senderDomain}`);
    score += 15;
  }

  // ── ПРОВЕРКА 4: Фишинговые ключевые слова ──
  const foundKeywords = hasPhishingKeywords(bodyText);
  if (foundKeywords.length > 0) {
    reasons.push(`Фишинговые слова (${foundKeywords.length}): ${foundKeywords.slice(0, 5).join(", ")}${foundKeywords.length > 5 ? "..." : ""}`);
    score += Math.min(30, 8 * foundKeywords.length);
  }

  // ── ПРОВЕРКА 5: Сокращённые URL ──
  const shortened = findShortenedUrls(urls);
  if (shortened.length > 0) {
    reasons.push(`Сокращённые URL: ${shortened.slice(0, 3).join(", ")}`);
    score += 20;
  }

  // ── ПРОВЕРКА 6: Несовпадение текста ссылки и href ──
  if (htmlText.length > 0) {
    const mismatches = findHrefMismatches(htmlText);
    if (mismatches.length > 0) {
      const sample = mismatches[0];
      reasons.push(`Текст ссылки не совпадает с URL: "${sample.display}" → ${sample.actual}`);
      score += 30;
    }
  }

  // ── ПРОВЕРКА 7: UNC/SMB пути (кража NTLM) ──
  const uncPaths = findUncSmb(bodyText);
  if (uncPaths.length > 0) {
    reasons.push(`Обнаружен UNC/SMB путь (риск кражи NTLM): ${uncPaths[0]}`);
    score += 50;
  }

  // ── ПРОВЕРКА 8: Гомограф-домены (punycode) ──
  const homographs = findHomographDomains(urls, settings.whitelistDomains);
  if (homographs.length > 0) {
    reasons.push(`Обнаружен гомограф/punycode-домен: ${homographs[0]}`);
    score += 35;
  }

  // ── ПРОВЕРКА 9: Опасные вложения ──
  let attachments = [];
  try {
    attachments = await browser.messages.listAttachments(message.id);
  } catch {
    attachments = [];
  }

  const dangerousAttachments = attachments
    .map((a) => a?.name || "")
    .filter((name) => hasDangerousExtension(name));
  if (dangerousAttachments.length > 0) {
    reasons.push(`Опасные вложения: ${dangerousAttachments.join(", ")}`);
    score += 40;
  }

  // ── ПРОВЕРКА 10: Двойные расширения ──
  const doubleExt = attachments
    .map((a) => a?.name || "")
    .filter((name) => hasDoubleExtension(name));
  if (doubleExt.length > 0) {
    reasons.push(`Двойное расширение: ${doubleExt.join(", ")}`);
    score += 45;
  }

  // ── ПРОВЕРКА 11: Пустое тело + вложение ──
  if (isEmptyBody(plainText, htmlText) && attachments.length > 0) {
    reasons.push("Пустое тело письма с вложением — возможный дроппер.");
    score += 15;
  }

  // ── ПРОВЕРКА 12: Подмена отображаемого имени (Display Name Spoofing) ──
  const spoofingWarning = checkDisplayNameSpoofing(headerFrom, senderAddress);
  if (spoofingWarning) {
    reasons.push(spoofingWarning);
    score += 30;
  }

  // ── ПРОВЕРКА 13: Несоответствие доменов (Domain Alignment Check) ──
  const alignmentAnalysis = checkDomainAlignment(senderAddress, urls);
  if (alignmentAnalysis) {
    reasons.push(alignmentAnalysis.reason);
    score += alignmentAnalysis.score;
  }

  // ── МАРШРУТ ПИСЬМА (MailHops) ──
  const receivedHeaders = headers["received"] || [];
  const route = parseReceivedHeaders(receivedHeaders);
  const routeIps = route.map(h => h.ip);
  let geoip = [];
  try { geoip = await resolveGeoIP(routeIps); } catch { /* ignore */ }

  // ── ПАРСИНГ АУТЕНТИФИКАЦИИ ──
  // authParsed already computed above

  const status = classifyScore(score);

  // Collect IOCs for detailed view
  const ioc = {
    senderEmail: senderAddress,
    senderDomain: senderDomain,
    replyTo: replyToAddress || null,
    urls: [...new Set(urls)].slice(0, 20),
    shortenedUrls: shortened || [],
    homographDomains: homographs || [],
    uncPaths: [],
    dangerousFiles: dangerousAttachments || [],
    doubleExtFiles: doubleExt || [],
    allAttachments: attachments.map((a) => a?.name || "").filter(Boolean),
    hrefMismatches: [],
    authResults: authParsed,
    route: route,
    geoip: geoip,
    deepAnalysis: null,
    unsubscribe: unsubscribeData,
    unsubscribeOneClick: supportsOneClick
  };

  // Collect UNC paths
  const uncRegex = /(?:file:)?\\\\\\\\[^\s\\]+|\\\\[^\s\\]+/gi;
  const uncMatches = bodyText.match(uncRegex);
  if (uncMatches) ioc.uncPaths = [...new Set(uncMatches)];

  // Collect href mismatches
  ioc.hrefMismatches = findHrefMismatches(htmlText);

  return {
    messageId: message.id,
    checkedAt: new Date().toISOString(),
    subject: message.subject || "",
    author: message.author || "",
    date: toIsoDate(message.date),
    score,
    status,
    reasons,
    urlCount: urls.length,
    attachmentCount: attachments.length,
    whitelisted: false,
    ioc
  };
}

const staticAnalysesInProgress = new Map(); // messageId -> Promise

async function ensureAnalysisForMessageId(messageId, messageHint = null) {
  const normalizedId = normalizeMessageId(messageId);
  if (normalizedId === undefined || normalizedId === null) {
    return null;
  }

  let analysisMap = await loadAnalysisMap();
  let { item, key } = findAnalysisEntry(analysisMap, normalizedId);

  if (!item) {
    // If there is already an analysis in progress for this message ID, wait for it!
    if (staticAnalysesInProgress.has(normalizedId)) {
      try {
        await staticAnalysesInProgress.get(normalizedId);
        // Reload map and find the entry again
        analysisMap = await loadAnalysisMap();
        const recheck = findAnalysisEntry(analysisMap, normalizedId);
        item = recheck.item;
        key = recheck.key;
      } catch (e) {
        console.error("Error waiting for concurrent static analysis:", e);
      }
    }

    if (!item) {
      let message = messageHint;
      if (!message || message.id == null) {
        try {
          message = await browser.messages.get(normalizedId);
        } catch (e) {
          console.error("ensureAnalysisForMessageId messages.get:", e);
          return null;
        }
      }

      const mapKey = messageKey(message);
      item = analysisMap[mapKey];
      key = item ? mapKey : null;

      if (!item) {
        // Create a promise for the analysis and store it in the map
        const analysisPromise = (async () => {
          const settings = await loadSettings();
          const analyzedItem = await analyzeMessage(message, settings);
          
          // Reload map inside the promise to prevent overwriting other concurrent writes
          const currentMap = await loadAnalysisMap();
          currentMap[mapKey] = analyzedItem;
          await markMessageScanned(message.id);
          await notifyIfRisk(analyzedItem, settings);
          await saveAnalysisMap(currentMap);
          
          if (settings.deepAnalysisEnabled !== false) {
            sendToDeepAnalysis(message.id, settings, currentMap).catch(() => {});
          }
          return analyzedItem;
        })();

        staticAnalysesInProgress.set(normalizedId, analysisPromise);

        try {
          item = await analysisPromise;
          key = mapKey;
        } catch (e) {
          console.error("ensureAnalysisForMessageId analyze:", e);
          return null;
        } finally {
          staticAnalysesInProgress.delete(normalizedId);
        }
      }
    }
  }

  if (item && item.ioc && !item.ioc.deepAnalysis) {
    triggerBackgroundDeepAnalysis(normalizedId).catch(() => {});
  }

  return withStorageKey(item, key);
}

// ──────────────────────────── NOTIFICATIONS ────────────────────────

async function notifyIfRisk(report, settings) {
  if (report.status === "CLEAN") return;
  if (report.status === "SUSPICIOUS" && !settings.notifySuspicious) return;
  if (report.status === "MALICIOUS" && !settings.notifyMalicious) return;

  const icon = report.status === "MALICIOUS" ? "⛔" : "⚠️";
  await browser.notifications.create(`phishing-alert-${report.messageId}`, {
    type: "basic",
    title: `${icon} Email ${report.status}`,
    message: `${report.subject || "(no subject)"}\n${report.reasons.join(" | ")}`.slice(0, 380)
  });
}

// ──────────────────────────── TAG MESSAGE ────────────────────────

async function markMessageScanned(messageId) {
  const messageIdNum = typeof messageId === "string" && !isNaN(Number(messageId)) ? Number(messageId) : messageId;
  try {
    const message = await browser.messages.get(messageIdNum);
    const currentTags = Array.isArray(message.tags) ? message.tags : [];
    if (!currentTags.includes("phishing-checked")) {
      await browser.messages.update(messageIdNum, { tags: [...currentTags, "phishing-checked"] });
    }
  } catch {
    // Tagging can fail if tags are unsupported
  }
}

// ──────────────────────────── DEEP ANALYSIS INTEGRATION ────────────

let nativePort = null;
const pendingRequests = new Map();
let nextRequestId = 1;

function getNativePort() {
  if (nativePort) return nativePort;

  console.log("[ThunderbirdPhishingGuard] Connecting to persistent native host...");
  nativePort = browser.runtime.connectNative("thunderbird_phishing_guard");

  nativePort.onMessage.addListener((response) => {
    const reqId = response.requestId;
    if (reqId && pendingRequests.has(reqId)) {
      const { resolve, reject, timer } = pendingRequests.get(reqId);
      clearTimeout(timer);
      pendingRequests.delete(reqId);
      resolve(response);
    } else {
      console.warn("[ThunderbirdPhishingGuard] Received native message without matching requestId:", response);
    }
  });

  nativePort.onDisconnect.addListener(() => {
    const error = browser.runtime.lastError;
    console.warn("[ThunderbirdPhishingGuard] Native host disconnected:", error ? error.message : "No error message");
    
    // Reject all pending requests
    for (const [reqId, { reject, timer }] of pendingRequests.entries()) {
      clearTimeout(timer);
      reject(new Error(error ? error.message : "Native host disconnected unexpectedly."));
    }
    pendingRequests.clear();
    nativePort = null;
  });

  return nativePort;
}

function sendToNativeHost(rawEml) {
  return new Promise((resolve, reject) => {
    try {
      const port = getNativePort();
      const reqId = nextRequestId++;
      
      // Set a timeout of 120 seconds for the request to prevent infinite hangs
      const timer = setTimeout(() => {
        if (pendingRequests.has(reqId)) {
          pendingRequests.delete(reqId);
          reject(new Error("Request to native host timed out."));
        }
      }, 120000);

      pendingRequests.set(reqId, { resolve, reject, timer });
      port.postMessage({ action: "analyze", eml: rawEml, requestId: reqId });
    } catch (e) {
      reject(e);
    }
  });
}

function sendActionToNativeHost(action, payload) {
  return new Promise((resolve, reject) => {
    try {
      const port = getNativePort();
      const reqId = nextRequestId++;
      
      const timer = setTimeout(() => {
        if (pendingRequests.has(reqId)) {
          pendingRequests.delete(reqId);
          reject(new Error(`Request ${action} to native host timed out.`));
        }
      }, 120000);

      pendingRequests.set(reqId, { resolve, reject, timer });
      port.postMessage({ action, ...payload, requestId: reqId });
    } catch (e) {
      reject(e);
    }
  });
}

async function sendToDeepAnalysis(messageId, settings, analysisMap) {
  try {
    const rawEml = await browser.messages.getRaw(messageId);
    if (!rawEml) return;

    console.log(`[ThunderbirdPhishingGuard] Sending message ${messageId} for deep Python analysis via native messaging...`);
    const response = await sendToNativeHost(rawEml);
    
    if (response && response.success) {
      const key = Object.keys(analysisMap).find(k => String(analysisMap[k].messageId) == String(messageId));
      if (key && analysisMap[key].ioc) {
        analysisMap[key].ioc.deepAnalysis = response.report_data;
        
        // If deep analysis verdict is worse, elevate status and score
        if (response.verdict === "MALICIOUS" || response.verdict === "SUSPICIOUS") {
          const oldStatus = analysisMap[key].status;
          if (oldStatus === "CLEAN" || (oldStatus === "SUSPICIOUS" && response.verdict === "MALICIOUS")) {
            analysisMap[key].status = response.verdict;
            analysisMap[key].score = Math.max(analysisMap[key].score, response.verdict === "MALICIOUS" ? 85 : 50);
            
            if (response.report_data.reasons) {
              for (const w of response.report_data.reasons) {
                if (!analysisMap[key].reasons.includes(w)) {
                  analysisMap[key].reasons.push(w);
                }
              }
            }
            await notifyIfRisk(analysisMap[key], settings);
          }
        }
        await saveAnalysisMap(analysisMap);
        console.log(`[ThunderbirdPhishingGuard] Deep analysis completed for ${messageId}. Verdict: ${response.verdict}`);
      }
    } else {
      console.error(`[ThunderbirdPhishingGuard] Deep analysis failed for ${messageId}:`, response?.error);
    }
  } catch (error) {
    console.error(`[ThunderbirdPhishingGuard] Native messaging error during deep analysis of ${messageId}:`, error);
  }
}

// ──────────────────────────── SCAN LOGIC ────────────────────────

async function scanMessageIfNeeded(message, analysisMap, settings) {
  const key = messageKey(message);
  if (analysisMap[key]) return false;

  const report = await analyzeMessage(message, settings);
  analysisMap[key] = report;
  await markMessageScanned(message.id);
  await notifyIfRisk(report, settings);

  // Auto-send to deep analysis server (non-blocking)
  if (settings.deepAnalysisEnabled !== false) {
    sendToDeepAnalysis(message.id, settings, analysisMap).catch(() => {});
  }

  // Auto-move to Junk if enabled
  if (settings.autoMoveToJunk && report.status !== "CLEAN") {
    const shouldMove = settings.autoMoveThreshold === "SUSPICIOUS"
      ? (report.status === "SUSPICIOUS" || report.status === "MALICIOUS")
      : report.status === "MALICIOUS";
    if (shouldMove) {
      await moveMessageToJunk(message.id);
      report.autoMoved = true;
    }
  }

  return true;
}

async function scanAllInboxMessages() {
  const settings = await loadSettings();
  const analysisMap = await loadAnalysisMap();
  const inboxFolders = await getAllInboxFolders();

  let scannedCount = 0;
  const CONCURRENCY_LIMIT = 5;
  const tasks = [];

  for (const folder of inboxFolders) {
    const messages = await getAllMessagesFromFolder(folder);
    for (const message of messages) {
      tasks.push(message);
    }
  }

  if (tasks.length === 0) return 0;

  // Process tasks with concurrency limit
  let index = 0;
  const activeWorkers = [];

  async function worker() {
    while (index < tasks.length) {
      const message = tasks[index++];
      try {
        const scanned = await scanMessageIfNeeded(message, analysisMap, settings);
        if (scanned) {
          scannedCount += 1;
          // Save after each message so popup always has fresh data
          await saveAnalysisMap(analysisMap);
        }
      } catch (err) {
        console.error(`[ThunderbirdPhishingGuard] Error scanning message ${message.id}:`, err);
      }
    }
  }

  for (let i = 0; i < Math.min(CONCURRENCY_LIMIT, tasks.length); i++) {
    activeWorkers.push(worker());
  }

  await Promise.all(activeWorkers);
  return scannedCount;
}

// ──────────────────────────── API FOR POPUP ────────────────────────

function getStats(analysisMap) {
  const entries = Object.values(analysisMap);
  return {
    total: entries.length,
    clean: entries.filter((e) => e.status === "CLEAN").length,
    suspicious: entries.filter((e) => e.status === "SUSPICIOUS").length,
    malicious: entries.filter((e) => e.status === "MALICIOUS").length,
    lastScan: entries.length > 0
      ? entries.reduce((latest, e) => (e.checkedAt > latest ? e.checkedAt : latest), "")
      : null
  };
}

function getRecentIncidents(analysisMap, limit = 500, statusFilter = null) {
  let entries = Object.entries(analysisMap)
    .filter(([, e]) => e.status !== "CLEAN");
  if (statusFilter) {
    entries = entries.filter(([, e]) => e.status === statusFilter);
  }
  return entries
    .map(([key, e]) => ({ ...e, storageKey: key }))
    .sort((a, b) => (b.checkedAt || "").localeCompare(a.checkedAt || ""))
    .slice(0, limit);
}

function getFullHistory(analysisMap, limit = 500, statusFilter = null) {
  let entries = Object.entries(analysisMap);
  if (statusFilter) {
    entries = entries.filter(([, e]) => e.status === statusFilter);
  }
  return entries
    .map(([key, e]) => ({ ...e, storageKey: key }))
    .sort((a, b) => (b.checkedAt || "").localeCompare(a.checkedAt || ""))
    .slice(0, limit);
}

// ──────────────────────────── RESPONSE ACTIONS ────────────────────

async function moveMessageToJunk(messageId) {
  const messageIdNum = typeof messageId === "string" && !isNaN(Number(messageId)) ? Number(messageId) : messageId;
  try {
    const message = await browser.messages.get(messageIdNum);
    const accountId = message.folder?.accountId;
    if (!accountId) return { ok: false, error: "No account found" };

    const accounts = await browser.accounts.list(true);
    let junkFolder = null;

    for (const account of accounts) {
      if (account.id !== accountId) continue;
      function findJunk(folders) {
        for (const f of folders) {
          if (f.type === "junk" || normalize(f.name) === "junk" || normalize(f.name) === "спам") {
            return f;
          }
          if (f.subFolders) {
            const found = findJunk(f.subFolders);
            if (found) return found;
          }
        }
        return null;
      }
      junkFolder = findJunk(account.folders || []);
    }

    if (!junkFolder) return { ok: false, error: "Junk folder not found" };
    await browser.messages.move([messageIdNum], junkFolder);
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

async function markMessageSafe(messageId, storageKey) {
  const messageIdNum = typeof messageId === "string" && !isNaN(Number(messageId)) ? Number(messageId) : messageId;
  const analysisMap = await loadAnalysisMap();
  if (storageKey && analysisMap[storageKey]) {
    analysisMap[storageKey].status = "CLEAN";
    analysisMap[storageKey].reasons = ["Marked safe by analyst"];
    analysisMap[storageKey].resolvedAt = new Date().toISOString();
    analysisMap[storageKey].score = 0;
    await saveAnalysisMap(analysisMap);
  }
  return { ok: true };
}

async function deleteMessageById(messageId) {
  const messageIdNum = typeof messageId === "string" && !isNaN(Number(messageId)) ? Number(messageId) : messageId;
  try {
    await browser.messages.delete([messageIdNum], false); // false = move to trash, not permanent
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

async function saveDeepAnalysisError(messageIdNum, errorMsg) {
  try {
    const analysisMap = await loadAnalysisMap();
    const key = Object.keys(analysisMap).find(k => String(analysisMap[k].messageId) == String(messageIdNum));
    if (key && analysisMap[key].ioc) {
      const item = analysisMap[key];
      item.ioc.deepAnalysis = {
        success: false,
        error: errorMsg
      };
      await saveAnalysisMap(analysisMap);
    }
  } catch (err) {
    console.error("Failed to save deep analysis error:", err);
  }
}

const activeAnalyses = new Set();

async function triggerBackgroundDeepAnalysis(messageId) {
  const messageIdNum = typeof messageId === "string" && !isNaN(Number(messageId)) ? Number(messageId) : messageId;
  if (activeAnalyses.has(messageIdNum)) return;
  activeAnalyses.add(messageIdNum);
  try {
    const settings = await loadSettings();
    if (settings.deepAnalysisEnabled !== false) {
      const rawEml = await browser.messages.getRaw(messageIdNum);
      if (!rawEml) return;

      const response = await sendToNativeHost(rawEml);
      if (response && response.success) {
        const analysisMap = await loadAnalysisMap();
        const key = Object.keys(analysisMap).find(k => String(analysisMap[k].messageId) == String(messageIdNum));
        if (key && analysisMap[key].ioc) {
          const item = analysisMap[key];
          item.ioc.deepAnalysis = response.report_data;

          if (response.verdict === "MALICIOUS" || response.verdict === "SUSPICIOUS") {
            const oldStatus = item.status;
            if (oldStatus === "CLEAN" || (oldStatus === "SUSPICIOUS" && response.verdict === "MALICIOUS")) {
              item.status = response.verdict;
              item.score = Math.max(item.score, response.verdict === "MALICIOUS" ? 85 : 50);
              
              if (response.report_data.reasons) {
                for (const w of response.report_data.reasons) {
                  if (!item.reasons.includes(w)) {
                    item.reasons.push(w);
                  }
                }
              }
              await notifyIfRisk(item, settings);
            }
          }
          await saveAnalysisMap(analysisMap);
          console.log(`[ThunderbirdPhishingGuard] Deep background analysis completed for ${messageIdNum}`);
        }
      } else {
        const errorMsg = response ? response.error : "Unknown error from native host";
        await saveDeepAnalysisError(messageIdNum, errorMsg);
      }
    }
  } catch (e) {
    console.error(`[triggerBackgroundDeepAnalysis] Error:`, e);
    await saveDeepAnalysisError(messageIdNum, e.message || String(e));
  } finally {
    activeAnalyses.delete(messageIdNum);
  }
}

async function runUnsubscribeAll() {
  try {
    const analysisMap = await loadAnalysisMap();
    const cleanList = Object.values(analysisMap).filter(
      item => item.status === "CLEAN" && item.ioc && item.ioc.unsubscribe
    );

    activeUnsubscribeState.total = cleanList.length;
    activeUnsubscribeState.current = 0;
    activeUnsubscribeState.log = [];
    activeUnsubscribeState.results = null;

    if (cleanList.length === 0) {
      activeUnsubscribeState.log.push({ text: "Не найдено безопасных рассылок для отписки.", type: "warn" });
      activeUnsubscribeState.running = false;
      activeUnsubscribeState.results = { httpPostCount: 0, mailtoCount: 0, httpGetCount: 0, totalProcessed: 0 };
      broadcastUnsubscribeState();
      return;
    }

    activeUnsubscribeState.log.push({ text: `Найдено рассылок для отписки: ${cleanList.length}. Начинаем процесс...`, type: "info" });
    broadcastUnsubscribeState();

    let httpPostCount = 0;
    let mailtoCount = 0;
    let httpGetCount = 0;

    for (const item of cleanList) {
      if (!activeUnsubscribeState.running) {
        activeUnsubscribeState.log.push({ text: "Процесс отписки остановлен пользователем.", type: "warn" });
        broadcastUnsubscribeState();
        break;
      }

      activeUnsubscribeState.current++;
      const subject = item.subject || "Без темы";
      const author = item.author || "Неизвестный отправитель";
      activeUnsubscribeState.log.push({ text: `[${activeUnsubscribeState.current}/${activeUnsubscribeState.total}] Обработка: "${subject}" от ${author}`, type: "info" });
      broadcastUnsubscribeState();

      const unsub = item.ioc.unsubscribe;
      const oneClick = item.ioc.unsubscribeOneClick;

      // 1. Try One-Click HTTP POST (RFC 8058) if supported
      if (unsub.http && oneClick) {
        activeUnsubscribeState.log.push({ text: `• Отправка фонового POST-запроса (One-Click)...`, type: "info" });
        broadcastUnsubscribeState();
        try {
          const resp = await fetch(unsub.http, {
            method: "POST",
            headers: {
              "Content-Type": "application/x-www-form-urlencoded"
            },
            body: "List-Unsubscribe=One-Click"
          });
          if (resp.ok) {
            httpPostCount++;
            activeUnsubscribeState.log.push({ text: `✔ Успешно отписано в один клик!`, type: "success" });
            broadcastUnsubscribeState();
            await sleep(400); // delay to let user see progress
            continue;
          } else {
            activeUnsubscribeState.log.push({ text: `⚠ POST-запрос вернул статус: ${resp.status}. Переходим к альтернативным методам.`, type: "warn" });
            broadcastUnsubscribeState();
          }
        } catch (e) {
          activeUnsubscribeState.log.push({ text: `⚠ Ошибка сети при POST: ${e.message || String(e)}. Переходим к альтернативным методам.`, type: "warn" });
          broadcastUnsubscribeState();
        }
      }

      // 2. Try HTTP GET if available (prefer over mailto in bulk mode to avoid opening many windows)
      if (unsub.http) {
        activeUnsubscribeState.log.push({ text: `• Отправка фонового GET-запроса...`, type: "info" });
        broadcastUnsubscribeState();
        let getSuccess = false;
        try {
          const resp = await fetch(unsub.http, {
            method: "GET",
            headers: {
              "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0"
            }
          });
          if (resp.ok) {
            httpGetCount++;
            activeUnsubscribeState.log.push({ text: `✔ Успешно отписано через фоновый GET-запрос!`, type: "success" });
            broadcastUnsubscribeState();
            await sleep(400);
            getSuccess = true;
          } else {
            activeUnsubscribeState.log.push({ text: `• GET-запрос вернул статус ${resp.status}. Открываем вкладку в фоне...`, type: "info" });
            broadcastUnsubscribeState();
          }
        } catch (e) {
          activeUnsubscribeState.log.push({ text: `• Ошибка сети при GET: ${e.message || String(e)}. Открываем вкладку в фоне...`, type: "info" });
          broadcastUnsubscribeState();
        }

        if (getSuccess) {
          continue;
        }

        // Fallback to opening a background tab
        try {
          await browser.tabs.create({ url: unsub.http, active: false });
          httpGetCount++;
          activeUnsubscribeState.log.push({ text: `✔ Ссылка открыта в фоновой вкладке.`, type: "success" });
          broadcastUnsubscribeState();
          await sleep(400);
          continue;
        } catch (e) {
          activeUnsubscribeState.log.push({ text: `⚠ Ошибка открытия вкладки: ${e.message || String(e)}`, type: "error" });
          broadcastUnsubscribeState();
        }
      }

      // 3. Try mailto: if available (only if HTTP was not available or failed)
      if (unsub.mailto) {
        activeUnsubscribeState.log.push({ text: `• Создание письма отписки (mailto)...`, type: "info" });
        broadcastUnsubscribeState();
        try {
          const emailParts = unsub.mailto.split("?");
          const to = emailParts[0];
          let mailSubject = "Unsubscribe";
          let mailBody = "Unsubscribe me from this mailing list.";
          if (emailParts[1]) {
            const params = new URLSearchParams(emailParts[1]);
            if (params.has("subject")) mailSubject = params.get("subject");
            if (params.has("body")) mailBody = params.get("body");
          }
          await browser.compose.beginNew(null, {
            to: to,
            subject: mailSubject,
            body: mailBody
          });
          mailtoCount++;
          activeUnsubscribeState.log.push({ text: `✔ Окно создания письма успешно открыто.`, type: "success" });
          broadcastUnsubscribeState();
          await sleep(1000); // Give more time since a window opened
          continue;
        } catch (e) {
          activeUnsubscribeState.log.push({ text: `⚠ Ошибка создания письма: ${e.message || String(e)}`, type: "error" });
          broadcastUnsubscribeState();
        }
      }
    }

    activeUnsubscribeState.log.push({ text: `Все рассылки успешно обработаны!`, type: "success" });
    activeUnsubscribeState.results = {
      httpPostCount,
      mailtoCount,
      httpGetCount,
      totalProcessed: cleanList.length
    };
    activeUnsubscribeState.running = false;
    broadcastUnsubscribeState();
  } catch (e) {
    console.error("runUnsubscribeAll error:", e);
    activeUnsubscribeState.log.push({ text: `Критическая ошибка процесса: ${e.message || String(e)}`, type: "error" });
    activeUnsubscribeState.running = false;
    broadcastUnsubscribeState();
  }
}

// ──────────────────────────── MESSAGE HANDLERS ────────────────────

browser.runtime.onMessage.addListener(async (request) => {
  let targetMessageId = request.messageId !== undefined ? normalizeMessageId(request.messageId) : undefined;

  if (request.action === "prepare_ai_session") {
    try {
      if (!targetMessageId && browser.messageDisplay && browser.messageDisplay.getDisplayedMessage) {
        const activeMsg = await browser.messageDisplay.getDisplayedMessage();
        if (activeMsg) {
          targetMessageId = activeMsg.id;
        }
      }
      
      if (!targetMessageId) {
        return { ok: false, error: "Идентификатор сообщения не определен." };
      }
      
      const rawEml = await browser.messages.getRaw(targetMessageId);
      if (!rawEml) {
        return { ok: false, error: "Не удалось получить сырое содержимое письма." };
      }
      const response = await sendActionToNativeHost("prepare_ai_session", { eml: rawEml });
      return response;
    } catch (e) {
      console.error("prepare_ai_session error:", e);
      return { ok: false, error: e.message || String(e) };
    }
  }

  if (request.action === "execute_tool") {
    try {
      const response = await sendActionToNativeHost("execute_tool", {
        tool_name: request.tool,
        arguments: request.arguments
      });
      return response;
    } catch (e) {
      console.error("execute_tool error:", e);
      return { ok: false, error: e.message || String(e) };
    }
  }

  if (request.action === "unsubscribe") {
    try {
      const report = await ensureAnalysisForMessageId(targetMessageId);
      if (!report || !report.ioc || !report.ioc.unsubscribe) {
        return { ok: false, error: "Данные для отписки не найдены в заголовках письма." };
      }
      
      if (report.status !== "CLEAN") {
        return { ok: false, error: "Отписка заблокирована в целях безопасности: это письмо подозрительное." };
      }

      const unsub = report.ioc.unsubscribe;
      const oneClick = report.ioc.unsubscribeOneClick;

      // 1. Try One-Click HTTP POST (RFC 8058) if supported
      if (unsub.http && oneClick) {
        console.log("[ThunderbirdPhishingGuard] Performing RFC 8058 One-Click Unsubscribe POST request to:", unsub.http);
        try {
          const resp = await fetch(unsub.http, {
            method: "POST",
            headers: {
              "Content-Type": "application/x-www-form-urlencoded"
            },
            body: "List-Unsubscribe=One-Click"
          });
          if (resp.ok) {
            return { ok: true, method: "http-post", message: "Запрос на отписку успешно отправлен в один клик!" };
          } else {
            console.warn("[ThunderbirdPhishingGuard] One-Click POST failed, status:", resp.status);
          }
        } catch (fetchErr) {
          console.warn("[ThunderbirdPhishingGuard] One-Click POST network error:", fetchErr);
        }
      }

      // 2. Try HTTP GET if available (prefer over mailto to avoid opening windows if possible)
      if (unsub.http) {
        console.log("[ThunderbirdPhishingGuard] Trying background GET request to:", unsub.http);
        try {
          const resp = await fetch(unsub.http, {
            method: "GET",
            headers: {
              "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0"
            }
          });
          if (resp.ok) {
            return { ok: true, method: "http-get-fetch", message: "Запрос на отписку успешно отправлен в фоне!" };
          } else {
            console.warn("[ThunderbirdPhishingGuard] Background GET failed, status:", resp.status);
          }
        } catch (fetchErr) {
          console.warn("[ThunderbirdPhishingGuard] Background GET network error, falling back to tab:", fetchErr);
        }

        // Fallback to opening a tab
        console.log("[ThunderbirdPhishingGuard] Opening unsubscribe link in new tab:", unsub.http);
        try {
          await browser.tabs.create({ url: unsub.http });
          return { ok: true, method: "http-get-tab", message: "Ссылка на отписку открыта в новой вкладке." };
        } catch (tabErr) {
          console.error("[ThunderbirdPhishingGuard] Failed to open tab:", tabErr);
        }
      }

      // 3. Try mailto: if available (only if HTTP was not available or failed)
      if (unsub.mailto) {
        console.log("[ThunderbirdPhishingGuard] Performing mailto unsubscribe to:", unsub.mailto);
        const emailParts = unsub.mailto.split("?");
        const to = emailParts[0];
        let subject = "Unsubscribe";
        let body = "Unsubscribe me from this mailing list.";
        
        if (emailParts[1]) {
          const params = new URLSearchParams(emailParts[1]);
          if (params.has("subject")) subject = params.get("subject");
          if (params.has("body")) body = params.get("body");
        }

        await browser.compose.beginNew(null, {
          to: to,
          subject: subject,
          body: body
        });
        return { ok: true, method: "mailto", message: "Открыто окно создания письма для отписки." };
      }

      return { ok: false, error: "Не удалось определить метод отписки." };
    } catch (e) {
      console.error("Unsubscribe error:", e);
      return { ok: false, error: e.message || String(e) };
    }
  }

  if (request.action === "startUnsubscribeAll") {
    if (activeUnsubscribeState.running) {
      return { ok: false, error: "Процесс отписки уже запущен." };
    }
    activeUnsubscribeState.running = true;
    runUnsubscribeAll(); // Run asynchronously
    return { ok: true };
  }

  if (request.action === "getUnsubscribeState") {
    return { state: activeUnsubscribeState };
  }

  if (request.action === "stopUnsubscribeAll") {
    activeUnsubscribeState.running = false;
    return { ok: true };
  }

  if (request.action === "resetUnsubscribeState") {
    activeUnsubscribeState = {
      running: false,
      total: 0,
      current: 0,
      log: [],
      results: null
    };
    return { ok: true };
  }

  if (request.action === "getSingleAnalysis") {
    try {
      const report = await ensureAnalysisForMessageId(
        targetMessageId,
        request.messageHeader || null
      );
      return { report };
    } catch (e) {
      console.error("getSingleAnalysis error:", e);
      return { report: null };
    }
  }

  if (request.action === "getStats") {
    const analysisMap = await loadAnalysisMap();
    return { stats: getStats(analysisMap) };
  }
  if (request.action === "getIncidents") {
    const analysisMap = await loadAnalysisMap();
    return { incidents: getRecentIncidents(analysisMap, request.limit || 500, request.statusFilter || null) };
  }
  if (request.action === "getHistory") {
    const analysisMap = await loadAnalysisMap();
    return { history: getFullHistory(analysisMap, request.limit || 500, request.statusFilter || null) };
  }
  if (request.action === "scanNow") {
    const count = await scanAllInboxMessages();
    const analysisMap = await loadAnalysisMap();
    return { scannedCount: count, stats: getStats(analysisMap) };
  }
  if (request.action === "exportReport") {
    const analysisMap = await loadAnalysisMap();
    return { data: analysisMap };
  }
  if (request.action === "getSettings") {
    return { settings: await loadSettings() };
  }
  if (request.action === "saveSettings") {
    await saveSettings(request.settings);
    const interval = request.settings.scanIntervalMinutes || 5;
    await browser.alarms.clear(SCAN_ALARM);
    await browser.alarms.create(SCAN_ALARM, { periodInMinutes: interval });
    return { ok: true };
  }
  if (request.action === "clearHistory") {
    await browser.storage.local.set({ [STORAGE_KEY]: {} });
    return { ok: true };
  }

  // ── Response actions ──
  if (request.action === "moveToJunk") {
    return await moveMessageToJunk(targetMessageId);
  }
  if (request.action === "markSafe") {
    return await markMessageSafe(targetMessageId, request.storageKey);
  }
  if (request.action === "deleteMessage") {
    return await deleteMessageById(targetMessageId);
  }
  if (request.action === "bulkAction") {
    const results = [];
    for (const item of (request.items || [])) {
      if (request.bulkType === "junk") {
        results.push(await moveMessageToJunk(item.messageId));
      } else if (request.bulkType === "safe") {
        results.push(await markMessageSafe(item.messageId, item.storageKey));
      } else if (request.bulkType === "delete") {
        results.push(await deleteMessageById(item.messageId));
      }
    }
    return { ok: true, results };
  }

  return {};
});

// ──────────────────────────── EVENT LISTENERS ────────────────────

browser.messages.onNewMailReceived.addListener(async (_folder, messages) => {
  const settings = await loadSettings();
  const analysisMap = await loadAnalysisMap();
  const list = messages?.messages || [];
  let changed = false;

  for (const message of list) {
    const scanned = await scanMessageIfNeeded(message, analysisMap, settings);
    if (scanned) changed = true;
  }

  if (changed) await saveAnalysisMap(analysisMap);
});

browser.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name !== SCAN_ALARM) return;
  await scanAllInboxMessages();
});

// ──────────────────────────── INIT ────────────────────────────

async function init() {
  const settings = await loadSettings();

  // Force disable notifications if they were enabled (per user request to "remove" them)
  if (settings.notifySuspicious || settings.notifyMalicious) {
    settings.notifySuspicious = false;
    settings.notifyMalicious = false;
    await saveSettings(settings);
    console.log("[Migration] Notifications force disabled per user request.");
  }

  await browser.alarms.create(SCAN_ALARM, {
    periodInMinutes: settings.scanIntervalMinutes || 5
  });
  await scanAllInboxMessages();
  console.log("ThunderbirdPhishingGuard v2.4.0 initialized.");
}

init().catch((error) => {
  console.error("ThunderbirdPhishingGuard initialization failed:", error);
});