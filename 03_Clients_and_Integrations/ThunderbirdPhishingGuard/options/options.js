/**
 * Thunderbird Phishing Guard v2.3 — Options Logic
 * AG-K08 (@And_8) © 2026
 */

"use strict";

const $ = (sel) => document.querySelector(sel);

async function loadCurrentSettings() {
  try {
    const response = await browser.runtime.sendMessage({ action: "getSettings" });
    const s = response.settings;

    $("#scanInterval").value = s.scanIntervalMinutes || 5;
    $("#intervalLabel").textContent = `${s.scanIntervalMinutes || 5} мин`;
    $("#notifySuspicious").checked = s.notifySuspicious !== false;
    $("#notifyMalicious").checked = s.notifyMalicious !== false;
    $("#autoMoveToJunk").checked = !!s.autoMoveToJunk;
    $("#autoMoveThreshold").value = s.autoMoveThreshold || "MALICIOUS";
    $("#thresholdGroup").style.display = s.autoMoveToJunk ? "flex" : "none";

    $("#deepAnalysisEnabled").checked = s.deepAnalysisEnabled !== false;
    $("#deepAnalysisUrl").value = s.deepAnalysisUrl || "http://127.0.0.1:5555/analyze";

    if (Array.isArray(s.whitelistDomains) && s.whitelistDomains.length > 0) {
      $("#whitelistDomains").value = s.whitelistDomains.join("\n");
    }
  } catch (err) {
    console.error("Failed to load settings:", err);
  }
}

async function saveCurrentSettings() {
  const domains = $("#whitelistDomains").value
    .split("\n")
    .map((d) => d.trim().toLowerCase())
    .filter((d) => d.length > 0);

  const settings = {
    scanIntervalMinutes: parseInt($("#scanInterval").value, 10) || 5,
    notifySuspicious: $("#notifySuspicious").checked,
    notifyMalicious: $("#notifyMalicious").checked,
    autoMoveToJunk: $("#autoMoveToJunk").checked,
    autoMoveThreshold: $("#autoMoveThreshold").value,
    deepAnalysisEnabled: $("#deepAnalysisEnabled").checked,
    deepAnalysisUrl: $("#deepAnalysisUrl").value.trim() || "http://127.0.0.1:5555/analyze",
    whitelistDomains: domains
  };

  try {
    await browser.runtime.sendMessage({ action: "saveSettings", settings });
    showSaveStatus("✅ Сохранено!");
  } catch (err) {
    showSaveStatus("❌ Ошибка сохранения");
    console.error("Failed to save settings:", err);
  }
}

async function clearHistory() {
  if (!confirm("Вы уверены? Вся история сканирования будет удалена.")) return;

  try {
    await browser.runtime.sendMessage({ action: "clearHistory" });
    showSaveStatus("🗑️ История очищена");
  } catch (err) {
    console.error("Failed to clear history:", err);
  }
}

function showSaveStatus(text) {
  const el = $("#saveStatus");
  el.textContent = text;
  el.classList.add("visible");
  setTimeout(() => el.classList.remove("visible"), 2500);
}

// Init
document.addEventListener("DOMContentLoaded", () => {
  loadCurrentSettings();

  $("#scanInterval").addEventListener("input", (e) => {
    $("#intervalLabel").textContent = `${e.target.value} мин`;
  });

  $("#autoMoveToJunk").addEventListener("change", (e) => {
    $("#thresholdGroup").style.display = e.target.checked ? "flex" : "none";
  });

  $("#btnSave").addEventListener("click", saveCurrentSettings);
  $("#btnClear").addEventListener("click", clearHistory);
});
