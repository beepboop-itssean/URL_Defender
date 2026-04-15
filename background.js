// ============================================================
// URL Guardian - background.js
// Core logic: intercept requests → cache check → VirusTotal
// ============================================================

// ----- CONFIG -----
const VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY_HERE"; // Get free key at virustotal.com
const VT_THRESHOLD = 2;          // How many engines must flag it as malicious
const CACHE_EXPIRY_MS = 24 * 60 * 60 * 1000; // Cache entries expire after 24h

// ----- IN-MEMORY CACHE (also persisted to chrome.storage.local) -----
// Structure: { [hostname]: { status: "safe"|"malicious"|"pending", timestamp, details } }
let urlCache = {};

// ----- DOMAINS TO NEVER CHECK (browser internals, your own extensions, etc.) -----
const WHITELIST = new Set([
  "localhost",
  "127.0.0.1",
  "accounts.google.com",     // avoid blocking auth flows during dev
  "clients2.google.com",
  "update.googleapis.com",
]);

// ============================================================
// INIT: Load persisted cache from storage on startup
// ============================================================
chrome.storage.local.get("urlCache", (data) => {
  if (data.urlCache) {
    urlCache = data.urlCache;
    console.log("[Guardian] Cache loaded:", Object.keys(urlCache).length, "entries");
  }
});

// ============================================================
// INTERCEPT: Hook into every outgoing web request
// ============================================================
chrome.webRequest.onBeforeRequest.addListener(
  handleRequest,
  { urls: ["<all_urls>"] } //,
  //["blocking"]   // "blocking" allows us to cancel the request
);

function handleRequest(details) {
  // Ignore non-http(s), extension internals, and VirusTotal API calls themselves
  if (!details.url.startsWith("http")) return {};
  if (details.url.includes("virustotal.com")) return {};

  let hostname;
  try {
    hostname = new URL(details.url).hostname;
  } catch {
    return {};
  }

  // Skip whitelisted domains
  if (WHITELIST.has(hostname)) return {};

  const cached = urlCache[hostname];

  if (cached) {
    const age = Date.now() - cached.timestamp;

    // Cache hit: entry is fresh
    if (age < CACHE_EXPIRY_MS) {
      if (cached.status === "malicious") {
        console.warn("[Guardian] BLOCKED (cached):", hostname);
        notifyUser(hostname, cached.details);
        return { cancel: true };   // ← DROP THE CONNECTION
      }
      return {}; // safe, allow
    }
  }

  // Cache miss or expired: check asynchronously
  // We allow the current request through but flag hostname as "pending"
  // NOTE: For stronger security, you could cancel & re-check, but that
  // breaks UX for legitimate first-time visits. This is a good learning tradeoff to explore.
  if (!cached || cached.status !== "pending") {
    markPending(hostname);
    checkWithVirusTotal(hostname);
  }

  return {}; // allow while checking
}

// ============================================================
// VIRUSTOTAL: Submit URL for analysis
// ============================================================
async function checkWithVirusTotal(hostname) {
  console.log("[Guardian] Checking:", hostname);

  try {
    // Step 1: Submit URL to VT
    const submitRes = await fetch("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: {
        "x-apikey": VT_API_KEY,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: `url=${encodeURIComponent("https://" + hostname)}`,
    });

    if (!submitRes.ok) throw new Error(`VT submit failed: ${submitRes.status}`);
    const submitData = await submitRes.json();

    // Step 2: Get the analysis ID and fetch results
    // VT returns an analysis object — we poll for the result
    const analysisId = submitData.data.id;
    const resultRes = await fetch(
      `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
      { headers: { "x-apikey": VT_API_KEY } }
    );

    if (!resultRes.ok) throw new Error(`VT result failed: ${resultRes.status}`);
    const resultData = await resultRes.json();

    parseAndCacheResult(hostname, resultData);

  } catch (err) {
    console.error("[Guardian] VT check error:", err.message);
    // On error, mark as malicious to block by default
    cacheResult(hostname, "malicious", { error: err.message, malicious: -1 });
    notifyUser(hostname, { error: err.message, malicious: -1 });
    blockHostname(hostname);
  }
}

// ============================================================
// PARSE VT RESPONSE
// ============================================================
function parseAndCacheResult(hostname, data) {
  const stats = data?.data?.attributes?.stats;

  if (!stats) {
    console.warn("[Guardian] Unexpected VT response shape for", hostname);
    cacheResult(hostname, "safe", { malicious: 0, note: "No stats returned" });
    return;
  }

  const maliciousCount = stats.malicious || 0;
  const suspiciousCount = stats.suspicious || 0;
  const harmlessCount = stats.harmless || 0;

  const details = { malicious: maliciousCount, suspicious: suspiciousCount, harmless: harmlessCount };

  if (maliciousCount >= VT_THRESHOLD) {
    console.warn(`[Guardian] MALICIOUS: ${hostname} (${maliciousCount} engines)`);
    cacheResult(hostname, "malicious", details);
    notifyUser(hostname, details);
    // Block future requests by adding a dynamic rule
    blockHostname(hostname);
  } else {
    console.log(`[Guardian] SAFE: ${hostname} (${maliciousCount} malicious flags)`);
    cacheResult(hostname, "safe", details);
  }
}

// ============================================================
// CACHE HELPERS
// ============================================================
function markPending(hostname) {
  urlCache[hostname] = { status: "pending", timestamp: Date.now(), details: {} };
  persistCache();
}

function cacheResult(hostname, status, details) {
  urlCache[hostname] = { status, timestamp: Date.now(), details };
  persistCache();
}

function persistCache() {
  chrome.storage.local.set({ urlCache });
}

// ============================================================
// BLOCK: Dynamically block a hostname for future requests
// Uses declarativeNetRequest for MV3-compatible blocking
// ============================================================
let ruleIdCounter = 1000;

function blockHostname(hostname) {
  const ruleId = ruleIdCounter++;
  chrome.declarativeNetRequest.updateDynamicRules({
    addRules: [{
      id: ruleId,
      priority: 1,
      action: { type: "block" },
      condition: {
        urlFilter: `||${hostname}^`,
        resourceTypes: [
          "main_frame", "sub_frame", "script", "image",
          "stylesheet", "object", "xmlhttprequest", "other"
        ]
      }
    }],
    removeRuleIds: []
  });
}

// ============================================================
// NOTIFY: Show OS notification
// ============================================================
function notifyUser(hostname, details) {
  chrome.notifications.create(`guardian-${hostname}-${Date.now()}`, {
    type: "basic",
    iconUrl: "icons/icon48.png",
    title: "⚠️ Malicious URL Blocked",
    message: `${hostname} was blocked. Flagged by ${details.malicious} security engines.`,
    priority: 2
  });
}

// ============================================================
// MESSAGE PASSING: Popup asks for cache data
// ============================================================
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "GET_CACHE") {
    sendResponse({ cache: urlCache });
  }
  if (msg.type === "CLEAR_CACHE") {
    urlCache = {};
    chrome.storage.local.remove("urlCache");
    sendResponse({ ok: true });
  }
  if (msg.type === "REMOVE_ENTRY") {
    delete urlCache[msg.hostname];
    persistCache();
    sendResponse({ ok: true });
  }
  if (msg.type === "BLOCK_HOSTNAME") {
    const hostname = msg.hostname;
    cacheResult(hostname, "malicious", { manual: true, malicious: 1 });
    blockHostname(hostname);
    notifyUser(hostname, { manual: true, malicious: 1 });
    sendResponse({ ok: true });
  }
  return true; // keep channel open for async
});
