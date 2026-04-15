// popup.js — drives the extension popup UI

function timeAgo(ms) {
  const diff = Date.now() - ms;
  const m = Math.floor(diff / 60000);
  const h = Math.floor(diff / 3600000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  return `${h}h ago`;
}

function renderList(containerId, entries) {
  const container = document.getElementById(containerId);
  if (!entries.length) {
    container.innerHTML = `<div class="empty"><div class="empty-icon">${containerId.includes("malicious") ? "🔒" : "✅"}</div>No entries yet.</div>`;
    return;
  }

  container.innerHTML = entries.map(([host, data]) => `
    <div class="url-item">
      <div class="url-dot ${data.status}"></div>
      <div class="url-text" title="${host}">${host}</div>
      <div class="url-meta ${data.status === 'malicious' ? 'bad' : ''}">
        ${data.status === "malicious"
          ? `🚨 ${data.details?.malicious || "?"} engines`
          : data.status === "pending"
          ? "scanning..."
          : `✓ ${timeAgo(data.timestamp)}`}
      </div>
      <button class="remove-btn" data-host="${host}">✕</button>
    </div>
  `).join("");

  // Attach remove handlers
  container.querySelectorAll(".remove-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      chrome.runtime.sendMessage({ type: "REMOVE_ENTRY", hostname: btn.dataset.host }, () => {
        loadData();
      });
    });
  });
}

function loadData() {
  chrome.runtime.sendMessage({ type: "GET_CACHE" }, ({ cache }) => {
    const entries = Object.entries(cache);

    const safe      = entries.filter(([, v]) => v.status === "safe");
    const malicious = entries.filter(([, v]) => v.status === "malicious");
    const pending   = entries.filter(([, v]) => v.status === "pending");

    // Update stats
    document.getElementById("count-safe").textContent      = safe.length;
    document.getElementById("count-malicious").textContent = malicious.length;
    document.getElementById("count-pending").textContent   = pending.length;
    document.getElementById("cache-info").textContent      = `${entries.length} entr${entries.length === 1 ? "y" : "ies"} cached`;

    // Render lists — sort malicious first in "all" tab
    const allSorted = [...malicious, ...pending, ...safe];
    renderList("list-all", allSorted);
    renderList("list-malicious", malicious);
    renderList("list-safe", safe);
  });
}

// Tab switching
document.querySelectorAll(".tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
    tab.classList.add("active");
    document.getElementById(`tab-${tab.dataset.tab}`).classList.add("active");
  });
});

// Clear cache
document.getElementById("clear-btn").addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "CLEAR_CACHE" }, () => loadData());
});

// Initial load + auto-refresh while popup is open
loadData();
setInterval(loadData, 3000);
