// content.js — injected into every page
// Listens for messages from background.js to show an in-page warning

chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === "SHOW_WARNING") {
    showBanner(msg.hostname, msg.details);
  }
});

function showBanner(hostname, details) {
  // Avoid duplicate banners
  if (document.getElementById("guardian-banner")) return;

  const banner = document.createElement("div");
  banner.id = "guardian-banner";
  banner.style.cssText = `
    position: fixed;
    top: 0; left: 0; right: 0;
    background: #1a0000;
    border-bottom: 2px solid #ff3a3a;
    color: #ff9999;
    font-family: 'JetBrains Mono', monospace, monospace;
    font-size: 13px;
    padding: 12px 20px;
    z-index: 2147483647;
    display: flex;
    align-items: center;
    justify-content: space-between;
    box-shadow: 0 4px 20px rgba(255,0,0,0.3);
  `;

  banner.innerHTML = `
    <span>⚠️ <strong style="color:#ff3a3a">URL Guardian blocked a request</strong> to <code style="background:#2a0000;padding:2px 6px;border-radius:3px">${hostname}</code> — flagged by ${details?.malicious || "multiple"} security engines.</span>
    <button onclick="this.parentElement.remove()" style="background:none;border:1px solid #ff3a3a;color:#ff3a3a;cursor:pointer;padding:4px 10px;font-family:inherit;font-size:11px;border-radius:4px">DISMISS</button>
  `;

  document.body.prepend(banner);

  // Auto-dismiss after 8 seconds
  setTimeout(() => banner?.remove(), 8000);
}
