# URL Guardian —A Chrome Extension

A cybersecurity learning project: intercept all browser requests, check them against
VirusTotal, blocks malicious URLs, and maintains a local cache of results.

---

## Setup

### 1. Get a VirusTotal API Key
- Sign up free at https://virustotal.com
- Go to your profile → API Key
- Free tier: 4 requests/minute, 500/day (plenty for learning)

### 2. Add your key
Open `background.js` and replace line 9:
```js
const VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY_HERE";
```

### 3. Create placeholder icons (for loading the extension)
Create an `icons/` folder and add PNG files: `icon16.png`, `icon48.png`, `icon128.png`
You can use any placeholder images while developing.

### 4. Load in Chrome
1. Open `chrome://extensions`
2. Enable **Developer Mode** (top right)
3. Click **Load unpacked**
4. Select this project folder

---

## File Structure

```
url-guardian/
├── manifest.json     # Extension config, permissions
├── background.js     # Core logic: intercept → cache → VirusTotal
├── popup.html        # Extension popup UI
├── popup.js          # Popup data rendering
├── content.js        # In-page warning banner
└── icons/
    ├── icon16.png
    ├── icon48.png
    └── icon128.png
```

---

## How It Works

```
Browser makes request
        │
        ▼
background.js intercepts (webRequest.onBeforeRequest)
        │
        ├─ Is hostname in cache?
        │     ├─ YES + malicious → CANCEL request + notify
        │     ├─ YES + safe      → allow through
        │     └─ YES + expired   → re-check
        │
        └─ NOT in cache → allow through, async check VT
                │
                ▼
          VirusTotal API
          POST /api/v3/urls   (submit)
          GET  /api/v3/analyses/{id} (result)
                │
                ├─ malicious >= threshold (2)
                │     → cache as malicious
                │     → add declarativeNetRequest block rule
                │     → show OS notification
                │
                └─ safe
                      → cache as safe for 24h
```

---

## Key Concepts Demonstrated

| Concept | Where |
|---|---|
| `chrome.webRequest` API | `background.js` → `handleRequest()` |
| `chrome.declarativeNetRequest` | `background.js` → `blockHostname()` |
| VirusToal REST API | `background.js` → `checkWithVirusTotal()` |
| `chrome.storage.local` (persistence) | `background.js` → `persistCache()` |
| `chrome.notifications` | `background.js` → `notifyUser()` |
| Message passing (background ↔ popup) | `background.js` + `popup.js` |
| Content script injection | `content.js` |

---

## Possible Extensions (pun intended)

- [ ] Add **WHOIS lookup** as fallback when VT has no data
- [ ] Add **IP geolocation** — flag requests to unusual cuontries
- [ ] Export blocklist as JSON
- [ ] Add a settings page for configuring the VT threshold
- [ ] Support **regex-based custom block rules**
- [ ] Add rate-limit handling for VT free tier (queue + delay)
- [ ] Show VT scan details (which engines flagged it) in the popup

## Disclaimer
- [ ] AI was used to debug and modify parts of the code for this project.
- [ ] This is should not be used in commercial or enterprise set ups as there are many things that can go wrong.

## Learning Outcomes
- [ ] Understanding the structure and creation of a chrome extension.
- [ ] Intercepting web requests before load
- [ ] Understand the limitations of chrome.webRequest.onBeforeRequest
- [ ] Domain reputation checks
