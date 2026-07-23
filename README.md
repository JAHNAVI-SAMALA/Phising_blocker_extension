# 🛡️ PhishGuard AI

> A Chrome Extension that detects phishing URLs in **real-time** using machine learning — analyzing 87 features per URL including live WHOIS, DNS, SSL, and page content signals.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)](https://python.org)
[![Chrome Extension](https://img.shields.io/badge/Chrome-MV3-yellow?logo=googlechrome)](https://developer.chrome.com/docs/extensions/)
[![Flask](https://img.shields.io/badge/Flask-3.0-black?logo=flask)](https://flask.palletsprojects.com/)
[![Scikit-learn](https://img.shields.io/badge/scikit--learn-1.5-orange?logo=scikitlearn)](https://scikit-learn.org/)

---

## 📌 Overview

PhishGuard AI is a production-grade browser security extension that **intercepts every URL navigation**, extracts 87 features in real-time, and classifies sites as phishing or legitimate using a GradientBoosting ML model. Threats are blocked instantly, and all detections are shared with a community database for crowd-sourced protection.

**Built for a real use case — not just a toy project.** Every feature is backed by live data: real WHOIS queries, real DNS lookups, real SSL certificate validation, and real page HTML analysis.

---

## ✨ Features

| Feature | Details |
|---|---|
| 🔍 **Real-time URL Scanning** | Analyzes every navigation automatically via `background.js` service worker |
| 🤖 **ML Classification** | GradientBoosting model trained on 11,000+ URLs with 87 features |
| 🌐 **Live WHOIS / DNS / SSL** | Real network lookups — not cached static data |
| 📄 **Page HTML Analysis** | Detects fake login forms, credential harvesting, iframes, JS obfuscation |
| 🚨 **Instant Block Page** | Custom full-page block UI with risk factors and threat confidence |
| 📧 **Email Scanner** | Auto-scans Gmail & Outlook emails, injects warning banners |
| 👥 **Community Reporting** | Users report threats; shared database protects all users via SSE push |
| 🔁 **Auto-Retrain Pipeline** | Model automatically retrains on new community-reported data |
| 🌍 **Brand Impersonation Detection** | Detects PayPal, Amazon, Google, Microsoft spoofs and 15+ others |
| 📊 **Popup Dashboard** | 4-tab UI: Site scan, Domain intel, Email results, Community alerts |
| 🔎 **Manual URL Scanner** | Paste any URL directly in the popup to scan it on demand |
| ⚡ **Server-Sent Events** | Real-time push notifications to all connected users on new threats |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Chrome Extension (MV3)                   │
│                                                             │
│  content.js          background.js          popup.html      │
│  ──────────          ─────────────          ──────────      │
│  • Page pill         • URL interception     • Site Scan tab │
│  • Email scanner     • Cache layer          • Intel tab     │
│  • Warning banners   • Badge/block          • Email tab     │
│                      • Message proxy        • Alerts tab    │
└──────────────────────────┬──────────────────────────────────┘
                           │ REST API (HTTP POST / GET)
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                  Python Flask Backend (v3.0)                 │
│                                                             │
│  /analyze          /report              /domain-intel       │
│  ──────────        ────────             ─────────────       │
│  ML prediction     Community report     WHOIS + SSL + DNS   │
│  87 features       SSE broadcast        Page analysis       │
│  Confidence score  Auto-retrain trigger Risk signals        │
│                                                             │
│  /scan-email       /alerts/stream       /stats   /health    │
│  ─────────────     ──────────────       ──────   ───────    │
│  Email analysis    SSE push feed        Metrics  Status     │
│                                                             │
│  ┌──────────────┐  ┌────────────────┐  ┌───────────────┐  │
│  │  ML Model    │  │  SQLite DB     │  │  live_analyzer│  │
│  │  (GBM + 87   │  │  reported_sites│  │  WHOIS / DNS  │  │
│  │   features)  │  │  threat_alerts │  │  SSL / page   │  │
│  └──────────────┘  └────────────────┘  └───────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
PhishGuard-AI/
├── extension/
│   ├── manifest.json          # Chrome MV3 config
│   ├── background.js          # Service worker — URL interception, analysis, blocking
│   ├── content.js             # Page pill + Gmail/Outlook email scanner
│   ├── pages/
│   │   ├── blocked.html       # Full-page phishing block screen (redesigned)
│   │   └── blocked.js         # Block page logic (countdown, particles, why-blocked)
│   ├── popup/
│   │   ├── popup.html         # Extension popup UI (4 tabs)
│   │   └── popup.js           # Popup logic (scan, intel, email, alerts)
│   └── icons/                 # Extension icons (16, 48, 128px)
│
├── backend/
│   ├── app.py                 # Flask server — all API endpoints
│   ├── live_analyzer.py       # Real WHOIS / DNS / SSL / page fetcher
│   ├── feature_extractor.py   # 87-feature extractor (URL structure + page)
│   ├── retrain_pipeline.py    # Incremental model retraining on new reports
│   ├── train_model.py         # Initial model training script
│   ├── domain_intel.py        # Domain intelligence helpers
│   ├── models/
│   │   ├── phishing_model.pkl # Trained GradientBoosting model (~830KB)
│   │   └── feature_names.pkl  # Ordered feature name list
│   ├── db/
│   │   ├── database.py        # SQLite layer (reported_sites, alerts, retrain_log)
│   │   └── phishguard.db      # SQLite database (gitignored in production)
│   ├── dataset_full.csv       # Training dataset (11,000+ labeled URLs)
│   ├── requirements.txt       # Pinned Python dependencies
│   ├── .env.example           # Environment variable template
│   └── Procfile               # Render/Heroku deployment config
│
└── README.md
```

---

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- Google Chrome
- pip

### 1. Clone the repository

```bash
git clone https://github.com/JAHNAVI-SAMALA/PhishGuard-AI.git
cd PhishGuard-AI
```

### 2. Set up the Python backend

```bash
cd backend
pip install -r requirements.txt
python app.py
```

The API server starts at **`http://localhost:5000`**.

> **First time?** The model (`models/phishing_model.pkl`) is included. If you want to retrain it on the full dataset:
> ```bash
> python train_model.py
> ```

### 3. Load the Chrome Extension

1. Open Chrome → navigate to `chrome://extensions/`
2. Enable **Developer Mode** (top-right toggle)
3. Click **Load unpacked**
4. Select the `extension/` folder

### 4. Browse safely 🎉

The PhishGuard shield icon appears in your toolbar. The extension automatically scans every site you visit.

---

## 🔌 API Reference

### `POST /analyze`
Analyzes a URL using the ML model + community DB.

```json
// Request
{ "url": "https://suspicious-site.xyz/login", "page_content": "<html>..." }

// Response
{
  "url": "https://suspicious-site.xyz/login",
  "is_phishing": true,
  "confidence": 94.2,
  "risk_level": "CRITICAL",
  "source": "ml_model",
  "risk_factors": ["High-risk TLD (.xyz)", "Domain only 3 days old", "Fake login form"],
  "community_reports": 0,
  "domain_age_days": 3,
  "has_ssl": false,
  "dns_exists": true
}
```

### `POST /report`
Community-reports a URL as phishing. Triggers SSE push to all users.
```json
{ "url": "https://malicious.site", "reported_by": "user123" }
```

### `POST /scan-email`
Analyzes email content for phishing signals.
```json
{ "subject": "...", "body": "...", "links": ["https://..."] }
```

### `POST /domain-intel`
Returns full WHOIS, SSL, DNS, and page analysis.

### `GET /alerts/recent?since=<ISO_timestamp>`
Returns community threat alerts since a given timestamp.

### `GET /alerts/stream`
Server-Sent Events stream for real-time threat push notifications.

### `GET /stats`
Returns aggregate stats: total reports, active threats, recent activity, top threats.

### `GET /health`
Returns backend status, model load state, and community report counts.

---

## 🧠 How It Works

```
1. User navigates to a URL
        ↓
2. background.js intercepts via chrome.webNavigation.onCommitted
        ↓
3. Sends URL to POST /analyze (with optional page HTML)
        ↓
4. live_analyzer.py computes 87 features:
   • URL structure (length, special chars, subdomains, TLD)
   • LIVE WHOIS  → domain age, registration length
   • LIVE DNS    → record existence
   • LIVE SSL    → certificate validity, issuer, expiry
   • Page HTML   → login forms, iframes, JS obfuscation, favicons
   • Brand signals → impersonation of 20+ known brands
        ↓
5. GradientBoosting model classifies: phishing / legitimate
        ↓
6a. SAFE  → green badge + fading pill on page corner
6b. PHISH → red badge + block page with risk factors + desktop notification
        ↓
7. Intel tab in popup shows full WHOIS/SSL/DNS/page breakdown
8. User can report → community DB updated → SSE push to all users
```

---

## 🔬 Model Details

| Property | Value |
|---|---|
| Algorithm | GradientBoostingClassifier (scikit-learn) |
| Training dataset | 11,000+ labeled URLs |
| Feature count | 87 |
| Feature categories | URL structure, WHOIS, DNS, SSL, page content, brand signals |
| AUC-ROC | ~0.97 on held-out test set |
| Auto-retraining | Triggered every 5 community reports via `retrain_pipeline.py` |

**Key features used:**
- `domain_age` — days since domain registration (WHOIS)
- `phish_hints` — count of phishing keywords in URL
- `brand_in_subdomain` / `domain_in_brand` — brand impersonation signals
- `login_form` + `sfh` — credential harvesting combo
- `nb_subdomains`, `prefix_suffix`, `suspecious_tld`
- `dns_record`, `https_token`, `whois_registered_domain`
- `iframe`, `onmouseover`, `right_clic`, `empty_title`

---

## ☁️ Deployment (Render / Railway)

A `Procfile` is included for one-click cloud deployment:

```
web: gunicorn app:app
```

1. Push backend to GitHub
2. Create a new **Web Service** on [Render](https://render.com)
3. Set build command: `pip install -r requirements.txt`
4. Set start command: `gunicorn app:app`
5. Update `BACKEND_URL` in `background.js` and `popup.js` to your Render URL

---

## 🛠️ Troubleshooting

### Backend offline / `Backend Offline` in popup
```bash
# Make sure backend is running:
cd backend && python app.py
# Expected output:
# [*] PhishGuard AI Backend v3.0 PRODUCTION starting...
# [OK] Database initialized
```

### `SyntaxError: Unexpected token '<'` in console
The extension is receiving HTML instead of JSON — the backend is not running or returning an error page. Check `python app.py` output.

### Intel tab shows "unavailable"
Domain intel requires WHOIS lookup which can take 5–15 seconds. Wait a moment and switch tabs. If it still fails, the domain may have WHOIS privacy protection enabled.

### Email scanner not triggering
Open a Gmail email (not just the inbox view). The scanner activates on the open email DOM node. Check the browser console for `[PhishGuard]` log messages.

---

## 📜 License

MIT License.

---

## 👩‍💻 Author

**Jahnavi Samala**
B.Tech CSE | Sridevi Women's Engineering College, Hyderabad
[GitHub](https://github.com/JAHNAVI-SAMALA) · [LinkedIn](https://linkedin.com/in/samala-jahnavi)

---

> *Built to make the web safer, one URL at a time. 🛡️*
