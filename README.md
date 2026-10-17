# ScamShield 🛡️

**Evidence-Based Multi-Vector Scam, Phishing & Fraud Detection Engine**  
Built for **Vedathon 2.0**.

ScamShield is an offline-first, explainable cybersecurity tool designed to protect everyday users and enterprise triage teams against social engineering attacks, credential phishing, and malicious attachments. Every score is backed by transparent, deterministic evidence flags, next-step recommendations, and clear defensive limitations.

---

## 🚀 Key Capabilities

| Vector | Capabilities | Engine Details |
|---|---|---|
| 🌐 **URL Scanner** | Typosquatting, Cyrillic/Greek homoglyphs, brand spoofing, IP hosts, URL shorteners, open redirects, multiple subdomains | Heuristic pattern matching against 25+ top targeted brands & internationalized domain names (IDN/Punycode). |
| 💬 **Message Scanner** | Smishing, banking suspensions (SBI, HDFC), KBC lottery traps, task/job scams, crypto seed phrase drainers, urgency cues | Multi-signal synergy analysis (e.g., prize lure + secrecy demands = critical fraud). |
| 📧 **Email Forensics** | Header authentication parsing (SPF, DKIM, DMARC), `From` vs. `Reply-To` mismatches, impersonation flags | MIME header parser & security verification logic. |
| 📱 **QR Code Inspector** | Scans QR images for hidden URLs, UPI payment requests, wifi credentials, and malicious payload targets | Decodes image matrix, extracts payload targets, and passes embedded URLs to URL scanner. |
| 📎 **File Attachment Safety** | Static metadata inspection, executable/macro detection in Office documents and ZIPs, double extension tricks (`.exe.pdf`) | Purely static binary signature and archive inspection (never executes untrusted code). |

---

## 🏛️ Architecture Overview

```
ScamShield/
├── scamshield-backend/
│   ├── main.py                     # FastAPI application, REST endpoints, SQLite history store
│   ├── requirements.txt            # Python dependencies (FastAPI, uvicorn, pillow, pyzbar, pytest, httpx)
│   ├── test_analyzers.py           # 71 comprehensive unit & integration tests
│   └── analyzer/
│       ├── url_analyzer.py         # URL structure, syntax, and threat heuristics
│       ├── url_heuristics.py       # TLD flags, suspicious subdomains, keywords
│       ├── advanced_checks.py      # Homoglyphs, Levenshtein typosquatting, shortener checks
│       ├── message_analyzer.py     # SMS, WhatsApp, and social engineering threat parser
│       ├── email_analyzer.py       # Header forensics (SPF, DKIM, DMARC, Reply-To)
│       ├── qr_analyzer.py          # QR matrix decoder and payload inspector
│       └── file_analyzer.py        # Static file inspection, magic bytes, archive contents
└── scamshield-frontend/
    ├── src/
    │   ├── App.jsx                 # Routing and navigation shell with sidebar
    │   ├── api.js                  # Frontend client communicating with FastAPI backend
    │   ├── utils.js                # UI formatting, risk color tokens, date formatters
    │   └── pages/
    │       ├── DashboardPage.jsx   # Threat posture, aggregate metrics, quick scan cards
    │       ├── ScanPage.jsx        # Unified URL & message scanning interface
    │       ├── EmailPage.jsx       # Email header & body forensic analyzer
    │       ├── QRPage.jsx          # QR code image uploader and payload evaluator
    │       ├── FilePage.jsx        # Safe static attachment analyzer
    │       ├── HistoryPage.jsx     # SQLite scan history with export capabilities
    │       ├── DemoPage.jsx        # Preloaded real-world scam cases for validation
    │       ├── LearnPage.jsx       # Educational center for common attack vectors
    │       └── SettingsPage.jsx    # System configuration & backend health monitoring
    └── vite.config.js              # Vite dev server with /api proxy to localhost:8000
```

---

## 🛠️ Getting Started

### 1. Backend Setup

```bash
cd scamshield-backend

# Install dependencies
pip install -r requirements.txt

# Run automated test suite (71 tests)
pytest test_analyzers.py -v

# Start FastAPI server
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

Backend will be available at: `http://localhost:8000`  
Interactive Swagger API docs: `http://localhost:8000/docs`

### 2. Frontend Setup

```bash
cd scamshield-frontend

# Install dependencies
npm install

# Run Vite dev server
npm run dev
```

Frontend will be available at: `http://localhost:5173`

---

## 📡 API Endpoints Reference

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | System health check and uptime |
| `GET` | `/readiness` | Dependency readiness checks (Pillow, PyZbar, SQLite) |
| `POST` | `/analyze/url` | Evaluates URL structure, homoglyphs, and brand spoofing |
| `POST` | `/analyze/message` | Analyzes text for urgency, financial bait, credentials, and impersonation |
| `POST` | `/analyze/email` | Header forensics (SPF, DKIM, Reply-To) + message body analysis |
| `POST` | `/analyze/qr` | Decodes QR code image and evaluates payload risk |
| `POST` | `/analyze/file` | Static metadata inspection of uploaded files |
| `GET` | `/history` | Query logged scans with optional category and limit filters |
| `GET` | `/stats` | Aggregate scan statistics and threat breakdown |
| `GET` | `/demo-cases` | List curated real-world demo cases |
| `POST` | `/demo-cases/{id}/run` | Execute analysis on a labeled demo case |

All `/analyze/*` and data endpoints are also mounted under `/api` and `/api/v1` for backwards compatibility.

---

## 🔒 Security & Defensive Principles

- **No Fabricated Intelligence:** All threat scores and flags are calculated deterministically by inspected rules and algorithms.
- **Explainability First:** Every flag comes with human-readable rationale and actionable next steps.
- **Defensive Limitations:** Results explicitly communicate that static heuristics cannot replace antivirus execution sandboxes, and negative signals do not guarantee total safety.
- **Safe Static File Handling:** File attachments are inspected strictly via byte signatures and archive headers without execution.
