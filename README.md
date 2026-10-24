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
| 🛡️ **RBAC & Super Admin Panel** | User management, granular permissions, session control, audit trail, external threat feeds, and live theme management | Role-based access control (Super Admin / Admin), bcrypt hashing, HttpOnly JWT cookies. |
| 🌌 **3D Multiverse Experience** | Full-screen Three.js WebGL 3D parallax background, particle dust, rotating energy rings, and dynamic threat typing animations | Responsive Three.js WebGL space with `codeverse-art.webp`, `hero-01.webp`, `hero-02.webp`, `hero-03.webp`, and `codeverse-hero.gif`. |

---

## 🏛️ Architecture Overview

```
ScamShield/
├── scamshield-backend/
│   ├── main.py                     # FastAPI application v3.0, routers, CORS & rate limiting
│   ├── database.py                 # SQLite schema (users, sessions, audit_log, notifications, settings)
│   ├── auth.py                     # Bcrypt hashing, JWT generation/validation, role dependencies
│   ├── admin_routes.py             # Auth & Admin REST routes (/auth/*, /admin/*, /superadmin/*)
│   ├── requirements.txt            # Python dependencies (FastAPI, uvicorn, slowapi, jose, etc.)
│   ├── test_analyzers.py           # 71 threat engine analyzer tests
│   ├── test_admin_auth.py          # 9 authentication, superadmin, RBAC, and persistence tests (80 tests total)
│   └── analyzer/
│       ├── url_analyzer.py         # URL structure, syntax, and threat heuristics
│       ├── advanced_checks.py      # Homoglyphs, Levenshtein typosquatting, shortener checks
│       ├── message_analyzer.py     # SMS, WhatsApp, and social engineering threat parser
│       ├── email_analyzer.py       # Header forensics (SPF, DKIM, DMARC, Reply-To)
│       ├── qr_analyzer.py          # QR matrix decoder and payload inspector
│       └── file_analyzer.py        # Static file inspection, magic bytes, archive contents
└── scamshield-frontend/
    ├── src/
    │   ├── App.jsx                 # Routing, AuthProvider, ThemeProvider, and responsive navigation shell
    │   ├── api.js                  # Frontend client communicating with FastAPI backend
    │   ├── utils.js                # UI formatting, permissions list, risk color tokens
    │   ├── context/
    │   │   ├── AuthContext.jsx     # User authentication state, role-check hooks
    │   │   └── ThemeContext.jsx    # Database-connected live theme & visual intensity manager
    │   ├── components/
    │   │   ├── HeroBackground.jsx  # Fullscreen multiverse 3D backdrop (codeverse-art.webp)
    │   │   ├── ThreeMultiverseScene.jsx # Three.js WebGL 3D particle dust and rotating energy rings
    │   │   ├── MultiverseHeroCards.jsx  # Themed cards (hero-01.webp, hero-02.webp, hero-03.webp, codeverse-hero.gif)
    │   │   ├── FuturisticCursor.jsx# Interactive glowing desktop neon cursor
    │   │   ├── ParticleCanvas.jsx  # 2D canvas particle fallback
    │   │   ├── NotificationBell.jsx# Real-time alert bell with unread badge & dropdown
    │   │   ├── TypingPlaceholder.jsx # Dynamic typing animation for realistic scam prompts
    │   │   ├── ResultPanel.jsx     # Threat score, verdict, evidence breakdowns
    │   │   └── ScoreRing.jsx       # Circular SVG risk meter
    │   └── pages/
    │       ├── DashboardPage.jsx   # Threat posture, aggregate metrics, Multiverse Sentinel Matrix
    │       ├── ScanPage.jsx        # Unified URL & message scanning interface with typing placeholder

    │       ├── EmailPage.jsx       # Email header & body forensic analyzer
    │       ├── QRPage.jsx          # QR code image uploader and payload evaluator
    │       ├── FilePage.jsx        # Safe static attachment analyzer
    │       ├── HistoryPage.jsx     # SQLite scan history with export capabilities
    │       ├── DemoPage.jsx        # Preloaded real-world scam cases for validation
    │       ├── LearnPage.jsx       # Educational center for common attack vectors
    │       ├── admin/
    │       │   ├── AdminLogin.jsx  # Secure login with lockout & initial password reset
    │       │   └── AdminDashboard.jsx # Admin metrics, permissions check & recent scans
    │       └── superadmin/
    │           └── SuperAdminDashboard.jsx # Full management (user CRUD, audit logs, themes)
    └── vite.config.js              # Vite dev server with /api proxy to localhost:8000
```

---

## 🛠️ Getting Started

### 1. Backend Setup

```bash
cd scamshield-backend

# Install dependencies
pip install -r requirements.txt

# Run automated test suite (76 tests)
pytest -v

# Start FastAPI server
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

Backend will be available at: `http://localhost:8000`  
Interactive Swagger API docs: `http://localhost:8000/docs`

> **Super Admin Initial Credentials:**  
` (Set via `SUPERADMIN_INITIAL_PASSWORD` in `.env`)

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
| `POST` | `/auth/login` | Authenticate user & return HttpOnly JWT cookie |
| `POST` | `/auth/logout` | Revoke session & clear auth cookie |
| `GET` | `/auth/me` | Fetch active user profile and permissions |
| `POST` | `/auth/change-password` | Update current user password |
| `GET` | `/admin/dashboard-stats` | Admin metrics (user counts, scans, audit events) |
| `GET` | `/admin/notifications` | Unread system alerts & notifications |
| `GET` | `/superadmin/users` | List all administrator accounts (Super Admin only) |
| `POST` | `/superadmin/users` | Create new admin with granular permissions |
| `PATCH` | `/superadmin/users/{id}` | Activate, suspend, or update permissions |
| `GET` | `/superadmin/audit-log` | Immutable security audit trail |
| `GET` | `/superadmin/settings` | App settings & available theme configurations |
| `PATCH` | `/superadmin/settings/theme` | Switch active theme in real-time |

All `/analyze/*` and data endpoints are also mounted under `/api` and `/api/v1` for backwards compatibility.

---

## 🔒 Security & Defensive Principles

- **No Fabricated Intelligence:** All threat scores and flags are calculated deterministically by inspected rules and algorithms.
- **Explainability First:** Every flag comes with human-readable rationale and actionable next steps.
- **Defensive Limitations:** Results explicitly communicate that static heuristics cannot replace antivirus execution sandboxes, and negative signals do not guarantee total safety.
- **Safe Static File Handling:** File attachments are inspected strictly via byte signatures and archive headers without execution.
- **Brute-Force & Lockout Defenses:** Enforces 5 failed attempt rate-limiting with 15-minute account lockouts and mandatory initial password resets.

---

## 🎨 Official Brand Identity & Assets

- **Brand Artwork:** `scamshield-logo.png` (Futuristic cyan-armored security sentinel, neon cyber shield with embedded 'S' checkmark, and ScamShield wordmark).
- **Dashboard Experience:** Exclusive dynamic background (`dashboard-art.jpg` / Pic 1) with cosmic drift, energy ring pulses, and scanline sweeps.
- **Scanner & Sub-Pages:** High-visibility original multiverse sentinel backdrop (`codeverse-art.webp`) with balanced contrast and dark translucent glass cards.
- **Dedicated Favicons:** Shield-only vector and raster assets:
  - SVG: `/shield-symbol.svg`
  - PNG 32×32: `/favicon-32.png`
  - PNG 16×16: `/favicon-16.png`
  - Apple Touch Icon 180×180: `/apple-touch-icon.png`
  - High-Res 512×512: `/shield-icon.png`
- **Real Threat Intelligence:** URLhaus (abuse.ch) live public threat feed integration with optional server-side VirusTotal & Google Safe Browsing adapters.

