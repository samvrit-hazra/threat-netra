# Threat Netra
### Integrated Multi-Vector Threat Intelligence & Counter-Surveillance Infrastructure

[![FastAPI](https://img.shields.io/badge/FastAPI-0.143.0-009688?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python)](https://python.org)
[![Supabase](https://img.shields.io/badge/Auth%20%26%20DB-Supabase-3ECF8E?style=flat-square&logo=supabase)](https://supabase.com)
[![AI Engine](https://img.shields.io/badge/AI%20Inference-Groq%20%2B%20Gemma%202-FF6F00?style=flat-square)](https://groq.com)
[![Mapping](https://img.shields.io/badge/GIS-OpenStreetMap%20%2B%20Leaflet-7EBC6F?style=flat-square&logo=openstreetmap)](https://openstreetmap.org)
[![Aesthetic](https://img.shields.io/badge/UI%20Design-Palantir%20Gotham%20Defense-000000?style=flat-square)](#)

---

## 1. Executive Overview

**Threat Netra** is an all-in-one defense intelligence and counter-threat operations platform engineered for defense analysts, governmental investigators, and cyber incident responders. It fuses cyber attack telemetry, real-world geopolitical crisis feeds, synthetic social identity detection, automated PDF contract forensics, and OS/network log telemetry into a single unified operational picture.

Built on an austere, high-precision defense software aesthetic (inspired by Palantir Gotham & Foundry), Threat Netra adheres to zero-trust architecture, role-partitioned access controls, and strict hallucination-defense reconciliation.

---

## 2. Mission-Critical Intelligence Suites

Threat Netra is partitioned into four modular intelligence vectors, deployable independently or fused for multi-domain correlation:

### 📡 01 // Autonomous Threat Feed Monitor & Spatial GIS (`/tools/feed_monitor`)
- **Multi-Source Ingestion**: Real-time syndication from Bing News OSINT search and Telegram channels (via RSS-Bridge).
- **Autonomous Scenario Triggering**: Correlates live incoming dispatches against customizable threat matrices (e.g., missile strikes, terror incidents, national citizen data leaks).
- **Tactical Spatial GIS (Leaflet + OpenStreetMap)**: Autonomous entity geolocation mapping for war, kinetic strikes, and border security incidents with zero external API key requirements.
- **VirusTotal IOC Scanner**: Integrated observable inspection for suspicious URLs, domains, and malicious payloads.

### 👤 02 // Account Authenticity & Synthetic Identity Detection (`/tools/profile_auth`)
- **Tier-Partitioned Collection**:
  - *Normal Tier*: Legal OSINT search syntax compiler (dorks for Google, Bing, LinkedIn, GitHub).
  - *Governmental Tier*: Automated deep profile scraping, follower/following network graph analysis, and Wayback Machine historical archive interrogation (`https://web.archive.org/web/*/https://twitter.com/USERNAME/status/*`).
- **AI Counter-Intelligence Engine (Groq LPU / Google Gemma 2)**:
  - **Fake Account Probability Percentage (`0% – 100%`)**: Large visual risk gauge calculating synthetic bot vs. organic human probability.
  - **Strategic Verdict**: High-confidence classification (`HIGH PROBABILITY SYNTHETIC BOT`, `SUSPICIOUS`, `AUTHENTIC OPERATOR`).
  - **Archival Tenure Forensics**: Wayback Machine snapshot timeline analysis.
  - **Raw Telemetry Export**: One-click JSON dossier download (`threatnetra_profile_telemetry_<target>.json`) with clean, suppressed screen clutter.

### 📄 03 // Legal Contract & Document Intelligence (`/tools/contract_intel`)
- **Pure PDF Ingestion**: PyMuPDF-based bitstream parsing supporting multi-page Adobe PDF agreements up to 25MB with zero text boxes.
- **Verbatim Hallucination Defense Engine**: Strict Levenshtein distance string reconciliation (via RapidFuzz) guaranteeing all cited trap clauses exist verbatim in the source text.
- **Financial Liability (TCO) Modeling**: Automatic calculation of minimum initial commitments, auto-renewal escalation surcharges, and non-refundable setup fees.
- **Targeted Tactical Q&A**: Session-cached document interrogation returning verifiable citations and page anchors.
- **Dual PDF Comparison Matrix**: Side-by-side differential analysis of restrictive vs. flexible agreements with variance highlighting.

### 🛡️ 04 // AI Network & OS Log Analyzer (`/tools/logs_analyze`)
- **Multi-Format Ingestion**: Native parsing for Syslog RFC 5424/3164, Apache/Nginx combined access logs, iptables/firewall traces, and Windows Event logs.
- **Continuous Log Analyzer**: Live continuous stream parsing with automatic threat scoring (`NOMINAL` to `CRITICAL`).
- **Heuristic Threat Detection**: Rapid identification of SQL Injection, Path Traversal, SSH Brute Force, and Port Sweeping.
- **AI Incident Briefings**: One-click generation of structured Markdown incident reports with instant copy and downloadable export.

---

## 3. Role-Based Clearance (RBAC) Architecture

Threat Netra enforces a four-tier access hierarchy authenticated via Supabase:

| Clearance Level | Role Identifier | Capabilities & Permissions |
| :--- | :--- | :--- |
| **Project Owner / Admin** | `admin` | Full operational clearance. Approves/rejects prospective user registrations, modifies clearance tiers, and accesses all tools. |
| **Governmental User** | `governmental_user` | Elevated clearance. Grants access to deep automated scrapers, Wayback Machine historical CDX scraping, and advanced AI threat models. |
| **Standard Analyst** | `normal_user` | Standard clearance. Accesses OSINT dork synthesis, PDF contract audits, and log analysis. Direct scraping disabled for legal compliance. |
| **Demo / Evaluation** | `demo` | Instant evaluation account pre-configured with full platform access for demonstrations. |

---

## 4. Technology Stack

- **Backend Framework**: Python 3.10+ & FastAPI (Asynchronous ASGI)
- **Frontend Architecture**: Jinja2 Server-Side Templates, CSS Custom Properties (Tokens), Vanilla JavaScript, Zero heavy frontend dependencies.
- **Design System**: Strict Palantir Gotham Defense UI (`#000000` pitch black, 0px radius, Inter + JetBrains Mono).
- **Authentication & Database**: Supabase (PostgreSQL, Row-Level Security, JWT session handling).
- **AI Inference Engine**:
  - Primary: Groq Cloud LPU (`openai/gpt-oss-120b` or `llama-3.3-70b-versatile`) for ultra-low latency inference.
  - Failover: Google Gemma 2 (`gemma-4-26b-a4b-it`) via Google AI Studio.
  - Offline Backup: Deterministic cybersecurity heuristic engines for 100% uptime.
- **Document & PDF Processing**: PyMuPDF (`pymupdf`), RapidFuzz string distance matching.
- **Geospatial Mapping**: OpenStreetMap (OSM) Tiles via Leaflet.js.

---

## 5. Directory Structure

```plaintext
threat-netra/
├── src/
│   ├── auth/                       # Supabase auth, RBAC dependencies, and admin panel
│   │   ├── backend/
│   │   └── frontend/
│   ├── dashboard/                  # Central operational command deck
│   ├── landing/                    # High-impact landing page & tactical TOC showcase
│   ├── shared/                     # Global base templates, Palantir design tokens, CSS
│   │   └── frontend/static/css/    # tokens.css, style.css
│   ├── tools/
│   │   ├── contract_intel/         # PDF contract audits, TCO costs, and dual diff
│   │   │   ├── backend/            # extractor.py, validator.py, engine.py, costs.py
│   │   │   └── frontend/
│   │   ├── feed_monitor/           # Threat feeds, OSM spatial GIS, VirusTotal
│   │   ├── logs_analyze/           # Network & syslog parser, continuous monitor, AI reports
│   │   └── profile_auth/           # Account scanner, Wayback CDX, AI fake probability
│   │       ├── backend/            # bing_scanner.py, twitter_archive.py, ai_analyzer.py
│   │       └── frontend/
│   └── main.py                     # Root FastAPI application & route registration
├── tests/                          # Integration and diagnostic test suite
├── supabase_schema.sql             # Database tables, triggers, and RLS policies
├── requirements.txt                # Frozen Python package dependencies
├── run.bat / run.ps1               # Quickstart scripts for Windows
└── .env.example                    # Template environment variables
```

---

## 6. Installation & Quickstart

### Prerequisites
- Python 3.10 or higher
- Git
- Active internet connection for feed syndication and AI inference

### Step 1: Clone Repository & Create Virtual Environment
```bash
git clone <repository_url>
cd "Threat Netra"

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate       # On Linux / macOS
# .venv\Scripts\activate        # On Windows
```

### Step 2: Install Package Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 3: Configure Environment Variables
Copy the template configuration file:
```bash
cp .env.example .env
```
Open `.env` and fill in your credentials:
```ini
# AI Inference Configuration
AI_PROVIDER=groq                     # "groq" or "gemma"
GROQ_API_KEY=your_groq_api_key_here
GROQ_MODEL=openai/gpt-oss-120b
GEMMA_API_KEY=your_gemma_api_key_here
GEMMA_MODEL=gemma-4-26b-a4b-it

# Supabase Authentication & Database
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your_supabase_anon_key_here
SUPABASE_SERVICE_ROLE_KEY=your_supabase_service_role_key_here

# Administrator Email (automatically granted admin role upon signup)
OWNER_EMAIL=admin@threatnetra.com

# Demo Account Credentials (instant evaluation access)
DEMO_EMAIL=demo@threatnetra.com
DEMO_PASSWORD=threatnetra-demo-2026
```

### Step 4: Initialize Supabase Database
Execute the SQL commands in [`supabase_schema.sql`](supabase_schema.sql) in your Supabase SQL Editor. This sets up user profiles, roles, and Row Level Security (RLS) policies.

### Step 5: Start Threat Netra Server
```bash
# Using Python directly:
python -m uvicorn src.main:app --host 127.0.0.1 --port 8000 --reload

# Or on Windows using batch script:
run.bat
```

Open your browser and navigate to:
**`http://localhost:8000`**

---

## 7. Diagnostics & Automated Testing

Threat Netra includes an automated test suite to verify route stability, AI provider latency, and log parsing:

```bash
# Run log parser & detector unit tests
python -m unittest tests/test_logs_analyze.py

# Run AI API connectivity and latency diagnostics
python test_ai_apis.py

# Run full route smoke test
python -c "
from fastapi.testclient import TestClient
from src.main import app
from src.auth.backend.dependencies import require_approved_user

app.dependency_overrides[require_approved_user] = lambda: {'email': 'admin@threatnetra.com', 'role': 'admin'}
client = TestClient(app)

for r in ['/', '/dashboard', '/tools/contract_intel', '/tools/feed_monitor', '/tools/logs_analyze', '/tools/profile_auth']:
    assert client.get(r).status_code == 200, f'Route {r} failed'
print('All operational routes verified successfully.')
"
```

---

## 8. Responsible Use & Security Notice

Threat Netra is designed for legitimate security research, defensive posture auditing, contract verification, and counter-disinformation monitoring.
- Automated scraping vectors are restricted by strict role-based access control (RBAC).
- Respect platform terms of service and legal regulations when utilizing OSINT reconnaissance tools.
- Never deploy credentials or `.env` files into public version control.

---

## 9. License

Proprietary defense intelligence software. Developed for Threat Netra Operations. All rights reserved &copy; 2026.
