<p align="center">
  <img src="https://img.shields.io/badge/SECURITY-DAST%20%26%20AUDIT-0ea5e9?style=for-the-badge&logo=shield&logoColor=white" alt="Security Suite" />
</p>

<h1 align="center">🛡️ DJOERAGANCYBER Security Suite</h1>

<p align="center">
  <strong>Universal Web & API Vulnerability Audit, Reconnaissance & Dynamic Security Testing Suite</strong>
</p>

<p align="center">
  <em>An enterprise-grade, full-stack DAST (Dynamic Application Security Testing) platform featuring automated vulnerability detection, passive OSINT reconnaissance, an interactive live security terminal, one-click PoC verification, and executive PDF audit reporting.</em>
</p>

<p align="center">
  <a href="#-key-features"><img src="https://img.shields.io/badge/Vulnerabilities-Active%20%26%20Passive-blue.svg?style=flat-square" alt="Vulnerabilities" /></a>
  <a href="https://fastapi.tiangolo.com/"><img src="https://img.shields.io/badge/Backend-FastAPI%20v0.110-009688.svg?style=flat-square&logo=fastapi&logoColor=white" alt="FastAPI" /></a>
  <a href="https://react.dev/"><img src="https://img.shields.io/badge/Frontend-React%2018%20%2B%20Vite-61dafb.svg?style=flat-square&logo=react&logoColor=black" alt="React" /></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.10%2B-3776ab.svg?style=flat-square&logo=python&logoColor=white" alt="Python" /></a>
  <a href="https://www.postgresql.org/"><img src="https://img.shields.io/badge/Database-SQLite%20%7C%20PostgreSQL-336791.svg?style=flat-square&logo=postgresql&logoColor=white" alt="Database" /></a>
  <a href="https://owasp.org/www-project-top-ten/"><img src="https://img.shields.io/badge/Compliance-OWASP%20Top%2010%20%26%20CVSS%20v3.1-orange.svg?style=flat-square" alt="Compliance" /></a>
  <a href="#-license"><img src="https://img.shields.io/badge/License-MIT-green.svg?style=flat-square" alt="License" /></a>
  <a href="#-contributing"><img src="https://img.shields.io/badge/PRs-Welcome-brightgreen.svg?style=flat-square" alt="PRs Welcome" /></a>
</p>

---

## 📑 Table of Contents

- [Overview](#-overview)
- [Target Versatility](#-target-versatility)
- [Key Features](#-key-features)
  - [1. Active Vulnerability Scanner](#1-active-vulnerability-scanner)
  - [2. Passive Reconnaissance & OSINT Engine](#2-passive-reconnaissance--osint-engine)
  - [3. Interactive Live Security Terminal Console](#3-interactive-live-security-terminal-console)
  - [4. Attack Surface Explorer & Live PoC Verifier](#4-attack-surface-explorer--live-poc-verifier)
  - [5. Compliance, Scoring & Executive PDF Reporting](#5-compliance-scoring--executive-pdf-reporting)
  - [6. Anti-SSRF Perimeter Protection](#6-anti-ssrf-perimeter-protection)
- [Tech Stack & Architecture](#-tech-stack--architecture)
- [Installation & Setup](#-installation--setup)
  - [Prerequisites](#prerequisites)
  - [Step 1: Clone the Repository](#step-1-clone-the-repository)
  - [Step 2: Environment Configuration](#step-2-environment-configuration)
  - [Step 3: Backend Setup](#step-3-backend-setup)
  - [Step 4: Frontend Setup](#step-4-frontend-setup)
  - [Alternative: One-Click Windows Launchers](#alternative-one-click-windows-launchers)
  - [Alternative: Docker & Docker Compose](#alternative-docker--docker-compose)
- [Directory Structure](#-directory-structure)
- [Live API Endpoints](#-live-api-endpoints)
- [Legal & Ethical Disclaimer](#-legal--ethical-disclaimer)
- [Contributing](#-contributing)
- [License](#-license)
- [GitHub Recommended Topics](#-github-recommended-topics-seo)

---

## 🌐 Overview

**DJOERAGANCYBER Security Suite** is an advanced open-source web application vulnerability scanner and security assessment platform. Built with high performance and defensive precision in mind, it bridges the gap between automated scanning tools and manual penetration testing.

Modern web applications are subjected to increasingly complex threats. DJOERAGANCYBER combines:
- **Asynchronous non-blocking architecture** powered by FastAPI, HTTPX, and WebSockets.
- **Deep active detection payloads** for critical OWASP Top 10 vulnerabilities.
- **Non-intrusive passive OSINT** gathering and SSL/TLS cryptographic validation.
- **Interactive live command console** enabling on-the-fly tactical security probes.
- **Instant Proof-of-Concept (PoC) verification** providing raw request/response telemetry.
- **Executive-grade PDF generation** with CVSS v3.1 calculation and web server remediation snippets.

---

## 🎯 Target Versatility

DJOERAGANCYBER is architected to safely and comprehensively audit various classes of mission-critical systems:

| Sector | Target Archetypes | Typical Audit Vectors |
|---|---|---|
| **🏥 Healthcare** | SIMRS (Hospital Management Systems), Electronic Medical Records (EMR) | Broken Access Control, Input Validation, PHI Data Exposure |
| **🏢 Enterprise** | ERP, Corporate Portals, Internal Admin Dashboards | SQL Injection, Sensitive File Fuzzing (`.env`, `.git`), SSO/JWT |
| **💳 Fintech & Banking** | Payment Gateways, Open Banking APIs, Core Services | CORS Misconfiguration, Insecure Headers, Session/Cookie Security |
| **🛒 E-Commerce** | Retail Stores, Inventory APIs, Customer Checkout | Cross-Site Scripting (XSS), Open Redirect, Template Injection |
| **🏛️ Public & Gov** | Public Service Portals, Civic Data Registries | DNS Hygiene, Subdomain Takeover, Outdated Component Fingerprints |
| **🎓 Higher Education** | SIAKAD (Academic Portals), Research Repositories | LFI / Directory Traversal, Directory Fuzzing, TLS Degradation |

---

## 🌟 Key Features

### 1. Active Vulnerability Scanner
- **SQL Injection (SQLi) Engine**: Detects Boolean-based Blind, Error-based, and Time-based Blind SQLi across GET/POST query parameters and form bodies.
- **Cross-Site Scripting (XSS) Analyzer**: Probes for Reflected, Stored, and DOM-based XSS vectors with HTML contextual sanitization checks.
- **Local File Inclusion (LFI) & Path Traversal**: Scans for system file exposures (`/etc/passwd`, `win.ini`, boot configurations) using diverse path encoding techniques.
- **Server-Side Template Injection (SSTI)**: Detects template execution vulnerabilities across Jinja2, Twig, Freemarker, and Smarty engines.
- **Open Redirect Scanner**: Identifies unvalidated parameter-based HTTP 30x redirections to third-party or hostile origins.
- **Sensitive File & Directory Fuzzer**: High-speed dictionary prober targeting critical leak paths: `.env`, `.git/HEAD`, `phpinfo.php`, `docker-compose.yml`, `actuator/env`, `backup.sql`, dump files, and server configs.
- **JWT (JSON Web Token) Security Analyzer**: Inspects `alg: none` vulnerabilities, weak secret signatures, token expiration claims, and header tampering.
- **CORS Misconfiguration Prober**: Verifies wildcard origins (`*`), arbitrary origin reflections, and null origin credential exposures (`Access-Control-Allow-Credentials: true`).
- **CSP (Content Security Policy) Auditor**: Evaluates `default-src`, `script-src` policies, `unsafe-inline`, `unsafe-eval`, and missing mitigation directives.
- **Deep Web Crawler & Form Extractor**: Recursive asynchronous web spider capable of mapping internal page hierarchies, extracting HTML form elements, and auto-populating parameter fuzz targets.

### 2. Passive Reconnaissance & OSINT Engine
- **DNS & Zone Intelligence**: Comprehensive record inspection (A, AAAA, MX, NS, TXT, SPF, DMARC, CNAME) to detect spoofing risks and email deliverability hygiene.
- **Subdomain Enumeration**: Passive discovery of exposed subdomains and target perimeters.
- **SSL/TLS Cryptographic Audit**: Real-time handshake examination, certificate expiry countdown, cipher suite strength evaluation, and Subject Alternative Names (SANs) mapping.
- **Certificate Transparency (crt.sh)**: Pulls public CT log history to discover past and obscure certificate issuances.
- **Web Application Firewall (WAF) Fingerprinting**: Signatures for Cloudflare, AWS WAF, Akamai, Imperva, ModSecurity, Sucuri, LiteSpeed, and others.
- **Technology & CVE Fingerprinting**: Identifies underlying server daemons (Nginx, Apache, IIS), backend runtimes, frontend frameworks, and known CVE signatures.
- **HTTP Security Header Compliance**: Grades HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.
- **Cookie Security Auditor**: Validates `HttpOnly`, `Secure`, and `SameSite` flags across all session cookies.

### 3. Interactive Live Security Terminal Console
Execute on-demand live audit commands against the target directly from the browser UI with instant streaming feedback:
```bash
> headers    # Comprehensive HTTP security header compliance analysis
> ssl        # Deep TLS handshake, cipher suite, and certificate inspection
> dns        # Complete DNS record mapping (A, MX, TXT, SPF, DMARC)
> waf        # Real-time Web Application Firewall fingerprinting
> portscan   # Async TCP probe on top web ports (80, 443, 8080, 8443, 3000, 8000, 9000)
> fuzz       # Targeted probe for high-risk sensitive paths (.env, .git, backup.sql)
> crawl      # Live web spider and form field parameter extraction
> methods    # Probe permitted HTTP verbs (OPTIONS, TRACE, PUT, DELETE) and CORS reflection
> robots     # Retrieve and parse robots.txt and sitemap.xml directives
> whois      # Target IP resolution, reverse PTR, ASN, and geo-location details
```

### 4. Attack Surface Explorer & Live PoC Verifier
- **Discovered Endpoints & Forms**: Interactive tree of discovered target pages and extracted form inputs with one-click injection tests.
- **Sensitive Paths Status Matrix**: Real-time HTTP status matrix (200, 301, 403, 404) with response byte sizes and exposure tags.
- **Custom Path Live Prober**: Submit arbitrary paths on the fly to inspect server reactions without initiating a full scan.
- **Live Proof-of-Concept (PoC) Verifier**: Every finding includes a live verification button that executes a fresh HTTP probe and displays raw request/response payloads in real-time.

### 5. Compliance, Scoring & Executive PDF Reporting
- **OWASP Top 10 (2021) Mapping**: Automated categorization against standard OWASP categories (A01 through A10).
- **CVSS v3.1 Calculator**: Accurate Base Score calculation using industry metrics (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`).
- **Severity & Exploitability Heatmap**: Dynamic risk classification ranging from *Trivial (1/5)* to *Expert (5/5)*.
- **Professional PDF Audit Reports**: Generates boardroom-ready reports with Executive Summaries, vulnerability matrices, raw PoC telemetry, and ready-to-use remediation configurations (Nginx & Apache).

### 6. Anti-SSRF Perimeter Protection
- Built-in strict IP filter that blocks unauthorized outbound scanning to:
  - Loopback addresses (`127.0.0.0/8`, `::1`)
  - RFC 1918 Private Networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
  - Link-Local & Cloud Metadata Endpoints (`169.254.169.254`)
  - Internal IPv6 ranges (`fc00::/7`, `fe80::/10`)
- Guarantees scanner safety and prevents the engine from being weaponized against local internal infrastructure.

---

## 🛠️ Tech Stack & Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      FRONTEND LAYER                         │
│   React 18  •  Vite 5  •  Tailwind CSS 3  •  Lucide Icons   │
│       (Interactive Terminal • Live Dashboard • Charts)      │
└──────────────────────────────┬──────────────────────────────┘
                               │ HTTP / WebSocket Stream
┌──────────────────────────────▼──────────────────────────────┐
│                       BACKEND API                           │
│        FastAPI (Python 3.10+)  •  Uvicorn  •  Pydantic v2   │
├─────────────────────────────────────────────────────────────┤
│                     ENGINE MODULES                          │
│  • Active Detectors (SQLi, XSS, LFI, SSTI, Fuzz, Crawl)     │
│  • Passive Recon (DNS, SSL/TLS, Headers, WAF, OSINT)        │
│  • Live Console Engine (Socket-based Live Command Dispatch) │
│  • Scoring & Compliance (CVSS v3.1 & OWASP 2021 Mapper)     │
│  • Reporting Engine (ReportLab PDF & Jinja2 Templating)     │
├──────────────────────────────┬──────────────────────────────┤
│  Persistence & Queue Layer:  │  Security Guardrails:        │
│  • SQLite (aiosqlite) /      │  • Strict Anti-SSRF Filter   │
│    PostgreSQL (asyncpg)      │  • Egress Rate-Limiting      │
│  • Redis & Celery (optional) │  • Timeout Enforcements      │
└─────────────────────────────────────────────────────────────┘
```

| Layer | Technologies | Description |
|---|---|---|
| **Frontend** | React 18, Vite 5, Tailwind CSS, Lucide React, PostCSS | Real-time reactive UI with dark theme, dynamic severity badges, and interactive terminal |
| **Backend** | Python 3.10+, FastAPI, Uvicorn, Pydantic v2 | High-concurrency asynchronous REST API and WebSocket engine |
| **HTTP Engine** | HTTPX (Async), BeautifulSoup4, lxml | Asynchronous HTTP client with connection pooling and HTML parsing |
| **Reconnaissance** | dnspython, cryptography, python-jose | DNS resolving, TLS certificate inspection, and JWT cryptanalysis |
| **Databases** | SQLite (`aiosqlite`), PostgreSQL (`asyncpg`, SQLAlchemy 2.0) | Zero-config SQLite out of the box; switchable to PostgreSQL via environment variable |
| **Task Broker** | Redis, Celery *(optional)* | Asynchronous distributed queue for enterprise background workloads |
| **Reporting** | ReportLab, Jinja2 | Clean, branded executive PDF security audit reports |

---

## 🚀 Installation & Setup

### Prerequisites
Make sure your system satisfies the following requirements:
- **Python**: `v3.10` or higher ([Download Python](https://www.python.org/downloads/))
- **Node.js**: `v18.x` or higher and **npm** ([Download Node.js](https://nodejs.org/))
- **Git**: Installed and configured in PATH ([Download Git](https://git-scm.com/))
- *(Optional)* **Docker & Docker Compose**: For containerized deployment

---

### Step 1: Clone the Repository
```bash
git clone https://github.com/rendikaangesti/APLIKASI-SCANNING-KERENTANAN-WEBSITE.git
cd APLIKASI-SCANNING-KERENTANAN-WEBSITE
```

---

### Step 2: Environment Configuration
Copy the example environment file into `.env`:
```bash
# On Linux / macOS / Git Bash
cp .env.example .env

# On Windows PowerShell
copy .env.example .env
```

Review and adjust settings inside `.env`:
```ini
# Database (Leave as default SQLite for zero-config run, or point to PostgreSQL)
DATABASE_URL=sqlite+aiosqlite:///./scanner.db

# Redis Message Broker (Optional for standalone mode)
REDIS_URL=redis://localhost:6379/0

# Security Secrets
SECRET_KEY=generate-a-secure-random-32-byte-key-here
ACCESS_TOKEN_EXPIRE_MINUTES=1440

# Scanner Engine Limits
MAX_CRAWL_DEPTH=2
MAX_CRAWL_PAGES=25
HTTP_TIMEOUT_SECONDS=8.0
```

> **Note:** By default, the application runs on **SQLite (`aiosqlite`)**, requiring zero database setup. The database tables and schemas will be created automatically on the first run.

---

### Step 3: Backend Setup
Open a terminal for the backend service:

```bash
# 1. Navigate to backend directory
cd backend

# 2. Create and activate Python virtual environment
# Windows:
python -m venv venv
.\venv\Scripts\activate

# Linux / macOS:
python3 -m venv venv
source venv/bin/activate

# 3. Install Python dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 4. Start the FastAPI server
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

The backend will be active at **`http://127.0.0.1:8000`**.  
Interactive Swagger API documentation is available at **`http://127.0.0.1:8000/docs`**.

---

### Step 4: Frontend Setup
Open a second terminal for the frontend service:

```bash
# 1. Navigate to frontend directory
cd frontend

# 2. Install Node.js packages
npm install

# 3. Start the Vite development server
npm run dev
```

The web interface will launch at **`http://localhost:3000`** (or `http://localhost:5173`).

---

### Alternative: One-Click Windows Launchers
For Windows users, pre-configured launcher scripts are provided:

- **`start-all.bat`**: Starts both the FastAPI backend and Vite frontend, then automatically opens your default browser at `http://localhost:3000`.
- **`start-backend.bat`**: Runs the backend service independently on port 8000.
- **`start-frontend.bat`**: Runs the frontend service independently on port 3000.

Simply double-click `start-all.bat` from File Explorer or execute:
```cmd
start-all.bat
```

---

### Alternative: Docker & Docker Compose
To spin up the entire stack (PostgreSQL 15, Redis 7, Backend API, and Celery Worker) using Docker:

```bash
# Build and launch all services in detached mode
docker-compose up -d --build

# View real-time container logs
docker-compose logs -f backend

# Stop all services
docker-compose down
```

Containerized services:
- **API Server**: `http://localhost:8000`
- **PostgreSQL**: `localhost:5432`
- **Redis**: `localhost:6379`

---

## 📁 Directory Structure

```text
APLIKASI-SCANNING-KERENTANAN-WEBSITE/
├── backend/                        # FastAPI Backend Application
│   ├── app/
│   │   ├── api/v1/                 # REST API & WebSocket Routers
│   │   │   ├── live.py             # Live terminal & exploration endpoints
│   │   │   ├── reports.py          # PDF generation & report downloads
│   │   │   ├── scans.py            # Scan management & scheduling
│   │   │   ├── targets.py          # Target profile management
│   │   │   └── ws.py               # WebSocket telemetry streaming
│   │   ├── core/                   # System core modules
│   │   │   ├── config.py           # Settings & environment variables
│   │   │   ├── database.py         # Async SQLAlchemy engine & auto-migration
│   │   │   └── security.py         # Anti-SSRF & auth protections
│   │   ├── engine/                 # Vulnerability Scanning Core
│   │   │   ├── active/             # Active vulnerability analyzers
│   │   │   │   ├── cors_analyzer.py
│   │   │   │   ├── crawler.py
│   │   │   │   ├── csp_analyzer.py
│   │   │   │   ├── db_integrity_checker.py
│   │   │   │   ├── dir_fuzzer.py
│   │   │   │   ├── input_validator.py
│   │   │   │   ├── jwt_analyzer.py
│   │   │   │   ├── lfi_detector.py
│   │   │   │   ├── open_redirect_detector.py
│   │   │   │   ├── sqli_detector.py
│   │   │   │   ├── ssti_detector.py
│   │   │   │   └── xss_analyzer.py
│   │   │   ├── live/               # Live interactive execution engine
│   │   │   │   └── live_engine.py
│   │   │   ├── passive/            # Passive reconnaissance analyzers
│   │   │   │   ├── cookie_auditor.py
│   │   │   │   ├── cve_fingerprint.py
│   │   │   │   ├── domain_relations.py
│   │   │   │   ├── email_finder.py
│   │   │   │   ├── header_analyzer.py
│   │   │   │   ├── ssl_tls_checker.py
│   │   │   │   ├── subdomain_enum.py
│   │   │   │   └── tech_detector.py
│   │   │   ├── reporting/          # Audit PDF & email dispatch
│   │   │   │   ├── email_reporter.py
│   │   │   │   └── pdf_generator.py
│   │   │   ├── scoring/            # Compliance & scoring engines
│   │   │   │   ├── compliance_benchmark.py
│   │   │   │   ├── cvss_v3.py
│   │   │   │   └── owasp_mapper.py
│   │   │   └── tasks.py            # Async scanning orchestration tasks
│   │   ├── models/                 # Database ORM models
│   │   ├── schemas/                # Pydantic validation schemas
│   │   └── main.py                 # FastAPI application entrypoint
│   ├── Dockerfile                  # Backend container configuration
│   ├── requirements.txt            # Python package dependencies
│   └── scanner.db                  # Local SQLite database (auto-generated)
│
├── frontend/                       # React + Vite Frontend Application
│   ├── src/
│   │   ├── App.jsx                 # Main security dashboard & interactive console
│   │   ├── index.css               # Tailwind CSS styles
│   │   └── main.jsx                # React entrypoint
│   ├── index.html                  # HTML template
│   ├── package.json                # Frontend dependencies & scripts
│   ├── tailwind.config.js          # Tailwind CSS design system config
│   ├── vite.config.js              # Vite server & proxy configuration
│   └── Dockerfile                  # Frontend container configuration
│
├── .env.example                    # Environment variable template
├── docker-compose.yml              # Multi-container orchestration (API, DB, Redis)
├── start-all.bat                   # 1-Click launcher for both Backend & Frontend
├── start-backend.bat               # 1-Click launcher for Backend
├── start-frontend.bat              # 1-Click launcher for Frontend
└── README.md                       # Documentation & usage guide
```

---

## 📡 Live API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/scans/` | Initiate a new security scan (`active` or `passive`) |
| `GET` | `/api/v1/scans/` | List all historical scan executions |
| `GET` | `/api/v1/scans/{id}` | Retrieve comprehensive scan details, status, and findings |
| `POST` | `/api/v1/scans/quick-intel` | Trigger instant passive intelligence reconnaissance |
| `POST` | `/api/v1/live/terminal-exec` | Execute real-time interactive terminal commands (`headers`, `ssl`, `dns`, etc.) |
| `POST` | `/api/v1/live/explore` | Retrieve live asset exploration and attack surface mapping data |
| `POST` | `/api/v1/live/verify-poc` | Execute live, single-click Proof-of-Concept verification for a finding |
| `GET` | `/api/v1/reports/{id}/pdf` | Generate and download an executive-grade PDF security audit report |
| `WS` | `/api/v1/ws/scans/{id}` | Real-time WebSocket channel for scan telemetry and live log streaming |
| `GET` | `/health` | Service health status check |

---

## ⚖️ Legal & Ethical Disclaimer

> [!WARNING]
> **USAGE OF THIS SOFTWARE FOR TARGETING INFRASTRUCTURE WITHOUT EXPLICIT PRIOR WRITTEN CONSENT IS STRICTLY PROHIBITED.**

This software is developed and published strictly for **educational purposes, defensive security auditing, and authorized vulnerability assessments**. 
- Developers, contributors, and maintainers assume **no responsibility or liability** for any misuse, damage, unauthorized access, or legal consequences arising from the utilization of this tool.
- Security researchers and penetration testers must adhere to local, national, and international cybersecurity laws (e.g., the *Computer Fraud and Abuse Act (CFAA)*, *UU ITE*, and *GDPR*).
- Always secure written authorization (Rules of Engagement) from the target system owner before executing active scans.

---

## 🤝 Contributing

Contributions make the open-source community an inspiring place to learn, innovate, and create. Any contributions you make are **greatly appreciated**.

1. **Fork** the repository
2. **Create a Feature Branch**:
   ```bash
   git checkout -b feature/AmazingDetector
   ```
3. **Commit your changes**:
   ```bash
   git commit -m "feat: Add GraphQL introspection active detector"
   ```
4. **Push to the Branch**:
   ```bash
   git push origin feature/AmazingDetector
   ```
5. **Open a Pull Request** with a detailed explanation of your changes.

---

## 📄 License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for more details.

---

## 🏷️ GitHub Recommended Topics (SEO)

To optimize discoverability on GitHub, add the following topics to your repository settings:

```text
vulnerability-scanner, dast, cybersecurity, penetration-testing, web-security, owasp-top-10, fast-api, react, sqli-detector, xss-scanner, security-audit, security-tools, reconnaissance, osint, cvss, python, information-security, bug-bounty
```

---

<p align="center">
  Crafted with ❤️ by <a href="https://github.com/rendikaangesti"><strong>Rendika Angesti</strong></a> & the Open Source Security Community
</p>
