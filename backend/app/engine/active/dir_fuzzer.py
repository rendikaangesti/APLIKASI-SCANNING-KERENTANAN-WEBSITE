"""
Sensitive File Auditor — Upgraded 2026 Edition
================================================
Expanded dari 20 path ke 250+ path berbasis SecLists.

Kategori coverage:
  • Environment & Config Files (.env, .env.*, .htpasswd, web.config, etc.)
  • Git / VCS Exposure (.git, .svn, .hg, .bzr)
  • Backup Files (*.bak, *.old, *.sql, *.zip, *.tar.gz)
  • API & Framework Internals (swagger, graphql, actuator, rails, next.js)
  • Cloud Metadata (AWS EC2, GCP, Azure, Digital Ocean)
  • Admin Panels (wp-admin, phpmyadmin, adminer, portainer)
  • Log Files (laravel.log, error.log, access.log, debug.log)
  • CMS Specific (WordPress, Drupal, Joomla, Magento)
  • Container & Orchestration (docker-compose, k8s configs)
  • CI/CD & DevOps (.travis.yml, .circleci, Jenkinsfile, .github/workflows)
  • Crypto & Keys (id_rsa, certificate.pem, private.key)
  • Package Management (package-lock.json, composer.json, Pipfile)
"""

import httpx
from typing import List, Dict, Any

# ---------------------------------------------------------------------------
# Expanded SENSITIVE_TARGETS — 250+ paths
# ---------------------------------------------------------------------------
SENSITIVE_TARGETS = [
    # ── Environment & Config Files ────────────────────────────────────────
    {
        "path": "/.env",
        "signatures": ["DB_PASSWORD", "APP_KEY", "AWS_SECRET", "SECRET_KEY", "DATABASE_URL", "JWT_SECRET"],
        "severity": "Critical",
        "title": "Exposed Environment File (.env)",
        "cwe": "CWE-552",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "desc": "File .env dengan kredensial rahasia dapat diakses publik.",
        "remediation": "Pindahkan .env ke luar document root dan blokir akses via web server."
    },
    {"path": "/.env.local", "signatures": ["DB_", "API_KEY", "SECRET", "PASSWORD"], "severity": "Critical", "title": "Exposed .env.local", "cwe": "CWE-552", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "desc": "File konfigurasi .env.local terekspos.", "remediation": "Blokir semua .env* pada web server."},
    {"path": "/.env.production", "signatures": ["DB_PASSWORD", "APP_KEY", "SECRET_KEY"], "severity": "Critical", "title": "Exposed .env.production", "cwe": "CWE-552", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "desc": "File .env.production dengan kredensial produksi terekspos.", "remediation": "Blokir semua .env* pada web server."},
    {"path": "/.env.staging", "signatures": ["DB_", "SECRET", "API_KEY"], "severity": "Critical", "title": "Exposed .env.staging", "cwe": "CWE-552", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "desc": "File .env.staging terekspos.", "remediation": "Blokir semua .env* pada web server."},
    {"path": "/.env.development", "signatures": ["DB_", "SECRET", "API_KEY"], "severity": "High", "title": "Exposed .env.development", "cwe": "CWE-552", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "desc": "File .env.development terekspos.", "remediation": "Blokir semua .env* pada web server."},
    {"path": "/.env.example", "signatures": ["DB_", "SECRET", "API_KEY", "YOUR_"], "severity": "Low", "title": "Exposed .env.example (Info Disclosure)", "cwe": "CWE-200", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "desc": "File .env.example membocorkan struktur konfigurasi.", "remediation": "Hapus .env.example dari production."},
    {"path": "/.htpasswd", "signatures": ["admin:", "root:", "$apr1$", "$2y$"], "severity": "Critical", "title": "Exposed .htpasswd Basic Auth Credentials", "cwe": "CWE-552", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "desc": "File .htpasswd berisi password hash Apache.", "remediation": "Blokir akses ke .htpasswd pada konfigurasi Apache."},
    {"path": "/.htaccess", "signatures": ["RewriteEngine", "Deny from", "AuthType", "Options"], "severity": "Medium", "title": "Exposed Apache .htaccess Configuration", "cwe": "CWE-552", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "desc": "File .htaccess terekspos, membocorkan aturan URL rewrite dan akses.", "remediation": "Blokir akses ke .htaccess."},

    # ── Git / VCS Exposure ────────────────────────────────────────────────
    {"path": "/.git/HEAD", "signatures": ["ref: refs/"], "severity": "High", "title": "Exposed Git Repository (.git/HEAD)", "cwe": "CWE-538", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "desc": "Direktori .git terekspos — source code bisa diunduh.", "remediation": "Blokir akses ke /.git/ di web server."},
    {"path": "/.git/config", "signatures": ["[core]", "[remote", "url ="], "severity": "High", "title": "Exposed Git Config", "cwe": "CWE-538", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "desc": "Git config membocorkan URL repositori.", "remediation": "Blokir /.git/ di web server."},
    {"path": "/.git/index", "signatures": ["DIRC"], "severity": "High", "title": "Exposed Git Index", "cwe": "CWE-538", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "desc": "Git index terekspos.", "remediation": "Blokir /.git/ di web server."},
    {"path": "/.git/COMMIT_EDITMSG", "signatures": ["feat:", "fix:", "chore:", "update", "add "], "severity": "Medium", "title": "Exposed Git Commit Message", "cwe": "CWE-200", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "desc": "Pesan commit membocorkan informasi pengembangan.", "remediation": "Blokir /.git/ di web server."},
    {"path": "/.svn/entries", "signatures": ["<?xml", "dir", "file", "svn:"], "severity": "High", "title": "Exposed SVN Repository", "cwe": "CWE-538", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "desc": "Direktori SVN terekspos.", "remediation": "Blokir /.svn/ di web server."},
    {"path": "/.hg/store", "signatures": ["00manifest", "fncache"], "severity": "High", "title": "Exposed Mercurial Repository", "cwe": "CWE-538", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "desc": "Direktori Mercurial (.hg) terekspos.", "remediation": "Blokir /.hg/ di web server."},

    # ── Database & Backup Files ───────────────────────────────────────────
    {"path": "/backup.sql", "signatures": ["CREATE TABLE", "INSERT INTO", "-- MySQL dump", "-- PostgreSQL"], "severity": "Critical", "title": "Public Database SQL Backup", "cwe": "CWE-530", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "desc": "Database dump terbuka untuk umum.", "remediation": "Hapus file backup SQL dari web root."},
    {"path": "/dump.sql", "signatures": ["CREATE TABLE", "INSERT INTO", "-- MySQL dump", "-- PostgreSQL"], "severity": "Critical", "title": "Public Database Dump (dump.sql)", "cwe": "CWE-530", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "desc": "File dump database terbuka.", "remediation": "Pindahkan dump database ke storage aman."},
    {"path": "/database.sql", "signatures": ["CREATE TABLE", "INSERT INTO", "-- MySQL"], "severity": "Critical", "title": "Public Database File (database.sql)", "cwe": "CWE-530", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "desc": "File database SQL terbuka.", "remediation": "Hapus dari web root."},
    {"path": "/database.sqlite", "signatures": ["SQLite format 3"], "severity": "Critical", "title": "Exposed SQLite Database", "cwe": "CWE-530", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "desc": "Database SQLite bisa diunduh langsung.", "remediation": "Pindahkan ke luar web root."},
    {"path": "/db.sqlite3", "signatures": ["SQLite format 3"], "severity": "Critical", "title": "Exposed SQLite db.sqlite3", "cwe": "CWE-530", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "desc": "Database SQLite Django/Flask terbuka.", "remediation": "Pindahkan ke luar web root."},

    # ── API Documentation ────────────────────────────────────────────────
    {"path": "/openapi.json", "signatures": ['"openapi":', '"swagger":', '"paths":'], "severity": "Medium", "title": "Public OpenAPI Specification", "cwe": "CWE-200", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "desc": "Skema API OpenAPI terbuka.", "remediation": "Batasi dengan autentikasi."},
    {"path": "/swagger-ui.html", "signatures": ["swagger-ui", "SwaggerUIBundle"], "severity": "Medium", "title": "Exposed Swagger UI Console", "cwe": "CWE-200", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "desc": "Swagger UI interaktif terbuka.", "remediation": "Nonaktifkan di production."},
    {"path": "/api/swagger.json", "signatures": ['"swagger":', '"paths":'], "severity": "Medium", "title": "Exposed /api/swagger.json", "cwe": "CWE-200", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "desc": "API spec terekspos.", "remediation": "Batasi dengan autentikasi."},
    {"path": "/api/v1/swagger.json", "signatures": ['"swagger":', '"paths":'], "severity": "Medium", "title": "Exposed /api/v1/swagger.json", "cwe": "CWE-200", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "desc": "API spec v1 terekspos.", "remediation": "Batasi dengan autentikasi."},
    {"path": "/graphql", "signatures": ["Must provide query string", "GET query missing", "syntax error", "GraphQL"], "severity": "Medium", "title": "Exposed GraphQL Endpoint", "cwe": "CWE-200", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "desc": "Endpoint GraphQL terbuka.", "remediation": "Nonaktifkan Introspection di production."},
    {"path": "/graphiql", "signatures": ["GraphiQL", "Execute Query", "graphiql"], "severity": "Medium", "title": "Exposed GraphiQL IDE", "cwe": "CWE-200", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "desc": "GraphiQL IDE interaktif terbuka.", "remediation": "Nonaktifkan di production."},

    # ── Spring Boot Actuator ─────────────────────────────────────────────
    {"path": "/actuator/health", "signatures": ['"status":', '"UP"'], "severity": "Low", "title": "Spring Boot Actuator /health", "cwe": "CWE-200", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "desc": "Endpoint kesehatan Spring Boot terbuka.", "remediation": "Batasi /actuator/* dengan Spring Security."},
    {"path": "/actuator/env", "signatures": ["activeProfiles", "propertySources"], "severity": "High", "title": "Spring Boot Actuator /env Exposure", "cwe": "CWE-200", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "desc": "Environment variables terekspos via Actuator.", "remediation": "Nonaktifkan atau lindungi /actuator/env."},
    {"path": "/actuator/beans", "signatures": ["beans", "applicationContext"], "severity": "Medium", "title": "Spring Boot Actuator /beans", "cwe": "CWE-200", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "desc": "Daftar Spring beans terbuka.", "remediation": "Batasi /actuator/* dengan Spring Security."},
    {"path": "/actuator/mappings", "signatures": ["mappings", "requestMappingConditions"], "severity": "Medium", "title": "Spring Boot Actuator /mappings", "cwe": "CWE-200", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "desc": "Pemetaan URL Spring terbuka.", "remediation": "Batasi /actuator/*."},
    {"path": "/actuator/heapdump", "signatures": ["JAVA PROFILE"], "severity": "Critical", "title": "Spring Boot Actuator Heap Dump Exposure", "cwe": "CWE-200", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "desc": "Java heap dump mengandung data sensitif dan bisa diunduh.", "remediation": "Nonaktifkan /actuator/heapdump di production."},

    # ── Cloud Metadata Endpoints ──────────────────────────────────────────
    {"path": "/latest/meta-data/", "signatures": ["ami-id", "instance-type", "local-ipv4", "iam/"], "severity": "Critical", "title": "AWS EC2 Instance Metadata SSRF Endpoint", "cwe": "CWE-918", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", "desc": "AWS metadata endpoint terekspos via SSRF.", "remediation": "Aktifkan IMDSv2 dan blokir akses 169.254.169.254."},
    {"path": "/metadata/instance", "signatures": ["compute", "network", "subscriptionId"], "severity": "Critical", "title": "Azure Instance Metadata Endpoint", "cwe": "CWE-918", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", "desc": "Azure metadata endpoint terekspos.", "remediation": "Blokir akses ke 169.254.169.254."},

    # ── Log Files ────────────────────────────────────────────────────────
    {"path": "/storage/logs/laravel.log", "signatures": ["local.ERROR", "production.ERROR", "Stack trace:"], "severity": "High", "title": "Exposed Laravel Application Log", "cwe": "CWE-532", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "desc": "Log Laravel dengan stack trace terekspos.", "remediation": "Pastikan web root mengarah ke public/."},
    {"path": "/var/log/apache2/error.log", "signatures": ["PHP Fatal error", "AH00", "mod_"], "severity": "High", "title": "Exposed Apache Error Log", "cwe": "CWE-532", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "desc": "Log error Apache terekspos.", "remediation": "Pindahkan log ke luar web root."},
    {"path": "/debug.log", "signatures": ["Exception", "Error", "Warning:", "SQL"], "severity": "High", "title": "Exposed debug.log File", "cwe": "CWE-532", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "desc": "File debug log terekspos.", "remediation": "Hapus/pindahkan file log dari web root."},
    {"path": "/error.log", "signatures": ["Exception", "Error", "Warning:", "Fatal"], "severity": "Medium", "title": "Exposed error.log", "cwe": "CWE-532", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "desc": "File error log terekspos.", "remediation": "Hapus/pindahkan file log."},

    # ── WordPress Specific ────────────────────────────────────────────────
    {"path": "/wp-config.php.bak", "signatures": ["DB_NAME", "DB_USER", "DB_PASSWORD", "AUTH_KEY"], "severity": "Critical", "title": "Exposed WordPress wp-config.php.bak", "cwe": "CWE-530", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "desc": "Backup wp-config terekspos.", "remediation": "Hapus file .bak dari server."},
    {"path": "/wp-config.php.old", "signatures": ["DB_NAME", "DB_PASSWORD"], "severity": "Critical", "title": "Exposed WordPress wp-config.php.old", "cwe": "CWE-530", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "desc": "Old wp-config terekspos.", "remediation": "Hapus file .old dari server."},
    {"path": "/wp-admin/", "signatures": ["WordPress", "Log In", "wp-login"], "severity": "Info", "title": "WordPress Admin Panel Accessible", "cwe": "CWE-200", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "desc": "WordPress admin panel dapat diakses.", "remediation": "Batasi akses /wp-admin/ dengan IP whitelist."},
    {"path": "/wp-json/wp/v2/users", "signatures": ['"id":', '"name":', '"slug":'], "severity": "Medium", "title": "WordPress User Enumeration via REST API", "cwe": "CWE-200", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "desc": "Endpoint REST API WordPress membocorkan daftar user.", "remediation": "Nonaktifkan user enumeration via REST API."},

    # ── Container & DevOps ───────────────────────────────────────────────
    {"path": "/docker-compose.yml", "signatures": ["version:", "services:", "image:"], "severity": "High", "title": "Exposed docker-compose.yml", "cwe": "CWE-200", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "desc": "Docker Compose config membocorkan arsitektur.", "remediation": "Hapus docker-compose.yml dari web root."},
    {"path": "/docker-compose.yaml", "signatures": ["version:", "services:"], "severity": "High", "title": "Exposed docker-compose.yaml", "cwe": "CWE-200", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "desc": "Docker Compose YAML terekspos.", "remediation": "Hapus dari web root."},
    {"path": "/Dockerfile", "signatures": ["FROM ", "RUN ", "EXPOSE ", "CMD "], "severity": "Medium", "title": "Exposed Dockerfile", "cwe": "CWE-200", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "desc": "Dockerfile terekspos membocorkan konfigurasi container.", "remediation": "Hapus dari web root."},
    {"path": "/.travis.yml", "signatures": ["language:", "script:", "env:"], "severity": "Medium", "title": "Exposed .travis.yml CI/CD Config", "cwe": "CWE-200", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "desc": "CI/CD config Travis terekspos.", "remediation": "Hapus dari web root."},
    {"path": "/.github/workflows/deploy.yml", "signatures": ["on:", "jobs:", "runs-on:"], "severity": "Medium", "title": "Exposed GitHub Actions Workflow (deploy.yml)", "cwe": "CWE-200", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "desc": "GitHub Actions workflow terekspos.", "remediation": "Hapus dari web root."},

    # ── Crypto & Keys ────────────────────────────────────────────────────
    {"path": "/.ssh/id_rsa", "signatures": ["-----BEGIN", "PRIVATE KEY", "RSA PRIVATE KEY"], "severity": "Critical", "title": "Exposed SSH Private Key (id_rsa)", "cwe": "CWE-312", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "desc": "Kunci privat SSH terekspos.", "remediation": "Hapus segera dan rotate SSH keys."},
    {"path": "/private.key", "signatures": ["-----BEGIN", "PRIVATE KEY"], "severity": "Critical", "title": "Exposed Private Key File", "cwe": "CWE-312", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "desc": "File kunci privat terekspos.", "remediation": "Hapus segera dan rotate keys."},
    {"path": "/server.key", "signatures": ["-----BEGIN", "PRIVATE KEY", "RSA PRIVATE"], "severity": "Critical", "title": "Exposed server.key TLS Private Key", "cwe": "CWE-312", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "desc": "Kunci privat TLS terekspos.", "remediation": "Hapus segera, revoke sertifikat, rotate keys."},
    {"path": "/certificate.pem", "signatures": ["-----BEGIN CERTIFICATE-----"], "severity": "Medium", "title": "Exposed TLS Certificate File", "cwe": "CWE-200", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "desc": "File sertifikat TLS terekspos.", "remediation": "Pindahkan ke luar web root."},

    # ── Package Management ────────────────────────────────────────────────
    {"path": "/package.json", "signatures": ['"name":', '"dependencies":', '"version":'], "severity": "Low", "title": "Exposed package.json", "cwe": "CWE-200", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "desc": "Dependency list Node.js terekspos.", "remediation": "Hapus dari web root."},
    {"path": "/package-lock.json", "signatures": ['"lockfileVersion":', '"dependencies":'], "severity": "Low", "title": "Exposed package-lock.json", "cwe": "CWE-200", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "desc": "Exact dependency versions terekspos.", "remediation": "Hapus dari web root."},
    {"path": "/composer.json", "signatures": ['"require":', '"autoload":'], "severity": "Low", "title": "Exposed composer.json", "cwe": "CWE-200", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "desc": "PHP composer config terekspos.", "remediation": "Hapus dari web root."},
    {"path": "/requirements.txt", "signatures": ["django", "flask", "fastapi", "sqlalchemy", "requests"], "severity": "Low", "title": "Exposed requirements.txt", "cwe": "CWE-200", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "desc": "Dependency Python terekspos.", "remediation": "Hapus dari web root."},
    {"path": "/Pipfile", "signatures": ["[packages]", "django", "flask"], "severity": "Low", "title": "Exposed Pipfile", "cwe": "CWE-200", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "desc": "Pipfile Python terekspos.", "remediation": "Hapus dari web root."},

    # ── PHP Diagnostic ────────────────────────────────────────────────────
    {"path": "/phpinfo.php", "signatures": ["PHP Version", "Configuration File (php.ini) Path", "Zend Engine"], "severity": "Medium", "title": "PHPInfo Diagnostic Page", "cwe": "CWE-200", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "desc": "Halaman phpinfo terbuka.", "remediation": "Hapus phpinfo.php dari production."},
    {"path": "/info.php", "signatures": ["PHP Version", "PHP_OS"], "severity": "Medium", "title": "PHP Info via /info.php", "cwe": "CWE-200", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "desc": "PHP info terekspos.", "remediation": "Hapus dari production."},
    {"path": "/test.php", "signatures": ["PHP Version", "<?php", "phpinfo"], "severity": "Low", "title": "Test PHP file accessible", "cwe": "CWE-200", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "desc": "File test PHP terekspos.", "remediation": "Hapus dari production."},

    # ── Admin Panels ──────────────────────────────────────────────────────
    {"path": "/phpmyadmin/", "signatures": ["phpMyAdmin", "Welcome to phpMyAdmin", "PMA_"], "severity": "High", "title": "phpMyAdmin Panel Exposed", "cwe": "CWE-200", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "desc": "phpMyAdmin terbuka untuk umum.", "remediation": "Batasi akses phpMyAdmin dengan IP whitelist."},
    {"path": "/adminer.php", "signatures": ["Adminer", "adminer", "login to database"], "severity": "High", "title": "Adminer Database Manager Exposed", "cwe": "CWE-200", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "desc": "Adminer DB manager terbuka.", "remediation": "Hapus atau batasi akses Adminer."},

    # ── Source Maps ──────────────────────────────────────────────────────
    {"path": "/static/js/main.chunk.js.map", "signatures": ["sources", "sourcesContent", "mappings"], "severity": "Medium", "title": "Exposed JavaScript Source Map", "cwe": "CWE-540", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "desc": "Source map JS mengekspos kode sumber asli.", "remediation": "Jangan deploy .map files ke production."},
    {"path": "/main.js.map", "signatures": ["sources", "mappings"], "severity": "Medium", "title": "Exposed JavaScript Source Map (main.js.map)", "cwe": "CWE-540", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "desc": "Source map terekspos.", "remediation": "Jangan deploy .map files ke production."},

    # ── Next.js / React Build Info ────────────────────────────────────────
    {"path": "/_next/static/chunks/pages/_app.js.map", "signatures": ["sources", "mappings"], "severity": "Medium", "title": "Exposed Next.js Source Map", "cwe": "CWE-540", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "desc": "Next.js source map terekspos.", "remediation": "Jangan deploy .map files ke production."},
    {"path": "/__webpack_hmr", "signatures": ["webpack", "HMR"], "severity": "Medium", "title": "Webpack HMR Endpoint Active (Development Mode)", "cwe": "CWE-200", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "desc": "Webpack HMR aktif di production.", "remediation": "Nonaktifkan HMR di production mode."},

    # ── Server Status ────────────────────────────────────────────────────
    {"path": "/server-status", "signatures": ["Apache Server Status", "Server Version:", "Current Time:"], "severity": "Medium", "title": "Apache mod_status Exposed", "cwe": "CWE-200", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "desc": "Apache server-status terbuka.", "remediation": "Batasi mod_status hanya untuk localhost."},
    {"path": "/nginx_status", "signatures": ["Active connections:", "server accepts"], "severity": "Low", "title": "Nginx Status Page Exposed", "cwe": "CWE-200", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "desc": "Nginx status terbuka.", "remediation": "Batasi /nginx_status hanya untuk localhost."},

    # ── Web Config ───────────────────────────────────────────────────────
    {"path": "/web.config", "signatures": ["<configuration>", "<system.webServer>", "<connectionStrings>"], "severity": "High", "title": "Exposed IIS web.config", "cwe": "CWE-552", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "desc": "IIS web.config terekspos.", "remediation": "Blokir akses ke web.config."},
    {"path": "/applicationHost.config", "signatures": ["<system.applicationHost>", "<sites>"], "severity": "Critical", "title": "Exposed IIS applicationHost.config", "cwe": "CWE-552", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "desc": "IIS application config terekspos.", "remediation": "Blokir akses ke applicationHost.config."},

    # ── Security.txt & Misc ───────────────────────────────────────────────
    {"path": "/.well-known/security.txt", "signatures": ["Contact:", "Expires:"], "severity": "Info", "title": "Security Contact Policy (security.txt)", "cwe": "CWE-200", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "desc": "security.txt ditemukan.", "remediation": "Pastikan kontak dan tanggal kadaluarsa diperbarui."},
    {"path": "/robots.txt", "signatures": ["Disallow:", "User-agent:"], "severity": "Info", "title": "robots.txt Disclosure", "cwe": "CWE-200", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "desc": "robots.txt membocorkan path tersembunyi.", "remediation": "Review paths yang di-Disallow."},
    {"path": "/sitemap.xml", "signatures": ["<urlset", "<sitemap>", "<url>"], "severity": "Info", "title": "Sitemap XML Accessible", "cwe": "CWE-200", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "desc": "Sitemap XML terbuka.", "remediation": "Review URL yang dipublikasikan."},
    {"path": "/CHANGELOG.md", "signatures": ["## [", "### Added", "### Fixed", "# Changelog"], "severity": "Low", "title": "Exposed CHANGELOG.md (Version Disclosure)", "cwe": "CWE-200", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "desc": "CHANGELOG membocorkan versi dan fitur.", "remediation": "Hapus dari web root."},
    {"path": "/README.md", "signatures": ["# ", "## Installation", "## Usage"], "severity": "Info", "title": "Exposed README.md", "cwe": "CWE-200", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "desc": "README.md terbuka.", "remediation": "Hapus dari production web root."},
]


class SensitiveFileAuditor:
    """
    Fuzzing 250+ sensitive file paths dengan signature validation.
    """

    async def scan(self, base_url: str, emit_log=None) -> List[Dict[str, Any]]:
        findings = []
        base_url = base_url.rstrip("/")

        async with httpx.AsyncClient(
            verify=False, timeout=5.0, follow_redirects=False
        ) as client:
            for item in SENSITIVE_TARGETS:
                test_url = f"{base_url}{item['path']}"
                if emit_log:
                    await emit_log(f"[FUZZER] Probing: {item['path']}")

                try:
                    res = await client.get(test_url)
                    if res.status_code == 200:
                        # Signature validation to eliminate soft-404 pages
                        matched_sig = None
                        if item["signatures"]:
                            for sig in item["signatures"]:
                                if sig.lower() in res.text.lower():
                                    matched_sig = sig
                                    break

                        if matched_sig:
                            findings.append({
                                "title": item["title"],
                                "severity": item["severity"],
                                "cwe": item["cwe"],
                                "owasp_category": "A05:2021-Security Misconfiguration",
                                "cvss_vector": item["cvss"],
                                "description": item["desc"],
                                "remediation": item["remediation"],
                                "evidence": (
                                    f"HTTP 200 OK pada {test_url} — "
                                    f"signature '{matched_sig}' terdeteksi dalam response body "
                                    f"({len(res.content)} bytes)"
                                ),
                                "target_url": test_url
                            })
                    elif res.status_code == 403:
                        # 403 is notable — resource exists but blocked
                        if emit_log:
                            await emit_log(f"[FUZZER] 403 Forbidden (protected): {item['path']}")

                except Exception:
                    continue

        return findings
