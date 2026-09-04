import React, { useState, useEffect, useRef } from 'react';
import { 
  ShieldAlert, Globe, Zap, Terminal, CheckCircle2, 
  Download, ListFilter, AlertTriangle, FileText, X, ShieldCheck, Lock,
  Network, History, Share2, Server, Search, ExternalLink, Calendar,
  Layers, Activity, Info, RefreshCw, ChevronRight, Check, Key,
  Database, Folder, Users, Cpu, Shield, ArrowRight, Play, Copy,
  CornerDownLeft, Sliders, AlertOctagon, Scale, Radio, Eye, EyeOff, Flame,
  RadioTower, Bug, HelpCircle, FileCode, CheckSquare, Compass,
  Code2, Sparkles, CheckCircle, Clock, Send, ChevronDown, LogOut,
  BarChart2, Award, Gavel
} from 'lucide-react';

// ─── KONFIGURASI PASSWORD & API BASE ──────────────────────────────
const APP_PASSWORD = 'djoeragancyber2026'; // Ganti password di sini
const API_BASE = import.meta.env.VITE_API_URL || '';

const getWsUrl = (scanId) => {
  if (import.meta.env.VITE_WS_URL) {
    return `${import.meta.env.VITE_WS_URL}/api/v1/ws/scans/${scanId}`;
  }
  if (API_BASE) {
    const wsProto = API_BASE.startsWith('https') ? 'wss:' : 'ws:';
    const host = API_BASE.replace(/^https?:\/\//, '');
    return `${wsProto}//${host}/api/v1/ws/scans/${scanId}`;
  }
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${protocol}//${window.location.host}/api/v1/ws/scans/${scanId}`;
};
// ──────────────────────────────────────────────────────────────────

// ─── OWASP Top 10 Reference for Severity Heatmap ─────────────────
const OWASP_CATEGORIES = [
  { id: 'A01', name: 'A01: Broken Access Control', match: 'A01' },
  { id: 'A02', name: 'A02: Cryptographic Failures', match: 'A02' },
  { id: 'A03', name: 'A03: Injection (SQL/SSTI)', match: 'A03' },
  { id: 'A04', name: 'A04: Insecure Design', match: 'A04' },
  { id: 'A05', name: 'A05: Security Misconfiguration', match: 'A05' },
  { id: 'A06', name: 'A06: Outdated / Vulnerable Components', match: 'A06' },
  { id: 'A07', name: 'A07: Identification & Auth (JWT)', match: 'A07' },
  { id: 'A08', name: 'A08: Software & Data Integrity', match: 'A08' },
  { id: 'A09', name: 'A09: Security Logging & Monitoring', match: 'A09' },
  { id: 'A10', name: 'A10: SSRF & Perimeter Defense', match: 'A10' },
];

function getExploitDifficulty(finding) {
  const title = (finding.title || '').toLowerCase();
  const sev = (finding.severity || '').toUpperCase();
  const desc = (finding.description || '').toLowerCase();

  if (title.includes('sql') || title.includes('.env') || title.includes('backup') || title.includes('ssti') || sev === 'CRITICAL') {
    return { level: 1, label: 'Trivial (1/5)', color: 'text-rose-600', bg: 'bg-rose-500', note: 'Public PoC / Exploit instan' };
  }
  if (title.includes('xss') || title.includes('redirect') || title.includes('traversal') || title.includes('lfi') || sev === 'HIGH') {
    return { level: 2, label: 'Low (2/5)', color: 'text-amber-600', bg: 'bg-amber-500', note: 'Browser / Direct HTTP probe' };
  }
  if (title.includes('cors') || title.includes('cookie') || title.includes('csrf') || sev === 'MEDIUM') {
    return { level: 3, label: 'Medium (3/5)', color: 'text-yellow-600', bg: 'bg-yellow-500', note: 'Interaksi pengguna / sesi khusus' };
  }
  if (title.includes('time') || title.includes('header') || title.includes('boundary') || sev === 'LOW') {
    return { level: 4, label: 'Hard (4/5)', color: 'text-sky-600', bg: 'bg-sky-500', note: 'Timing / Custom payload required' };
  }
  return { level: 5, label: 'Expert (5/5)', color: 'text-slate-600', bg: 'bg-slate-500', note: 'Multi-stage chain / Hardened' };
}

function parseJwtClient(token) {
  try {
    const parts = token.trim().split('.');
    if (parts.length < 2) return { error: 'Format token bukan JWT valid (minimal membutuhkan Header dan Payload dipisahkan oleh titik).' };
    const headerStr = atob(parts[0].replace(/-/g, '+').replace(/_/g, '/'));
    const payloadStr = atob(parts[1].replace(/-/g, '+').replace(/_/g, '/'));
    const header = JSON.parse(headerStr);
    const payload = JSON.parse(payloadStr);

    const checks = [];
    const alg = (header.alg || '').toLowerCase();
    if (!header.alg || alg === 'none') {
      checks.push({
        status: 'CRITICAL',
        title: 'Critical Vulnerability: Algorithm "none" Terdeteksi',
        desc: 'Token tidak membutuhkan verifikasi tanda tangan kriptografi (Unsigned JWT). Penyerang dapat memodifikasi payload dan menjadi admin.'
      });
    } else {
      checks.push({
        status: 'PASS',
        title: `Algoritma Tanda Tangan: ${header.alg}`,
        desc: 'Token menggunakan algoritma kriptografis standar yang memerlukan verifikasi secret/key.'
      });
    }

    if (!payload.exp) {
      checks.push({
        status: 'MEDIUM',
        title: 'Missing "exp" Expiration Claim',
        desc: 'Token tidak memiliki batas kedaluwarsa dan berlaku selamanya jika tidak di-revokasi.'
      });
    } else {
      const expDate = new Date(payload.exp * 1000);
      const isExpired = Date.now() > payload.exp * 1000;
      checks.push({
        status: isExpired ? 'INFO' : 'PASS',
        title: isExpired ? `Token Sudah Kedaluwarsa (${expDate.toLocaleString()})` : `Token Masih Aktif s/d ${expDate.toLocaleString()}`,
        desc: isExpired ? 'Token ditolak oleh server jika validasi waktu aktif.' : 'Token dalam masa berlaku sah.'
      });
    }

    const payloadStrLower = JSON.stringify(payload).toLowerCase();
    if (payloadStrLower.includes('password') || payloadStrLower.includes('secret') || payloadStrLower.includes('pin')) {
      checks.push({
        status: 'HIGH',
        title: 'Data Rahasia / Kredensial di Payload JWT',
        desc: 'Payload JWT hanya di-Base64 encode, BUKAN dienkripsi. Jangan letakkan password atau secret di dalamnya.'
      });
    }

    return {
      header,
      payload,
      checks,
      raw: token,
      hasSignature: parts.length >= 3 && !!parts[2],
      signaturePart: parts[2] || ''
    };
  } catch (e) {
    return { error: `Gagal mendekode token: ${e.message}` };
  }
}

export default function App() {
  // ── Auth State ──
  const [isAuthenticated, setIsAuthenticated] = useState(
    () => sessionStorage.getItem('djc_auth') === 'true'
  );
  const [loginPassword, setLoginPassword] = useState('');
  const [loginError, setLoginError] = useState('');
  const [showLoginPass, setShowLoginPass] = useState(false);
  const [loginShake, setLoginShake] = useState(false);

  const handleLogin = (e) => {
    e.preventDefault();
    if (loginPassword === APP_PASSWORD) {
      sessionStorage.setItem('djc_auth', 'true');
      setIsAuthenticated(true);
      setLoginError('');
    } else {
      setLoginError('Password salah. Coba lagi.');
      setLoginShake(true);
      setLoginPassword('');
      setTimeout(() => setLoginShake(false), 600);
    }
  };

  const handleLogout = () => {
    sessionStorage.removeItem('djc_auth');
    setIsAuthenticated(false);
    setLoginPassword('');
  };

  // Target & Scan Pipeline State
  const [targetUrl, setTargetUrl] = useState('https://scanme.nmap.org');
  const [profile, setProfile] = useState('active'); // 'active' | 'passive'
  const [isScanning, setIsScanning] = useState(false);
  const [activeScanId, setActiveScanId] = useState(null);
  const [progress, setProgress] = useState(0);
  const [stage, setStage] = useState('Ready');
  const [logs, setLogs] = useState([
    '// DjoeraganCyber Security Audit Engine ready.',
    '// Masukkan domain target publik dan klik "Jalankan Audit Keamanan Live" untuk memulai probe real-time.'
  ]);
  const [findings, setFindings] = useState([]);
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [showHeatmap, setShowHeatmap] = useState(false);

  // JWT Decoder State
  const [jwtInput, setJwtInput] = useState('');
  const [jwtAuditResult, setJwtAuditResult] = useState(null);

  // Active Main Tab Navigation: 'live_scanner' | 'live_assets' | 'live_terminal' | 'domain_intel' | 'remediation_hub' | 'export_hub' | 'compliance_hub'
  const [activeTab, setActiveTab] = useState('live_scanner');

  // Compliance Hub State
  const [complianceData, setComplianceData] = useState(null);
  const [isComplianceLoading, setIsComplianceLoading] = useState(false);

  // Live PoC Verifier Modal State
  const [showVerifyModal, setShowVerifyModal] = useState(false);
  const [verifyingFinding, setVerifyingFinding] = useState(null);
  const [verifyResult, setVerifyResult] = useState(null);
  const [isVerifyingPoC, setIsVerifyingPoC] = useState(false);

  // Interactive Live Terminal State
  const [terminalInput, setTerminalInput] = useState('');
  const [terminalHistory, setTerminalHistory] = useState([
    {
      prompt: 'auditor@live-target:~$ ',
      command: 'help',
      output: `⚡ DJOERAGANCYBER LIVE SECURITY AUDIT CONSOLE
Seluruh perintah mengeksekusi probe jaringan & HTTP secara LANGSUNG ke domain target:

[ 📊 Enterprise Standards & Scorecard ]
  scorecard   : Kalkulasi skor postur keamanan & Letter Grade (A+ s/d F)
  compliance  : Audit OWASP Top 10, ISO 27001:2022, PCI-DSS v4.0, NIST SP 800-53
  emailsec    : Audit SPF, DMARC, CAA, DNSSEC anti-spoofing & hijacking

[ 🌐 HTTP, Headers & API ]
  headers     : Evaluasi HTTP Security Headers (HSTS, CSP, COOP, dll.)
  api         : Probe endpoint OpenAPI & Swagger (/openapi.json, /swagger-ui.html)
  graphql     : Uji endpoint GraphQL dan cek query Introspection
  cors        : Uji refleksi CORS misconfiguration
  ssl         : Live audit sertifikat TLS 1.3/1.2, cipher, masa berlaku, SANs
  methods     : Probe metode HTTP (OPTIONS, TRACE, PUT, DELETE)

[ 🔍 Recon & Network ]
  dns         : Query DNS publik (A, AAAA, MX, TXT, SPF, DMARC, CNAME)
  waf         : Deteksi & fingerprinting WAF (Cloudflare, AWS WAF, Akamai)
  portscan    : Probe TCP async aman port web & service umum
  whois / ip  : Resolusi IP & reverse PTR record
  tech        : Fingerprinting stack teknologi, CMS, web server

[ 🎯 Attack Surface & Fuzzing ]
  fuzz        : Probe file berisiko tinggi (.env, .git, backup.sql, actuator)
  crawl       : Spider live tautan & form HTML internal
  test-xss    : Uji refleksi Reflected XSS
  test-sqli   : Uji respon SQL Injection
  remediation : Skrip hardening instan (Nginx, Apache, Caddy, FastAPI)
  curl <path> : HTTP GET ke endpoint target tertentu`,
      exit_code: 0,
      timestamp: new Date().toLocaleTimeString()
    }
  ]);
  const [isTermExecuting, setIsTermExecuting] = useState(false);
  const simTerminalRef = useRef(null);
  const terminalRef = useRef(null);

  // Live Asset Explorer State
  const [liveAssetData, setLiveAssetData] = useState(null);
  const [isAssetLoading, setIsAssetLoading] = useState(false);
  const [assetSubTab, setAssetSubTab] = useState('endpoints'); // 'endpoints' | 'paths' | 'headers' | 'perimeter'
  const [customPathInput, setCustomPathInput] = useState('/.env');
  const [customPathResult, setCustomPathResult] = useState(null);
  const [isCustomPathProbing, setIsCustomPathProbing] = useState(false);

  // Domain Intelligence State
  const [domainIntel, setDomainIntel] = useState(null);

  // Input & DB Integrity Hub State
  const [activeSubTabInputDB, setActiveSubTabInputDB] = useState('input_resilience'); // 'input_resilience' | 'db_boundary'
  const [inputTestUrl, setInputTestUrl] = useState('');
  const [inputTestParam, setInputTestParam] = useState('q');
  const [inputTestProbe, setInputTestProbe] = useState("'%27--");
  const [inputTestMethod, setInputTestMethod] = useState('GET');
  const [isInputTesting, setIsInputTesting] = useState(false);
  const [inputTestResult, setInputTestResult] = useState(null);
  const [inputTestHistory, setInputTestHistory] = useState([]);

  const [dbBoundaryUrl, setDbBoundaryUrl] = useState('');
  const [dbBoundaryParam, setDbBoundaryParam] = useState('id');
  const [dbBoundaryInstruction, setDbBoundaryInstruction] = useState('drop_database_canary');
  const [dbBoundaryMethod, setDbBoundaryMethod] = useState('GET');
  const [isDbBoundaryTesting, setIsDbBoundaryTesting] = useState(false);
  const [dbBoundaryResult, setDbBoundaryResult] = useState(null);
  const [selectedDbmsGuide, setSelectedDbmsGuide] = useState('MySQL / MariaDB');

  // Remediation Hub State
  const [remediationPlatform, setRemediationPlatform] = useState('nginx'); // 'nginx' | 'apache' | 'caddy' | 'cloudflare' | 'fastapi' | 'express'

  // Utility Copy State
  const [copiedKey, setCopiedKey] = useState(null);

  // Email Report State
  const [emailRecipient, setEmailRecipient] = useState('');
  const [emailSender, setEmailSender] = useState('');
  const [emailAppPassword, setEmailAppPassword] = useState('');
  const [emailCustomMsg, setEmailCustomMsg] = useState('');
  const [emailAttachPdf, setEmailAttachPdf] = useState(false);
  const [emailSending, setEmailSending] = useState(false);
  const [emailResult, setEmailResult] = useState(null);
  const [showEmailPassword, setShowEmailPassword] = useState(false);

  const handleSendEmailReport = async () => {
    if (!activeScanId) return;
    if (!emailRecipient || !emailRecipient.includes('@')) {
      setEmailResult({ success: false, message: 'Email penerima tidak valid.' });
      return;
    }
    if (!emailSender || !emailAppPassword) {
      setEmailResult({ success: false, message: 'Gmail pengirim dan App Password wajib diisi.' });
      return;
    }
    setEmailSending(true);
    setEmailResult(null);
    try {
      const res = await fetch(`${API_BASE}/api/v1/reports/${activeScanId}/email`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          recipient_email: emailRecipient,
          custom_message: emailCustomMsg,
          attach_pdf: emailAttachPdf,
          sender_email: emailSender,
          sender_app_password: emailAppPassword,
        })
      });
      const data = await res.json();
      if (res.ok) {
        setEmailResult({ success: true, message: data.message || 'Email berhasil dikirim!' });
      } else {
        setEmailResult({ success: false, message: data.detail || 'Gagal mengirim email.' });
      }
    } catch (err) {
      setEmailResult({ success: false, message: 'Network error: ' + err.message });
    } finally {
      setEmailSending(false);
    }
  };

  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [logs]);

  useEffect(() => {
    if (simTerminalRef.current) {
      simTerminalRef.current.scrollTop = simTerminalRef.current.scrollHeight;
    }
  }, [terminalHistory]);

  const addLog = (msg) => {
    const time = new Date().toLocaleTimeString();
    setLogs((prev) => [...prev, `[${time}] ${msg}`]);
  };

  const copyToClipboard = (text, key) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // Launch Full Live Scan Pipeline
  const startLiveScan = async () => {
    if (!targetUrl.trim()) {
      alert('Silakan masukkan URL target yang valid.');
      return;
    }

    setIsScanning(true);
    setProgress(5);
    setStage('Menginisialisasi pipeline audit...');
    setFindings([]);
    setDomainIntel(null);
    setLogs([`[${new Date().toLocaleTimeString()}] [INIT] Memulai audit keamanan live ke: ${targetUrl}`]);
    setActiveTab('live_scanner');

    try {
      const response = await fetch(`${API_BASE}/api/v1/scans/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_url: targetUrl, profile: profile })
      });

      if (!response.ok) {
        let errorMsg = 'Gagal memulai pemindaian live.';
        try {
          const err = await response.json();
          errorMsg = err.detail || errorMsg;
        } catch (_) {
          errorMsg = `Server response error (${response.status}: ${response.statusText || 'Unknown'})`;
        }
        throw new Error(errorMsg);
      }

      const scanData = await response.json();
      setActiveScanId(scanData.id);
      addLog(`[QUEUED] Scan ID #${scanData.id} terdaftar. Menghubungkan live WebSocket telemetry...`);

      // Connect to WebSocket Telemetry
      const wsUrl = getWsUrl(scanData.id);
      const ws = new WebSocket(wsUrl);

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === 'log') {
            addLog(data.message);
            if (data.message.includes('[PASSIVE]')) setStage('Menganalisis Security Headers & SSL/TLS 1.3...');
            if (data.message.includes('[ACTIVE]')) setStage('Menjalankan Live Spider, API Prober & Active Fuzzing...');
            if (data.message.includes('[SCORING]')) setStage('Menghitung Skor CVSS v3.1...');
          } else if (data.type === 'finding') {
            setFindings((prev) => [...prev, data.finding]);
          } else if (data.type === 'domain_intel') {
            setDomainIntel(data.data);
          } else if (data.type === 'done') {
            setIsScanning(false);
            setProgress(100);
            setStage('Audit Selesai');
            addLog(`[DONE] Pemindaian selesai dengan status: ${data.status}`);
            ws.close();
            loadLiveAssetData(targetUrl, scanData.id);
          }
        } catch (e) {
          console.error('WS parse error:', e);
        }
      };

      ws.onerror = () => {
        addLog('[WARN] WebSocket terputus. Menggunakan fallback polling...');
        pollScanStatus(scanData.id);
      };

    } catch (err) {
      setIsScanning(false);
      setProgress(0);
      setStage('Error');
      const isFetchErr = err.message === 'Failed to fetch' || err.name === 'TypeError';
      const cleanError = isFetchErr
        ? 'Gagal terhubung ke Backend API (FastAPI di http://127.0.0.1:8000). Pastikan server backend sudah dijalankan di terminal.'
        : err.message;
      addLog(`[ERROR] ${cleanError}`);
      alert(`Gagal memulai audit: ${cleanError}`);
    }
  };

  const pollScanStatus = async (scanId) => {
    const interval = setInterval(async () => {
      try {
        const res = await fetch(`${API_BASE}/api/v1/scans/${scanId}`);
        if (res.ok) {
          const data = await res.json();
          setProgress(data.progress);
          setFindings(data.vulnerabilities || []);
          if (data.parsed_domain_intel) setDomainIntel(data.parsed_domain_intel);
          if (data.status === 'COMPLETED' || data.status === 'FAILED') {
            setIsScanning(false);
            setStage(data.status);
            clearInterval(interval);
            loadLiveAssetData(data.target_url, scanId);
          }
        }
      } catch (e) {
        clearInterval(interval);
      }
    }, 2500);
  };

  // Live Terminal Command Executor
  const executeTerminalCommand = async (cmdToRun) => {
    const command = cmdToRun !== undefined ? cmdToRun : terminalInput;
    if (!command.trim()) return;

    const cmd = command.trim();
    setTerminalInput('');

    if (cmd === 'clear') {
      setTerminalHistory([]);
      return;
    }

    setIsTermExecuting(true);
    try {
      const res = await fetch(`${API_BASE}/api/v1/live/terminal-exec`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          command: cmd,
          target_url: targetUrl || 'https://scanme.nmap.org'
        })
      });

      if (res.ok) {
        const result = await res.json();
        setTerminalHistory(prev => [...prev, result]);
      } else {
        const err = await res.json();
        setTerminalHistory(prev => [...prev, {
          prompt: 'auditor@live-target:~$ ',
          command: cmd,
          output: `[ERROR] ${err.detail || 'Eksekusi live command gagal.'}`,
          exit_code: 1,
          timestamp: new Date().toLocaleTimeString()
        }]);
      }
    } catch (e) {
      setTerminalHistory(prev => [...prev, {
        prompt: 'auditor@live-target:~$ ',
        command: cmd,
        output: `[NETWORK ERROR] Gagal terhubung: ${e.message}`,
        exit_code: 1,
        timestamp: new Date().toLocaleTimeString()
      }]);
    } finally {
      setIsTermExecuting(false);
    }
  };

  // Live Asset Explorer Loader
  const loadLiveAssetData = async (url = targetUrl, scanId = activeScanId) => {
    if (!url.trim()) return;
    setIsAssetLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/v1/live/explore`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_url: url, scan_id: scanId })
      });
      if (res.ok) {
        const data = await res.json();
        setLiveAssetData(data);
      }
    } catch (e) {
      console.error('Failed to load live asset data:', e);
    } finally {
      setIsAssetLoading(false);
    }
  };

  // Custom Live Path Prober
  const probeCustomPath = async () => {
    if (!customPathInput.trim()) return;
    setIsCustomPathProbing(true);
    setCustomPathResult(null);

    const fullUrl = targetUrl.replace(/\/+$/, '') + '/' + customPathInput.replace(/^\/+/, '');
    try {
      const res = await fetch(`${API_BASE}/api/v1/live/terminal-exec`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          command: `curl ${customPathInput}`,
          target_url: targetUrl
        })
      });
      if (res.ok) {
        const data = await res.json();
        setCustomPathResult({
          url: fullUrl,
          output: data.output,
          exit_code: data.exit_code
        });
      }
    } catch (e) {
      setCustomPathResult({
        url: fullUrl,
        output: `[ERROR] Koneksi gagal: ${e.message}`,
        exit_code: 1
      });
    } finally {
      setIsCustomPathProbing(false);
    }
  };

  // Live Finding PoC Verification
  const openPoCModal = async (finding) => {
    setVerifyingFinding(finding);
    setVerifyResult(null);
    setShowVerifyModal(true);
    setIsVerifyingPoC(true);

    try {
      const res = await fetch(`${API_BASE}/api/v1/live/verify-poc`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_url: finding.target_url || targetUrl,
          finding_title: finding.title,
          evidence: finding.evidence || ''
        })
      });
      if (res.ok) {
        const data = await res.json();
        setVerifyResult(data);
      } else {
        setVerifyResult({
          verified: false,
          message: 'Gagal menghubungi backend untuk verifikasi ulang PoC.'
        });
      }
    } catch (e) {
      setVerifyResult({
        verified: false,
        message: `Error re-testing PoC: ${e.message}`
      });
    } finally {
      setIsVerifyingPoC(false);
    }
  };

  // Live Input & Search Resilience Test Runner
  const handleRunInputTest = async (overrideUrl = null, overrideParam = null, overrideProbe = null) => {
    const url = overrideUrl || inputTestUrl || targetUrl;
    const param = overrideParam || inputTestParam || 'q';
    const probe = overrideProbe || inputTestProbe || "'--";

    setIsInputTesting(true);
    setInputTestResult(null);

    try {
      const res = await fetch(`${API_BASE}/api/v1/live/test-input`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_url: url,
          param_name: param,
          probe: probe,
          method: inputTestMethod
        })
      });
      if (res.ok) {
        const data = await res.json();
        setInputTestResult(data);
        setInputTestHistory(prev => [data, ...prev.slice(0, 9)]);
      } else {
        const err = await res.json();
        setInputTestResult({
          target_url: url,
          param: param,
          probe: probe,
          method: inputTestMethod,
          status_code: 500,
          response_length: 0,
          db_error_found: false,
          is_blocked_by_waf: false,
          is_reflected_raw: false,
          resilience_status: `[ERROR] ${err.detail || 'Pengujian input gagal.'}`,
          score_impact: 'Info',
          timestamp: new Date().toLocaleTimeString()
        });
      }
    } catch (e) {
      setInputTestResult({
        target_url: url,
        param: param,
        probe: probe,
        method: inputTestMethod,
        status_code: 0,
        response_length: 0,
        db_error_found: false,
        is_blocked_by_waf: false,
        is_reflected_raw: false,
        resilience_status: `[NETWORK ERROR] ${e.message}`,
        score_impact: 'Info',
        timestamp: new Date().toLocaleTimeString()
      });
    } finally {
      setIsInputTesting(false);
    }
  };

  // Live Database Integrity & Privilege Boundary Test Runner (Isolated Mode)
  const handleRunDbBoundary = async (overrideInstruction = null) => {
    const url = dbBoundaryUrl || targetUrl;
    const param = dbBoundaryParam || 'id';
    const instructionId = overrideInstruction || dbBoundaryInstruction;

    setIsDbBoundaryTesting(true);
    setDbBoundaryResult(null);

    try {
      const res = await fetch(`${API_BASE}/api/v1/live/test-db-boundary`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_url: url,
          param_name: param,
          instruction_id: instructionId,
          method: dbBoundaryMethod,
          is_isolated_confirmed: true
        })
      });
      if (res.ok) {
        const data = await res.json();
        setDbBoundaryResult(data);
      } else {
        const err = await res.json();
        setDbBoundaryResult({
          target_url: url,
          param_tested: param,
          instruction_type: instructionId,
          risk_category: 'System Boundary Error',
          payload_used: 'N/A',
          safe_target: 'vulnhunter_canary_audit_db',
          status_code: 500,
          status_type: 'SERVER_ERROR',
          verdict: `[ERROR] ${err.detail || 'Audit batas database gagal dieksekusi.'}`,
          severity: 'Info',
          waf_blocked: false,
          stacked_blocked: false,
          privilege_denied: false,
          syntax_error: false,
          hardening_script: '',
          timestamp: new Date().toLocaleTimeString()
        });
      }
    } catch (e) {
      setDbBoundaryResult({
        target_url: url,
        param_tested: param,
        instruction_type: instructionId,
        risk_category: 'Connection Error',
        payload_used: 'N/A',
        safe_target: 'vulnhunter_canary_audit_db',
        status_code: 0,
        status_type: 'NETWORK_ERROR',
        verdict: `[NETWORK ERROR] ${e.message}`,
        severity: 'Info',
        waf_blocked: false,
        stacked_blocked: false,
        privilege_denied: false,
        syntax_error: false,
        hardening_script: '',
        timestamp: new Date().toLocaleTimeString()
      });
    } finally {
      setIsDbBoundaryTesting(false);
    }
  };

  // Severity Counter Aggregator
  const counts = {
    CRITICAL: findings.filter((f) => f.severity?.toUpperCase() === 'CRITICAL').length,
    HIGH: findings.filter((f) => f.severity?.toUpperCase() === 'HIGH').length,
    MEDIUM: findings.filter((f) => f.severity?.toUpperCase() === 'MEDIUM').length,
    LOW: findings.filter((f) => f.severity?.toUpperCase() === 'LOW').length,
    INFO: findings.filter((f) => f.severity?.toUpperCase() === 'INFO').length,
  };
  const totalFindings = findings.length;

  const filteredFindings = findings.filter((f) => {
    const matchesSev = filterSeverity === 'ALL' || f.severity?.toUpperCase() === filterSeverity;
    const matchesSearch = !searchQuery.trim() || 
      f.title?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.description?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.owasp_category?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.cwe?.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesSev && matchesSearch;
  });

  // Remediation Code Snippets Generator
  const getRemediationSnippet = (platform) => {
    switch (platform) {
      case 'nginx':
        return `# /etc/nginx/conf.d/security.conf (Standar Keamanan 2026)
server {
    # 1. HSTS & Cryptographic Protection
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    
    # 2. XSS, Clickjacking & Frame Protection
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header Cross-Origin-Resource-Policy "same-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'self';" always;

    # 3. Sembunyikan Versi & Banner Server
    server_tokens off;

    # 4. Blokir Akses ke File Rahasia & Dotfiles
    location ~ /\\.(?!well-known) {
        deny all;
        return 404;
    }

    # 5. Blokir Akses ke File Backup & Environment
    location ~* \\.(env|git|sql|bak|yml|yaml|log|sqlite|sqlite3)$ {
        deny all;
        return 404;
    }
}`;

      case 'apache':
        return `# .htaccess atau httpd.conf (Standar Keamanan 2026)
<IfModule mod_headers.c>
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()"
    Header always set Cross-Origin-Opener-Policy "same-origin"
    Header always set Cross-Origin-Resource-Policy "same-origin"
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none';"
    Header unset X-Powered-By
    Header unset Server
</IfModule>

# Sembunyikan Banner Server
ServerSignature Off
ServerTokens Prod

# Blokir Akses File Sensitif
<FilesMatch "^(\\.|.*\\.(env|git|sql|bak|yml|yaml|log|sqlite))$">
    Require all denied
</FilesMatch>`;

      case 'caddy':
        return `# Caddyfile (Caddy Server v2 - Standar 2026)
your-domain.com {
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        X-Frame-Options "SAMEORIGIN"
        X-Content-Type-Options "nosniff"
        Referrer-Policy "strict-origin-when-cross-origin"
        Permissions-Policy "camera=(), microphone=(), geolocation=()"
        Cross-Origin-Opener-Policy "same-origin"
        Cross-Origin-Resource-Policy "same-origin"
        Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none';"
        -Server
        -X-Powered-By
    }

    # Blokir akses ke file tersembunyi
    @blocked path_regexp (^|/)\\.(?!well-known)
    respond @blocked 404
}`;

      case 'cloudflare':
        return `# Cloudflare Transform Rules (HTTP Response Header Modification)
# Buat aturan "Modify Response Header" di dashboard Cloudflare:
1. Strict-Transport-Security -> "max-age=31536000; includeSubDomains; preload"
2. X-Frame-Options -> "SAMEORIGIN"
3. X-Content-Type-Options -> "nosniff"
4. Referrer-Policy -> "strict-origin-when-cross-origin"
5. Permissions-Policy -> "camera=(), microphone=(), geolocation=()"
6. Content-Security-Policy -> "default-src 'self'; script-src 'self' 'unsafe-inline';"

# Cloudflare WAF Custom Rule (Expression):
(http.request.uri.path contains "/.env" or http.request.uri.path contains "/.git" or http.request.uri.path contains "/backup.sql") -> Action: Block`;

      case 'fastapi':
        return `# Python FastAPI / Starlette Security Middleware
from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware

app = FastAPI(title="Secure API Application")

class ProductionSecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        if "server" in response.headers:
            del response.headers["server"]
        return response

app.add_middleware(ProductionSecurityHeadersMiddleware)`;

      case 'express':
        return `// Node.js Express.js Security Configuration (Helmet 2026)
const express = require('express');
const helmet = require('helmet');

const app = express();

// Terapkan proteksi header keamanan lengkap
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  frameguard: { action: 'sameorigin' },
  noSniff: true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

// Sembunyikan header X-Powered-By
app.disable('x-powered-by');`;

      default:
        return '';
    }
  };

  // ── Login Screen (Tema Putih & Abu-abu) ──
  if (!isAuthenticated) {
    return (
      <div style={{
        minHeight: '100vh',
        backgroundColor: '#f8fafc',
        backgroundImage: 'radial-gradient(at 0% 0%, rgba(226,232,240,0.6) 0px, transparent 50%), radial-gradient(at 100% 100%, rgba(241,245,249,0.9) 0px, transparent 50%)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
        position: 'relative',
        padding: '24px 16px'
      }}>
        {/* Subtle grid pattern */}
        <div style={{
          position: 'absolute', inset: 0,
          backgroundImage: 'radial-gradient(#cbd5e1 0.8px, transparent 0.8px)',
          backgroundSize: '24px 24px',
          opacity: 0.45,
          pointerEvents: 'none'
        }} />

        <div
          style={{
            width: '100%',
            maxWidth: '420px',
            position: 'relative',
            zIndex: 10,
            animation: loginShake ? 'loginShake 0.5s ease' : 'loginFadeIn 0.5s cubic-bezier(0.16, 1, 0.3, 1)'
          }}
        >
          <style>{`
            @keyframes loginFadeIn { from { opacity:0; transform: translateY(16px); } to { opacity:1; transform: translateY(0); } }
            @keyframes loginShake { 0%,100%{transform:translateX(0)} 20%{transform:translateX(-10px)} 40%{transform:translateX(10px)} 60%{transform:translateX(-8px)} 80%{transform:translateX(8px)} }
            @keyframes eyePop { 0% { transform: scale(0.65) rotate(-10deg); opacity: 0; } 60% { transform: scale(1.15) rotate(3deg); } 100% { transform: scale(1) rotate(0deg); opacity: 1; } }
            .login-white-input:focus { outline: none !important; border-color: #6366f1 !important; background: #ffffff !important; box-shadow: 0 0 0 3.5px rgba(99,102,241,0.12) !important; }
            .login-white-btn:hover { background-color: #0f172a !important; transform: translateY(-1px); box-shadow: 0 8px 20px -4px rgba(15,23,42,0.2) !important; }
            .login-white-btn:active { transform: translateY(0); }
            .eye-toggle-btn:hover { background-color: #e2e8f0 !important; color: #0f172a !important; }
          `}</style>

          {/* Logo / Brand */}
          <div style={{ textAlign:'center', marginBottom:'28px' }}>
            <div style={{
              width:'64px', height:'64px', margin:'0 auto 14px',
              backgroundColor:'#ffffff',
              border:'1px solid #e2e8f0',
              borderRadius:'18px',
              display:'flex', alignItems:'center', justifyContent:'center',
              boxShadow:'0 10px 25px -5px rgba(15,23,42,0.08), 0 2px 4px rgba(0,0,0,0.02)',
              fontSize:'28px'
            }}>🛡️</div>
            <h1 style={{ color:'#0f172a', fontSize:'24px', fontWeight:800, margin:0, letterSpacing:'-0.5px' }}>DjoeraganCyber</h1>
          </div>

          {/* Clean White Card */}
          <div style={{
            backgroundColor:'#ffffff',
            border:'1px solid #e2e8f0',
            borderRadius:'20px',
            padding:'32px 28px',
            boxShadow:'0 20px 40px -15px rgba(15,23,42,0.07), 0 0 0 1px rgba(0,0,0,0.02)'
          }}>
            <h2 style={{ color:'#0f172a', fontSize:'16px', fontWeight:700, margin:'0 0 4px' }}>🔐 Akses Terbatas</h2>
            <p style={{ color:'#64748b', fontSize:'12.5px', margin:'0 0 22px', lineHeight:'1.5' }}>
              Masukkan password untuk mengakses dashboard audit keamanan.
            </p>

            <form onSubmit={handleLogin} style={{ display:'flex', flexDirection:'column', gap:'16px' }}>
              {/* Password field */}
              <div style={{ position:'relative' }}>
                <label style={{ display:'block', color:'#475569', fontSize:'11px', fontWeight:700, marginBottom:'6px', letterSpacing:'0.5px' }}>PASSWORD</label>
                <div style={{ position:'relative' }}>
                  <input
                    id="login-password-input"
                    className="login-white-input"
                    type={showLoginPass ? 'text' : 'password'}
                    value={loginPassword}
                    onChange={e => { setLoginPassword(e.target.value); setLoginError(''); }}
                    placeholder="Masukkan password..."
                    autoFocus
                    style={{
                      width:'100%', boxSizing:'border-box',
                      backgroundColor:'#f8fafc',
                      border:'1px solid #cbd5e1',
                      borderRadius:'10px',
                      color:'#0f172a',
                      fontSize:'14px',
                      padding:'11px 42px 11px 13px',
                      transition:'all 0.15s ease-in-out',
                      fontFamily:"'Inter', sans-serif"
                    }}
                  />
                  <button
                    type="button"
                    className="eye-toggle-btn"
                    onClick={() => setShowLoginPass(p => !p)}
                    style={{
                      position:'absolute', right:'8px', top:'50%', transform:'translateY(-50%)',
                      background:'transparent', border:'none', cursor:'pointer',
                      color:'#64748b', padding:'6px', borderRadius:'7px',
                      display:'flex', alignItems:'center', justifyContent:'center',
                      transition:'all 0.15s ease-in-out'
                    }}
                    title={showLoginPass ? 'Sembunyikan password' : 'Lihat password'}
                  >
                    <span
                      key={showLoginPass ? 'open' : 'closed'}
                      style={{ display:'inline-flex', animation:'eyePop 0.3s cubic-bezier(0.34, 1.56, 0.64, 1)' }}
                    >
                      {showLoginPass ? (
                        <EyeOff className="w-4 h-4 text-indigo-600" />
                      ) : (
                        <Eye className="w-4 h-4 text-slate-500" />
                      )}
                    </span>
                  </button>
                </div>
                {loginError && (
                  <p style={{ color:'#dc2626', fontSize:'12px', margin:'7px 0 0', display:'flex', alignItems:'center', gap:'4px', fontWeight:500 }}>
                    ⚠️ {loginError}
                  </p>
                )}
              </div>

              {/* Submit */}
              <button
                id="login-submit-btn"
                type="submit"
                className="login-white-btn"
                style={{
                  width:'100%',
                  padding:'12px',
                  backgroundColor:'#1e293b',
                  border:'none',
                  borderRadius:'10px',
                  color:'#ffffff',
                  fontSize:'13.5px',
                  fontWeight:700,
                  cursor:'pointer',
                  transition:'all 0.2s',
                  letterSpacing:'0.2px',
                  boxShadow:'0 4px 12px rgba(15,23,42,0.12)',
                  fontFamily:"'Inter', sans-serif"
                }}
              >Login</button>
            </form>

            {/* Security note */}
            <div style={{ marginTop:'20px', padding:'10px 12px', backgroundColor:'#f8fafc', borderRadius:'10px', border:'1px solid #e2e8f0' }}>
              <p style={{ color:'#64748b', fontSize:'11px', margin:0, textAlign:'center', lineHeight:'1.6' }}>
                🔒 Platform audit khusus <strong style={{color:'#334155'}}>authorized security auditor</strong>.<br/>
                Seluruh aktivitas sesi direkam.
              </p>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#f8fafc] text-slate-800 flex flex-col antialiased selection:bg-indigo-500 selection:text-white">
      
      {/* TOP HEADER & SYSTEM STATUS BAR */}
      <header className="sticky top-0 z-40 border-b border-slate-200 bg-white/95 backdrop-blur-md shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-4">
          
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-indigo-600 via-blue-600 to-cyan-500 p-0.5 shadow-md shadow-indigo-500/20 flex items-center justify-center">
              <div className="w-full h-full bg-white rounded-[10px] flex items-center justify-center">
                <ShieldAlert className="w-5 h-5 text-indigo-600" />
              </div>
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-extrabold text-base tracking-tight text-slate-900">
                  DJOERAGANCYBER
                </span>
              </div>
              <p className="text-[11px] text-slate-500 hidden sm:block">
                Web Vulnerability Scanner, API Security & Interactive Penetration Testing Suite
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2.5">
            {activeScanId && (
              <div className="flex items-center space-x-1.5 bg-slate-100 p-1 rounded-xl border border-slate-200">
                <a
                  href={`${API_BASE}/api/v1/reports/${activeScanId}/pdf`}
                  target="_blank"
                  rel="noreferrer"
                  className="px-3 py-1.5 rounded-lg bg-white hover:bg-slate-50 text-slate-700 hover:text-indigo-600 text-xs font-semibold flex items-center space-x-1.5 transition shadow-sm border border-slate-200"
                  title="Unduh Laporan PDF Resmi"
                >
                  <Download className="w-3.5 h-3.5 text-indigo-600" />
                  <span className="hidden sm:inline">PDF Report</span>
                </a>

                <a
                  href={`${API_BASE}/api/v1/reports/${activeScanId}/sarif`}
                  className="px-2.5 py-1.5 rounded-lg hover:bg-white text-slate-600 hover:text-indigo-600 text-xs font-semibold transition"
                  title="Unduh format SARIF 2.1.0 untuk DevSecOps"
                >
                  SARIF
                </a>
                <a
                  href={`${API_BASE}/api/v1/reports/${activeScanId}/json`}
                  className="px-2.5 py-1.5 rounded-lg hover:bg-white text-slate-600 hover:text-indigo-600 text-xs font-semibold transition"
                  title="Unduh format JSON Raw"
                >
                  JSON
                </a>
              </div>
            )}
            
            {isScanning && (
              <div className="flex items-center space-x-2 px-3 py-1.5 rounded-xl bg-indigo-50 border border-indigo-200 text-xs text-indigo-700">
                <RadioTower className="w-3.5 h-3.5 text-indigo-600 animate-pulse" />
                <span className="font-mono text-[11px] font-semibold">
                  {stage}
                </span>
              </div>
            )}

            {/* Logout Button */}
            <button
              onClick={handleLogout}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-xl bg-slate-100 hover:bg-rose-50 border border-slate-200 hover:border-rose-200 text-xs font-semibold text-slate-600 hover:text-rose-600 transition shadow-sm"
              title="Keluar dari sesi audit"
            >
              <LogOut className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Keluar</span>
            </button>
          </div>
        </div>
      </header>

      {/* TARGET INPUT & AUDIT CONTROL CENTER */}
      <section className="border-b border-slate-200 bg-white py-6 px-4 sm:px-6 lg:px-8 shadow-sm">
        <div className="max-w-7xl mx-auto space-y-4">
          <div className="flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-3.5">
            
            {/* TARGET URL INPUT */}
            <div className="flex-1 flex items-center bg-slate-50 rounded-xl border border-slate-300 focus-within:border-indigo-500 focus-within:ring-2 focus-within:ring-indigo-500/10 focus-within:bg-white transition px-3.5 py-2.5 shadow-inner">
              <Globe className="w-5 h-5 text-indigo-600 mr-2.5 flex-shrink-0" />
              <input
                type="text"
                placeholder="Masukkan domain publik live (contoh: https://scanme.nmap.org atau https://example.com)"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                disabled={isScanning}
                className="bg-transparent border-none text-slate-900 placeholder-slate-400 text-sm font-mono w-full focus:outline-none"
              />
            </div>

            {/* SCAN PROFILE TOGGLE */}
            <div className="flex items-center space-x-1.5 bg-slate-100 p-1.5 rounded-xl border border-slate-200">
              <button
                onClick={() => setProfile('active')}
                disabled={isScanning}
                className={`px-3.5 py-2 rounded-lg text-xs font-bold transition flex items-center space-x-1.5 ${
                  profile === 'active'
                    ? 'bg-white text-indigo-700 shadow-sm border border-slate-200'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                <Zap className="w-3.5 h-3.5 text-amber-500" />
                <span>Full Audit (Active + API)</span>
              </button>
              <button
                onClick={() => setProfile('passive')}
                disabled={isScanning}
                className={`px-3.5 py-2 rounded-lg text-xs font-bold transition flex items-center space-x-1.5 ${
                  profile === 'passive'
                    ? 'bg-white text-indigo-700 shadow-sm border border-slate-200'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                <Eye className="w-3.5 h-3.5 text-sky-600" />
                <span>Passive Recon Only</span>
              </button>
            </div>

            {/* LAUNCH AUDIT BUTTON */}
            <button
              onClick={startLiveScan}
              disabled={isScanning}
              className={`px-6 py-3 rounded-xl font-bold text-xs uppercase tracking-wider flex items-center justify-center space-x-2 transition shadow-md ${
                isScanning
                  ? 'bg-slate-100 text-slate-400 cursor-not-allowed border border-slate-200'
                  : 'bg-indigo-600 hover:bg-indigo-700 text-white shadow-indigo-500/20 active:scale-[0.98]'
              }`}
            >
              {isScanning ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin text-indigo-500" />
                  <span>Sedang Memindai ({progress}%)...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current" />
                  <span>Jalankan Audit Keamanan Live</span>
                </>
              )}
            </button>
          </div>

          {/* QUICK TARGET PRESET CHIPS */}
          <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500">
            <span className="font-semibold text-slate-600">Preset Target Uji:</span>
            {['https://scanme.nmap.org', 'https://example.com', 'https://httpbin.org'].map((preset, idx) => (
              <button
                key={idx}
                onClick={() => setTargetUrl(preset)}
                disabled={isScanning}
                className="px-2.5 py-1 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 font-mono text-[11px] transition"
              >
                {preset}
              </button>
            ))}
          </div>

          {/* PROGRESS BAR (IF SCANNING) */}
          {isScanning && (
            <div className="space-y-1.5 pt-1">
              <div className="flex justify-between text-xs font-mono text-indigo-600 font-semibold">
                <span>{stage}</span>
                <span>{progress}% Selesai</span>
              </div>
              <div className="w-full h-2 bg-slate-100 rounded-full overflow-hidden border border-slate-200">
                <div 
                  className="h-full bg-gradient-to-r from-indigo-500 via-blue-500 to-cyan-500 transition-all duration-300"
                  style={{ width: `${progress}%` }}
                ></div>
              </div>
            </div>
          )}
        </div>
      </section>

      {/* MAIN NAVIGATION TABS */}
      <nav className="border-b border-slate-200 bg-white px-4 sm:px-6 lg:px-8">
        <div className="max-w-7xl mx-auto flex items-center space-x-2 sm:space-x-3 overflow-x-auto py-2.5">
          <button
            onClick={() => setActiveTab('live_scanner')}
            className={`px-3.5 py-2 rounded-xl text-xs font-bold whitespace-nowrap flex items-center space-x-2 transition ${
              activeTab === 'live_scanner'
                ? 'bg-indigo-50 text-indigo-700 border border-indigo-200 shadow-sm'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            <ShieldAlert className="w-4 h-4 text-indigo-600" />
            <span>Temuan Audit ({totalFindings})</span>
          </button>

          <button
            onClick={() => {
              setActiveTab('live_assets');
              if (!liveAssetData) loadLiveAssetData();
            }}
            className={`px-3.5 py-2 rounded-xl text-xs font-bold whitespace-nowrap flex items-center space-x-2 transition ${
              activeTab === 'live_assets'
                ? 'bg-indigo-50 text-indigo-700 border border-indigo-200 shadow-sm'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            <Compass className="w-4 h-4 text-cyan-600" />
            <span>API & Attack Surface</span>
          </button>

          <button
            onClick={() => setActiveTab('live_terminal')}
            className={`px-3.5 py-2 rounded-xl text-xs font-bold whitespace-nowrap flex items-center space-x-2 transition ${
              activeTab === 'live_terminal'
                ? 'bg-indigo-50 text-indigo-700 border border-indigo-200 shadow-sm'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            <Terminal className="w-4 h-4 text-slate-700" />
            <span>Interactive Live Terminal</span>
          </button>

          <button
            onClick={() => {
              setActiveTab('input_db_integrity');
              if (!inputTestUrl) setInputTestUrl(targetUrl);
              if (!dbBoundaryUrl) setDbBoundaryUrl(targetUrl);
            }}
            className={`px-3.5 py-2 rounded-xl text-xs font-bold whitespace-nowrap flex items-center space-x-2 transition ${
              activeTab === 'input_db_integrity'
                ? 'bg-rose-50 text-rose-700 border border-rose-200 shadow-sm font-black'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            <Database className="w-4 h-4 text-rose-600" />
            <span>Uji Input & Integritas DB</span>
          </button>

          <button
            onClick={() => setActiveTab('domain_intel')}
            className={`px-3.5 py-2 rounded-xl text-xs font-bold whitespace-nowrap flex items-center space-x-2 transition ${
              activeTab === 'domain_intel'
                ? 'bg-indigo-50 text-indigo-700 border border-indigo-200 shadow-sm'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            <Network className="w-4 h-4 text-blue-600" />
            <span>Domain Relations & CT Logs</span>
          </button>

          <button
            onClick={() => setActiveTab('remediation_hub')}
            className={`px-3.5 py-2 rounded-xl text-xs font-bold whitespace-nowrap flex items-center space-x-2 transition ${
              activeTab === 'remediation_hub'
                ? 'bg-indigo-50 text-indigo-700 border border-indigo-200 shadow-sm'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            <Code2 className="w-4 h-4 text-emerald-600" />
            <span>Remediation Hub</span>
          </button>

          <button
            onClick={() => setActiveTab('export_hub')}
            className={`px-3.5 py-2 rounded-xl text-xs font-bold whitespace-nowrap flex items-center space-x-2 transition ${
              activeTab === 'export_hub'
                ? 'bg-indigo-50 text-indigo-700 border border-indigo-200 shadow-sm'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            <FileText className="w-4 h-4 text-amber-600" />
            <span>Laporan & Kepatuhan</span>
          </button>

          <button
            onClick={() => setActiveTab('compliance_hub')}
            className={`px-3.5 py-2 rounded-xl text-xs font-bold whitespace-nowrap flex items-center space-x-2 transition ${
              activeTab === 'compliance_hub'
                ? 'bg-violet-50 text-violet-700 border border-violet-200 shadow-sm'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            <Award className="w-4 h-4 text-violet-600" />
            <span>Compliance Standards</span>
          </button>

          <button
            onClick={() => {
              setActiveTab('jwt_analyzer');
              if (!jwtInput && !jwtAuditResult) {
                const sampleToken = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIFVzZXIiLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE1MTYyMzkwMjJ9.';
                setJwtInput(sampleToken);
                setJwtAuditResult(parseJwtClient(sampleToken));
              }
            }}
            className={`px-3.5 py-2 rounded-xl text-xs font-bold whitespace-nowrap flex items-center space-x-2 transition ${
              activeTab === 'jwt_analyzer'
                ? 'bg-purple-50 text-purple-700 border border-purple-200 shadow-sm font-black'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            <Key className="w-4 h-4 text-purple-600" />
            <span>JWT Security Analyzer</span>
          </button>
        </div>
      </nav>

      {/* MAIN CONTENT AREA */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">

        {/* TAB 1: LIVE SCANNER & FINDINGS */}
        {activeTab === 'live_scanner' && (
          <div className="space-y-6">
            
            {/* SEVERITY STATS CARDS */}
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
              <div 
                onClick={() => setFilterSeverity('ALL')}
                className={`p-4 rounded-xl border cursor-pointer transition ${
                  filterSeverity === 'ALL' 
                    ? 'bg-indigo-50/80 border-indigo-300 shadow-md ring-2 ring-indigo-500/20' 
                    : 'glass-panel hover:border-slate-300'
                }`}
              >
                <div className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">Total Temuan</div>
                <div className="text-2xl font-black mt-1 text-slate-900">{totalFindings}</div>
              </div>

              <div 
                onClick={() => setFilterSeverity('CRITICAL')}
                className={`p-4 rounded-xl border cursor-pointer transition ${
                  filterSeverity === 'CRITICAL' 
                    ? 'bg-rose-50 border-rose-300 shadow-md ring-2 ring-rose-500/20' 
                    : 'glass-panel hover:border-slate-300'
                }`}
              >
                <div className="text-[11px] font-bold text-rose-600 uppercase tracking-wider">Critical</div>
                <div className="text-2xl font-black mt-1 text-rose-700">{counts.CRITICAL}</div>
              </div>

              <div 
                onClick={() => setFilterSeverity('HIGH')}
                className={`p-4 rounded-xl border cursor-pointer transition ${
                  filterSeverity === 'HIGH' 
                    ? 'bg-amber-50 border-amber-300 shadow-md ring-2 ring-amber-500/20' 
                    : 'glass-panel hover:border-slate-300'
                }`}
              >
                <div className="text-[11px] font-bold text-amber-600 uppercase tracking-wider">High</div>
                <div className="text-2xl font-black mt-1 text-amber-700">{counts.HIGH}</div>
              </div>

              <div 
                onClick={() => setFilterSeverity('MEDIUM')}
                className={`p-4 rounded-xl border cursor-pointer transition ${
                  filterSeverity === 'MEDIUM' 
                    ? 'bg-yellow-50 border-yellow-300 shadow-md ring-2 ring-yellow-500/20' 
                    : 'glass-panel hover:border-slate-300'
                }`}
              >
                <div className="text-[11px] font-bold text-yellow-700 uppercase tracking-wider">Medium</div>
                <div className="text-2xl font-black mt-1 text-yellow-800">{counts.MEDIUM}</div>
              </div>

              <div 
                onClick={() => setFilterSeverity('LOW')}
                className={`p-4 rounded-xl border cursor-pointer transition ${
                  filterSeverity === 'LOW' 
                    ? 'bg-sky-50 border-sky-300 shadow-md ring-2 ring-sky-500/20' 
                    : 'glass-panel hover:border-slate-300'
                }`}
              >
                <div className="text-[11px] font-bold text-sky-600 uppercase tracking-wider">Low</div>
                <div className="text-2xl font-black mt-1 text-sky-700">{counts.LOW}</div>
              </div>

              <div 
                onClick={() => setFilterSeverity('INFO')}
                className={`p-4 rounded-xl border cursor-pointer transition ${
                  filterSeverity === 'INFO' 
                    ? 'bg-slate-100 border-slate-400 shadow-md ring-2 ring-slate-500/20' 
                    : 'glass-panel hover:border-slate-300'
                }`}
              >
                <div className="text-[11px] font-bold text-slate-600 uppercase tracking-wider">Informational</div>
                <div className="text-2xl font-black mt-1 text-slate-800">{counts.INFO}</div>
              </div>
            </div>

            {/* LIVE TELEMETRY LOGS (CLEAN WHITE/GREY CARD) */}
            <div className="glass-panel rounded-xl border border-slate-200 overflow-hidden">
              <div className="bg-slate-50 px-4 py-2.5 border-b border-slate-200 flex items-center justify-between">
                <div className="flex items-center space-x-2 text-xs font-bold text-slate-700">
                  <Terminal className="w-3.5 h-3.5 text-indigo-600" />
                  <span>Real-Time Audit Telemetry Stream</span>
                </div>
                <span className="text-[11px] text-slate-500 font-mono">{logs.length} events logged</span>
              </div>
              <div 
                ref={terminalRef}
                className="p-3.5 font-mono text-[11px] text-slate-700 bg-white max-h-36 overflow-y-auto space-y-1 select-text border-t border-slate-100"
              >
                {logs.map((line, idx) => (
                  <div key={idx} className={line.includes('[ERROR]') ? 'text-rose-600 font-semibold' : line.includes('[INIT]') || line.includes('[DONE]') ? 'text-indigo-600 font-semibold' : 'text-slate-600'}>
                    {line}
                  </div>
                ))}
              </div>
            </div>

            {/* VULNERABILITY FINDINGS LIST WITH SEARCH & FILTER & HEATMAP */}
            <div className="space-y-3">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="flex items-center space-x-2">
                  <Bug className="w-4 h-4 text-indigo-600" />
                  <h3 className="text-sm font-bold text-slate-800">
                    Temuan Kerentanan & Konfigurasi Keamanan ({filteredFindings.length})
                  </h3>
                </div>

                <div className="flex items-center space-x-2 w-full sm:w-auto">
                  <button
                    onClick={() => setShowHeatmap(!showHeatmap)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-bold flex items-center space-x-1.5 transition ${
                      showHeatmap
                        ? 'bg-indigo-600 text-white shadow-sm'
                        : 'bg-white hover:bg-slate-50 text-indigo-700 border border-slate-300'
                    }`}
                  >
                    <BarChart2 className="w-3.5 h-3.5" />
                    <span>{showHeatmap ? 'Tutup Heatmap' : 'Heatmap OWASP'}</span>
                  </button>

                  {/* SEARCH INPUT */}
                  <div className="relative w-full sm:w-64">
                    <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
                    <input
                      type="text"
                      placeholder="Cari temuan, CWE, CVE, OWASP..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="w-full bg-white rounded-lg border border-slate-300 pl-9 pr-3 py-1.5 text-xs text-slate-800 placeholder-slate-400 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500"
                    />
                  </div>
                </div>
              </div>

              {/* OWASP TOP 10 × SEVERITY HEATMAP MATRIX */}
              {showHeatmap && (
                <div className="glass-panel p-4 rounded-xl border border-indigo-200 bg-gradient-to-br from-indigo-50/50 via-white to-purple-50/30 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2 text-xs font-bold text-slate-800">
                      <BarChart2 className="w-4 h-4 text-indigo-600" />
                      <span>OWASP Top 10 × Severity Heatmap Matrix</span>
                    </div>
                    <span className="text-[11px] text-slate-500 font-medium">Klik pada angka untuk memfilter temuan</span>
                  </div>

                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs border-collapse">
                      <thead>
                        <tr className="border-b border-slate-200 text-[11px] font-bold text-slate-600">
                          <th className="py-2 px-3">Kategori OWASP</th>
                          <th className="py-2 px-2 text-center text-rose-700">Critical</th>
                          <th className="py-2 px-2 text-center text-amber-700">High</th>
                          <th className="py-2 px-2 text-center text-yellow-700">Medium</th>
                          <th className="py-2 px-2 text-center text-sky-700">Low</th>
                          <th className="py-2 px-2 text-center text-slate-600">Info</th>
                          <th className="py-2 px-2 text-center text-indigo-700 font-black">Total</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100">
                        {OWASP_CATEGORIES.map((cat) => {
                          const catFindings = findings.filter(f => 
                            (f.owasp_category || '').includes(cat.match) ||
                            (f.title || '').toLowerCase().includes(cat.match.toLowerCase())
                          );
                          const crit = catFindings.filter(f => (f.severity || '').toUpperCase() === 'CRITICAL').length;
                          const high = catFindings.filter(f => (f.severity || '').toUpperCase() === 'HIGH').length;
                          const med = catFindings.filter(f => (f.severity || '').toUpperCase() === 'MEDIUM').length;
                          const low = catFindings.filter(f => (f.severity || '').toUpperCase() === 'LOW').length;
                          const info = catFindings.filter(f => ['INFO', 'INFORMATIONAL'].includes((f.severity || '').toUpperCase())).length;
                          const total = catFindings.length;

                          return (
                            <tr key={cat.id} className="hover:bg-slate-50/80 transition">
                              <td className="py-2 px-3 font-semibold text-slate-800 text-[11px]">{cat.name}</td>
                              <td 
                                onClick={() => { if (crit > 0) { setSearchQuery(cat.match); setFilterSeverity('CRITICAL'); } }}
                                className={`py-1 px-2 text-center font-bold text-[11px] rounded transition ${
                                  crit > 0 ? 'bg-rose-100 text-rose-800 cursor-pointer hover:bg-rose-200' : 'text-slate-300'
                                }`}
                              >
                                {crit}
                              </td>
                              <td 
                                onClick={() => { if (high > 0) { setSearchQuery(cat.match); setFilterSeverity('HIGH'); } }}
                                className={`py-1 px-2 text-center font-bold text-[11px] rounded transition ${
                                  high > 0 ? 'bg-amber-100 text-amber-800 cursor-pointer hover:bg-amber-200' : 'text-slate-300'
                                }`}
                              >
                                {high}
                              </td>
                              <td 
                                onClick={() => { if (med > 0) { setSearchQuery(cat.match); setFilterSeverity('MEDIUM'); } }}
                                className={`py-1 px-2 text-center font-bold text-[11px] rounded transition ${
                                  med > 0 ? 'bg-yellow-100 text-yellow-800 cursor-pointer hover:bg-yellow-200' : 'text-slate-300'
                                }`}
                              >
                                {med}
                              </td>
                              <td 
                                onClick={() => { if (low > 0) { setSearchQuery(cat.match); setFilterSeverity('LOW'); } }}
                                className={`py-1 px-2 text-center font-bold text-[11px] rounded transition ${
                                  low > 0 ? 'bg-sky-100 text-sky-800 cursor-pointer hover:bg-sky-200' : 'text-slate-300'
                                }`}
                              >
                                {low}
                              </td>
                              <td 
                                onClick={() => { if (info > 0) { setSearchQuery(cat.match); setFilterSeverity('INFO'); } }}
                                className={`py-1 px-2 text-center font-bold text-[11px] rounded transition ${
                                  info > 0 ? 'bg-slate-200 text-slate-800 cursor-pointer hover:bg-slate-300' : 'text-slate-300'
                                }`}
                              >
                                {info}
                              </td>
                              <td 
                                onClick={() => { if (total > 0) { setSearchQuery(cat.match); setFilterSeverity('ALL'); } }}
                                className={`py-1 px-2 text-center font-extrabold text-[11px] rounded transition ${
                                  total > 0 ? 'bg-indigo-100 text-indigo-900 cursor-pointer hover:bg-indigo-200' : 'text-slate-300'
                                }`}
                              >
                                {total}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {filteredFindings.length === 0 ? (
                <div className="glass-panel p-12 text-center rounded-xl border border-slate-200 space-y-3">
                  <ShieldCheck className="w-10 h-10 text-emerald-500 mx-auto" />
                  <h4 className="text-sm font-bold text-slate-800">
                    {isScanning ? 'Memindai target secara live...' : 'Tidak ada temuan pada filter ini.'}
                  </h4>
                  <p className="text-xs text-slate-500 max-w-md mx-auto">
                    {isScanning 
                      ? 'Engine sedang mengirim probe aktif dan pasif terhadap target domain.' 
                      : 'Masukkan URL target di atas dan klik "Jalankan Audit Keamanan Live" untuk memulai pengujian.'}
                  </p>
                </div>
              ) : (
                <div className="space-y-3">
                  {filteredFindings.map((item, idx) => {
                    const sev = item.severity?.toUpperCase() || 'INFO';
                    const sevBadge = 
                      sev === 'CRITICAL' ? 'bg-rose-100 text-rose-800 border-rose-200 font-black' :
                      sev === 'HIGH' ? 'bg-amber-100 text-amber-800 border-amber-200 font-bold' :
                      sev === 'MEDIUM' ? 'bg-yellow-100 text-yellow-800 border-yellow-200 font-bold' :
                      sev === 'LOW' ? 'bg-sky-100 text-sky-800 border-sky-200 font-semibold' :
                      'bg-slate-100 text-slate-700 border-slate-200 font-semibold';

                    const cveMatch = (item.title + ' ' + (item.description || '')).match(/CVE-\d{4}-\d{4,7}/i);
                    const diff = getExploitDifficulty(item);

                    return (
                      <div 
                        key={idx}
                        className="glass-panel p-5 rounded-xl border border-slate-200 hover:border-slate-300 hover:shadow-md transition space-y-3 relative overflow-hidden"
                      >
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className={`px-2.5 py-0.5 rounded-full text-[10px] border uppercase tracking-wider ${sevBadge}`}>
                              {sev} {item.cvss_score ? `• CVSS ${item.cvss_score}` : ''}
                            </span>

                            {cveMatch && (
                              <a
                                href={`https://nvd.nist.gov/vuln/detail/${cveMatch[0].toUpperCase()}`}
                                target="_blank"
                                rel="noreferrer"
                                className="px-2 py-0.5 rounded-md bg-purple-100 border border-purple-300 text-purple-800 text-[10px] font-extrabold flex items-center space-x-1 hover:bg-purple-200 transition"
                                title="Lihat NVD NIST Advisory Resmi"
                              >
                                <span>🔥 {cveMatch[0].toUpperCase()}</span>
                                <ExternalLink className="w-2.5 h-2.5" />
                              </a>
                            )}

                            <div className="flex items-center space-x-1.5 px-2 py-0.5 rounded-md bg-slate-100 border border-slate-200 text-[10px]" title={diff.note}>
                              <Sliders className="w-3 h-3 text-slate-500" />
                              <span className="text-slate-500 font-semibold">Tingkat Eksploitasi:</span>
                              <span className={`font-black ${diff.color}`}>{diff.label}</span>
                              <div className="flex space-x-0.5 ml-1">
                                {[1, 2, 3, 4, 5].map((step) => (
                                  <div 
                                    key={step} 
                                    className={`w-1.5 h-2.5 rounded-sm ${step <= diff.level ? diff.bg : 'bg-slate-200'}`}
                                  />
                                ))}
                              </div>
                            </div>

                            <h4 className="text-sm font-bold text-slate-900 ml-1">{item.title}</h4>
                          </div>

                          <div className="flex items-center space-x-2">
                            {/* Live PoC Re-Test Button */}
                            <button
                              onClick={() => openPoCModal(item)}
                              className="px-3 py-1 rounded-lg bg-indigo-50 hover:bg-indigo-100 border border-indigo-200 text-indigo-700 text-xs font-bold flex items-center space-x-1.5 transition flex-shrink-0"
                            >
                              <Play className="w-3 h-3 fill-current text-indigo-600" />
                              <span>Uji Live PoC</span>
                            </button>
                          </div>
                        </div>

                        <p className="text-xs text-slate-600 leading-relaxed">{item.description}</p>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2 text-xs">
                          {item.evidence && (
                            <div className="bg-slate-50 p-3 rounded-lg border border-slate-200 font-mono text-[11px] text-slate-700 space-y-1">
                              <span className="text-slate-500 font-bold block text-[10px] uppercase">Bukti Live Probe:</span>
                              <div className="text-indigo-700 break-all">{item.evidence}</div>
                            </div>
                          )}

                          {item.remediation && (
                            <div className="bg-emerald-50/70 p-3 rounded-lg border border-emerald-200 text-[11px] text-slate-700 space-y-1">
                              <span className="text-emerald-800 font-bold block text-[10px] uppercase">Langkah Remediasi:</span>
                              <div className="text-slate-800">{item.remediation}</div>
                            </div>
                          )}
                        </div>

                        <div className="flex flex-wrap items-center gap-2 pt-1 text-[11px] text-slate-500 font-mono">
                          {item.owasp_category && (
                            <span className="px-2 py-0.5 rounded bg-slate-100 border border-slate-200">
                              OWASP: {item.owasp_category}
                            </span>
                          )}
                          {item.cwe && (
                            <span className="px-2 py-0.5 rounded bg-slate-100 border border-slate-200">
                              CWE: {item.cwe}
                            </span>
                          )}
                          {item.cvss_vector && (
                            <span className="px-2 py-0.5 rounded bg-slate-100 border border-slate-200 text-[10px]">
                              Vector: {item.cvss_vector}
                            </span>
                          )}
                          {item.target_url && (
                            <span className="px-2 py-0.5 rounded bg-slate-100 border border-slate-200 truncate max-w-xs">
                              URL: {item.target_url}
                            </span>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 2: LIVE ATTACK SURFACE & RECON EXPLORER */}
        {activeTab === 'live_assets' && (
          <div className="space-y-5">
            
            {/* TOP BAR */}
            <div className="glass-panel p-5 rounded-xl border border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <h3 className="text-base font-bold text-slate-900 flex items-center space-x-2">
                  <Compass className="w-5 h-5 text-indigo-600" />
                  <span>API & Attack Surface Explorer (2026 Edition)</span>
                </h3>
                <p className="text-xs text-slate-500 mt-0.5">
                  Eksplorasi mendalam endpoint ter-crawl, matriks status file sensitif & OpenAPI, security headers, WAF, dan open ports.
                </p>
              </div>

              <button
                onClick={() => loadLiveAssetData()}
                disabled={isAssetLoading}
                className="px-4 py-2 rounded-xl bg-white hover:bg-slate-50 border border-slate-300 text-xs font-bold text-indigo-700 flex items-center space-x-2 transition shadow-sm"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isAssetLoading ? 'animate-spin' : ''}`} />
                <span>Muat Ulang Asset Live</span>
              </button>
            </div>

            {/* SUB-TABS */}
            <div className="flex flex-wrap gap-2 border-b border-slate-200 pb-3">
              {[
                { id: 'endpoints', label: 'Endpoints & Formulir Ter-crawl', icon: Globe },
                { id: 'paths', label: 'Matriks File Sensitif & OpenAPI', icon: FileCode },
                { id: 'headers', label: 'Evaluasi Security Headers', icon: ShieldCheck },
                { id: 'perimeter', label: 'Perimeter, WAF & Open Ports', icon: RadioTower },
              ].map((sub) => {
                const Icon = sub.icon;
                return (
                  <button
                    key={sub.id}
                    onClick={() => setAssetSubTab(sub.id)}
                    className={`px-3.5 py-2 rounded-xl text-xs font-bold flex items-center space-x-2 transition ${
                      assetSubTab === sub.id
                        ? 'bg-indigo-600 text-white shadow-sm'
                        : 'bg-white text-slate-600 hover:text-slate-900 border border-slate-200'
                    }`}
                  >
                    <Icon className="w-3.5 h-3.5" />
                    <span>{sub.label}</span>
                  </button>
                );
              })}
            </div>

            {/* SUB-TAB 1: DISCOVERED ENDPOINTS & FORMS */}
            {assetSubTab === 'endpoints' && (
              <div className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Discovered URLs */}
                  <div className="glass-panel p-5 rounded-xl border border-slate-200 space-y-3">
                    <div className="flex items-center justify-between">
                      <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider flex items-center space-x-2">
                        <Globe className="w-3.5 h-3.5 text-indigo-600" />
                        <span>Tautan Internal Ditemukan ({liveAssetData?.discovered_urls?.length || 1})</span>
                      </h4>
                    </div>
                    <div className="space-y-2 max-h-72 overflow-y-auto">
                      {(liveAssetData?.discovered_urls || [targetUrl]).map((url, idx) => (
                        <div key={idx} className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 font-mono text-xs text-slate-700 flex items-center justify-between">
                          <span className="truncate mr-2">{url}</span>
                          <button
                            onClick={() => {
                              setActiveTab('live_terminal');
                              executeTerminalCommand(`curl ${url}`);
                            }}
                            className="px-2 py-0.5 rounded bg-white hover:bg-indigo-600 hover:text-white text-[11px] font-bold text-indigo-700 border border-slate-200 transition flex-shrink-0"
                          >
                            Probe Live
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Discovered Forms */}
                  <div className="glass-panel p-5 rounded-xl border border-slate-200 space-y-3">
                    <div className="flex items-center justify-between">
                      <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider flex items-center space-x-2">
                        <FileCode className="w-3.5 h-3.5 text-indigo-600" />
                        <span>Formulir HTML Ditemukan ({liveAssetData?.discovered_forms?.length || 0})</span>
                      </h4>
                    </div>
                    <div className="space-y-2 max-h-72 overflow-y-auto">
                      {(liveAssetData?.discovered_forms || []).length === 0 ? (
                        <div className="text-xs text-slate-400 italic p-4 text-center">
                          Tidak ditemukan form HTML terbuka pada crawling tingkat atas.
                        </div>
                      ) : (
                        liveAssetData.discovered_forms.map((form, idx) => (
                          <div key={idx} className="p-3 rounded-lg bg-slate-50 border border-slate-200 font-mono text-xs text-slate-700 space-y-1.5">
                            <div className="flex items-center justify-between">
                              <span className="font-bold text-indigo-600">[{form.method}]</span>
                              <span className="text-[11px] text-slate-500 truncate">{form.url}</span>
                            </div>
                            <div className="text-[11px] text-slate-600 flex items-center justify-between">
                              <div>
                                Parameter: <span className="text-slate-900 font-semibold">{form.inputs?.join(', ') || 'None'}</span>
                              </div>
                              {form.inputs && form.inputs.length > 0 && (
                                <button
                                  onClick={() => {
                                    setInputTestUrl(form.url);
                                    setInputTestParam(form.inputs[0]);
                                    setInputTestMethod(form.method || 'GET');
                                    setActiveTab('input_db_integrity');
                                    setActiveSubTabInputDB('input_resilience');
                                  }}
                                  className="px-2 py-0.5 rounded-lg bg-rose-50 hover:bg-rose-100 text-rose-700 border border-rose-200 text-[10px] font-bold transition flex items-center space-x-1"
                                >
                                  <span>Uji di Lab Input</span>
                                  <ChevronRight className="w-3 h-3" />
                                </button>
                              )}
                            </div>
                          </div>
                        ))
                      )}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* SUB-TAB 2: SENSITIVE PATHS MATRIX */}
            {assetSubTab === 'paths' && (
              <div className="space-y-4">
                
                {/* CUSTOM PATH PROBER */}
                <div className="glass-panel p-4 rounded-xl border border-slate-200 space-y-3">
                  <h4 className="text-xs font-bold text-slate-800 flex items-center space-x-2">
                    <Search className="w-3.5 h-3.5 text-indigo-600" />
                    <span>Uji Endpoint Kustom Mandiri</span>
                  </h4>
                  <div className="flex items-center space-x-2">
                    <span className="text-xs font-mono text-slate-600 bg-slate-100 px-3 py-2 rounded-lg border border-slate-200 truncate max-w-xs">
                      {targetUrl}
                    </span>
                    <input
                      type="text"
                      placeholder="/admin, /api/v1, /openapi.json, /.git/config, /swagger-ui.html"
                      value={customPathInput}
                      onChange={(e) => setCustomPathInput(e.target.value)}
                      className="bg-white border border-slate-300 rounded-lg px-3 py-2 text-xs font-mono text-slate-800 flex-1 focus:outline-none focus:border-indigo-500"
                    />
                    <button
                      onClick={probeCustomPath}
                      disabled={isCustomPathProbing}
                      className="px-4 py-2 rounded-lg bg-indigo-600 text-white font-bold text-xs hover:bg-indigo-700 transition shadow-sm"
                    >
                      {isCustomPathProbing ? 'Menguji...' : 'Probe Live'}
                    </button>
                  </div>

                  {customPathResult && (
                    <div className="mt-2 bg-slate-900 text-slate-200 p-3 rounded-xl border border-slate-800 font-mono text-xs">
                      <div className="text-[10px] text-slate-400 mb-1">Target: {customPathResult.url}</div>
                      <pre className="text-[11px] text-cyan-300 whitespace-pre-wrap">{customPathResult.output}</pre>
                    </div>
                  )}
                </div>

                {/* SENSITIVE PATHS MATRIX TABLE */}
                <div className="glass-panel rounded-xl border border-slate-200 overflow-hidden">
                  <div className="bg-slate-50 px-4 py-3 border-b border-slate-200 flex items-center justify-between text-xs font-bold text-slate-800">
                    <span>Matriks Status File Sensitif & OpenAPI Endpoints</span>
                    <span className="text-[11px] text-slate-500 font-mono">Real-Time HTTP Probed</span>
                  </div>

                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs font-mono">
                      <thead className="bg-slate-100 text-[10px] text-slate-600 uppercase tracking-wider border-b border-slate-200">
                        <tr>
                          <th className="px-4 py-2.5">Path Target</th>
                          <th className="px-4 py-2.5">Kategori / Judul</th>
                          <th className="px-4 py-2.5">Live Status</th>
                          <th className="px-4 py-2.5">Ukuran</th>
                          <th className="px-4 py-2.5">Tingkat Risiko</th>
                          <th className="px-4 py-2.5">Aksi</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-200 text-slate-700">
                        {(liveAssetData?.sensitive_paths_matrix || []).map((item, idx) => {
                          const statusColor = 
                            item.status_code === 200 && item.is_exposed ? 'text-rose-700 font-bold bg-rose-100 border-rose-300' :
                            item.status_code === 200 ? 'text-amber-700 bg-amber-50 border-amber-200' :
                            item.status_code === 403 ? 'text-sky-700 bg-sky-50 border-sky-200' :
                            'text-slate-500 bg-slate-100 border-slate-200';

                          return (
                            <tr key={idx} className="hover:bg-slate-50/80">
                              <td className="px-4 py-2.5 font-bold text-slate-900">{item.path}</td>
                              <td className="px-4 py-2.5 text-slate-600 font-sans">{item.title}</td>
                              <td className="px-4 py-2.5">
                                <span className={`px-2 py-0.5 rounded border text-[10px] ${statusColor}`}>
                                  {item.status_code ? `HTTP ${item.status_code}` : 'No Response'}
                                </span>
                              </td>
                              <td className="px-4 py-2.5 text-slate-500">{item.content_length ? `${item.content_length} B` : '-'}</td>
                              <td className="px-4 py-2.5">
                                <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                  item.severity === 'Critical' ? 'text-rose-700 bg-rose-50' :
                                  item.severity === 'High' ? 'text-amber-700 bg-amber-50' : 'text-slate-600'
                                }`}>
                                  {item.severity}
                                </span>
                              </td>
                              <td className="px-4 py-2.5">
                                <button
                                  onClick={() => {
                                    setActiveTab('live_terminal');
                                    executeTerminalCommand(`curl ${item.path}`);
                                  }}
                                  className="px-2.5 py-0.5 rounded bg-white hover:bg-indigo-600 hover:text-white text-[11px] font-bold text-indigo-700 border border-slate-300 transition shadow-sm"
                                >
                                  Inspeksi Live
                                </button>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            )}

            {/* SUB-TAB 3: SECURITY HEADERS */}
            {assetSubTab === 'headers' && (
              <div className="glass-panel p-5 rounded-xl border border-slate-200 space-y-4">
                <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider flex items-center space-x-2">
                  <ShieldCheck className="w-4 h-4 text-indigo-600" />
                  <span>Evaluasi HTTP Security Headers Standar 2026</span>
                </h4>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {[
                    { name: 'Strict-Transport-Security (HSTS)', desc: 'Mencegah serangan SSL-strip & MitM downgrade, memaksa HTTPS.', std: 'max-age=31536000; includeSubDomains; preload' },
                    { name: 'Content-Security-Policy (CSP)', desc: 'Mencegah eksekusi script jahat XSS dan injeksi data.', std: "default-src 'self'; script-src 'self'" },
                    { name: 'X-Frame-Options', desc: 'Mencegah Clickjacking UI redressing via iframe.', std: 'DENY atau SAMEORIGIN' },
                    { name: 'X-Content-Type-Options', desc: 'Mencegah MIME-type sniffing browser.', std: 'nosniff' },
                    { name: 'Referrer-Policy', desc: 'Mengontrol kebocoran parameter URL sensitif ke server lain.', std: 'strict-origin-when-cross-origin' },
                    { name: 'Permissions-Policy', desc: 'Membatasi akses API kamera, mikrofon, dan geolocation.', std: 'camera=(), microphone=(), geolocation=()' },
                    { name: 'Cross-Origin-Opener-Policy (COOP)', desc: 'Isolasi konteks browsing untuk proteksi side-channel (Spectre).', std: 'same-origin' },
                    { name: 'Cross-Origin-Resource-Policy (CORP)', desc: 'Membatasi pembacaan resource internal lintas-domain.', std: 'same-origin' },
                  ].map((hdr, idx) => (
                    <div key={idx} className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 text-xs space-y-1">
                      <div className="font-bold text-indigo-700">{hdr.name}</div>
                      <p className="text-[11px] text-slate-600">{hdr.desc}</p>
                      <div className="text-[10px] font-mono text-slate-500 pt-1">Rekomendasi: {hdr.std}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* SUB-TAB 4: PERIMETER, WAF & PORTS */}
            {assetSubTab === 'perimeter' && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="glass-panel p-5 rounded-xl border border-slate-200 space-y-3">
                  <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider flex items-center space-x-2">
                    <Shield className="w-3.5 h-3.5 text-indigo-600" />
                    <span>Hasil Deteksi WAF & CDN Firewall</span>
                  </h4>
                  <pre className="p-3.5 rounded-lg bg-slate-900 text-slate-200 border border-slate-800 font-mono text-xs whitespace-pre-wrap overflow-x-auto">
                    {liveAssetData?.waf_summary || '// Klik "Muat Ulang Asset Live" untuk mendeteksi WAF target.'}
                  </pre>
                </div>

                <div className="glass-panel p-5 rounded-xl border border-slate-200 space-y-3">
                  <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider flex items-center space-x-2">
                    <RadioTower className="w-3.5 h-3.5 text-indigo-600" />
                    <span>Hasil Port Scan Web & Layanan Target</span>
                  </h4>
                  <pre className="p-3.5 rounded-lg bg-slate-900 text-slate-200 border border-slate-800 font-mono text-xs whitespace-pre-wrap overflow-x-auto">
                    {liveAssetData?.ports_summary || '// Klik "Muat Ulang Asset Live" untuk memindai port umum.'}
                  </pre>
                </div>
              </div>
            )}
          </div>
        )}

        {/* TAB 3: INTERACTIVE LIVE TERMINAL */}
        {activeTab === 'live_terminal' && (
          <div className="space-y-4">
            
            {/* TERMINAL HEADER & QUICK PILLS */}
            <div className="glass-panel p-4 rounded-xl border border-slate-200 space-y-3">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div>
                  <h3 className="text-sm font-bold text-slate-900 flex items-center space-x-2">
                    <Terminal className="w-4 h-4 text-indigo-600" />
                    <span>Live Interactive Security Console (2026 Edition)</span>
                  </h3>
                  <p className="text-[11px] text-slate-500">
                    Ketik perintah atau klik quick pills di bawah untuk mengirim probe jaringan & HTTP secara langsung ke <span className="font-mono font-bold text-indigo-700">{targetUrl}</span>.
                  </p>
                </div>

                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => setTerminalHistory([])}
                    className="px-2.5 py-1 rounded-lg bg-white border border-slate-300 text-[11px] text-slate-600 hover:text-slate-900 shadow-sm transition"
                  >
                    Bersihkan Layar
                  </button>
                </div>
              </div>

              {/* QUICK COMMAND PILLS */}
              <div className="flex flex-wrap gap-1.5 pt-1">
                {[
                  { label: '📊 Scorecard', cmd: 'scorecard', highlight: true },
                  { label: '🏛️ Compliance', cmd: 'compliance', highlight: true },
                  { label: '🔍 Test Input/Search', cmd: 'test-input', highlight: true },
                  { label: '🛡️ DB Boundary DDL', cmd: 'db-boundary', highlight: true },
                  { label: '🛡️ Email/DNS Sec', cmd: 'emailsec', highlight: true },
                  { label: 'Headers Audit', cmd: 'headers' },
                  { label: 'OpenAPI / Swagger', cmd: 'api' },
                  { label: 'GraphQL Probe', cmd: 'graphql' },
                  { label: 'CORS Reflection', cmd: 'cors' },
                  { label: 'SSL/TLS 1.3', cmd: 'ssl' },
                  { label: 'DNS Records', cmd: 'dns ALL' },
                  { label: 'WAF Detect', cmd: 'waf' },
                  { label: 'Port Scan', cmd: 'portscan' },
                  { label: 'Probe Secrets', cmd: 'fuzz' },
                  { label: 'Tech Fingerprint', cmd: 'tech' },
                  { label: 'Remediation Fix', cmd: 'remediation' },
                  { label: 'Spider / Crawl', cmd: 'crawl' },
                  { label: 'Robots & Sitemap', cmd: 'robots' },
                  { label: 'IP & WHOIS', cmd: 'whois' },
                ].map((pill, idx) => (
                  <button
                    key={idx}
                    onClick={() => executeTerminalCommand(pill.cmd)}
                    disabled={isTermExecuting}
                    className={`px-2.5 py-1 rounded-lg border text-[11px] font-mono transition shadow-sm ${
                      pill.highlight
                        ? 'bg-violet-50 hover:bg-violet-100 border-violet-200 hover:border-violet-400 text-violet-700 hover:text-violet-900 font-semibold'
                        : 'bg-slate-100 hover:bg-indigo-50 border-slate-200 hover:border-indigo-300 text-slate-700 hover:text-indigo-700'
                    }`}
                  >
                    {pill.highlight ? pill.label : `$${pill.cmd}`}
                  </button>
                ))}
              </div>
            </div>

            {/* TERMINAL DISPLAY SCREEN (DARK TERMINAL INSIDE CLEAN WHITE FRAME) */}
            <div className="rounded-xl border border-slate-300 overflow-hidden shadow-lg bg-slate-950">
              <div className="bg-slate-900 px-4 py-2.5 border-b border-slate-800 flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <div className="w-3 h-3 rounded-full bg-rose-500"></div>
                  <div className="w-3 h-3 rounded-full bg-amber-500"></div>
                  <div className="w-3 h-3 rounded-full bg-emerald-500"></div>
                  <span className="font-mono text-xs text-slate-300 ml-2 font-bold">live-audit-shell</span>
                </div>
                <span className="text-[11px] text-cyan-400 font-mono">Target: {targetUrl}</span>
              </div>

              <div 
                ref={simTerminalRef}
                className="p-5 font-mono text-xs text-slate-200 min-h-[420px] max-h-[560px] overflow-y-auto space-y-4 select-text leading-relaxed"
              >
                {terminalHistory.map((item, idx) => (
                  <div key={idx} className="space-y-1.5 border-b border-slate-900 pb-3">
                    <div className="flex items-center justify-between text-slate-400 text-[11px]">
                      <div className="flex items-center space-x-1.5 text-cyan-400">
                        <span className="text-emerald-400 font-bold">{item.prompt || 'auditor@live-target:~$ '}</span>
                        <span className="text-white font-bold">{item.command}</span>
                      </div>
                      <span className="text-slate-500 text-[10px]">{item.timestamp}</span>
                    </div>
                    <pre className="text-slate-300 text-[11px] whitespace-pre-wrap break-all bg-slate-900/60 p-3 rounded-lg border border-slate-800 overflow-x-auto">
                      {item.output}
                    </pre>
                  </div>
                ))}

                {isTermExecuting && (
                  <div className="flex items-center space-x-2 text-cyan-400 text-xs animate-pulse">
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Sedang mengeksekusi live probe pada target server...</span>
                  </div>
                )}
              </div>

              {/* TERMINAL INPUT PROMPT */}
              <form 
                onSubmit={(e) => {
                  e.preventDefault();
                  executeTerminalCommand();
                }}
                className="bg-slate-900 p-3 border-t border-slate-800 flex items-center space-x-2"
              >
                <span className="font-mono text-xs text-emerald-400 font-bold flex-shrink-0">
                  auditor@live-target:~$
                </span>
                <input
                  type="text"
                  placeholder="Ketik command live (contoh: headers, api, graphql, cors, ssl, dns, waf, portscan, fuzz, help)..."
                  value={terminalInput}
                  onChange={(e) => setTerminalInput(e.target.value)}
                  disabled={isTermExecuting}
                  className="bg-transparent border-none text-white placeholder-slate-500 text-xs font-mono w-full focus:outline-none"
                />
                <button
                  type="submit"
                  disabled={isTermExecuting || !terminalInput.trim()}
                  className="px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-xs transition disabled:opacity-50"
                >
                  Jalankan
                </button>
              </form>
            </div>
          </div>
        )}

        {/* TAB 4: DOMAIN RELATIONS & CT LOGS */}
        {activeTab === 'domain_intel' && (
          <div className="space-y-6">
            {!domainIntel ? (
              <div className="glass-panel p-12 text-center rounded-xl border border-slate-200 space-y-3">
                <Network className="w-10 h-10 text-indigo-600 mx-auto" />
                <h4 className="text-sm font-bold text-slate-800">Domain Relations & SSL Intelligence</h4>
                <p className="text-xs text-slate-500 max-w-md mx-auto">
                  Jalankan live scan pada target domain untuk menganalisis Subject Alternative Names (SANs) dan histori Certificate Transparency (CT Logs).
                </p>
              </div>
            ) : (
              <div className="space-y-4">
                {/* SSL OVERVIEW */}
                <div className="glass-panel p-5 rounded-xl border border-slate-200 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 text-xs">
                  <div>
                    <span className="text-[10px] text-slate-500 uppercase font-bold">Domain Target</span>
                    <div className="text-sm font-bold text-indigo-700 font-mono mt-0.5">{domainIntel.target_domain}</div>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-500 uppercase font-bold">Certificate Issuer</span>
                    <div className="text-sm font-bold text-slate-800 font-mono mt-0.5">{domainIntel.current_ssl?.issuer || 'N/A'}</div>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-500 uppercase font-bold">Berlaku Hingga</span>
                    <div className="text-sm font-bold text-slate-800 font-mono mt-0.5">{domainIntel.current_ssl?.not_after || 'N/A'}</div>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-500 uppercase font-bold">Total SAN Domains</span>
                    <div className="text-sm font-bold text-emerald-700 font-mono mt-0.5">{domainIntel.san_domains?.length || 0} Domains</div>
                  </div>
                </div>

                {/* SANS LIST */}
                <div className="glass-panel p-5 rounded-xl border border-slate-200 space-y-3">
                  <div className="flex items-center justify-between">
                    <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                      Subject Alternative Names (SANs) & Cross-Domain Sharing
                    </h4>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2">
                    {(domainIntel.san_domains || []).map((san, idx) => (
                      <div key={idx} className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 font-mono text-xs text-slate-700 flex items-center space-x-2">
                        <Globe className="w-3.5 h-3.5 text-indigo-600 flex-shrink-0" />
                        <span className="truncate">{san}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* TAB 5: REMEDIATION HUB */}
        {activeTab === 'remediation_hub' && (
          <div className="space-y-5">
            <div className="glass-panel p-5 rounded-xl border border-slate-200 space-y-4">
              <div>
                <h3 className="text-base font-bold text-slate-900 flex items-center space-x-2">
                  <Code2 className="w-5 h-5 text-emerald-600" />
                  <span>Remediation Hub: 1-Click Hardening Code Snippets</span>
                </h3>
                <p className="text-xs text-slate-500 mt-0.5">
                  Salin konfigurasi keamanan siap pakai standar 2026 untuk mengamankan server web dan backend aplikasi Anda dari temuan audit.
                </p>
              </div>

              {/* PLATFORM SELECTOR TABS */}
              <div className="flex flex-wrap gap-2 border-b border-slate-200 pb-3">
                {[
                  { id: 'nginx', label: 'Nginx Server' },
                  { id: 'apache', label: 'Apache HTTPD' },
                  { id: 'caddy', label: 'Caddy Server' },
                  { id: 'cloudflare', label: 'Cloudflare Rules' },
                  { id: 'fastapi', label: 'Python FastAPI' },
                  { id: 'express', label: 'Node.js Express' },
                ].map((plat) => (
                  <button
                    key={plat.id}
                    onClick={() => setRemediationPlatform(plat.id)}
                    className={`px-3.5 py-1.5 rounded-lg text-xs font-bold transition ${
                      remediationPlatform === plat.id
                        ? 'bg-emerald-600 text-white shadow-sm'
                        : 'bg-slate-100 text-slate-700 hover:bg-slate-200'
                    }`}
                  >
                    {plat.label}
                  </button>
                ))}
              </div>

              {/* CODE SNIPPET DISPLAY */}
              <div className="relative">
                <div className="flex justify-between items-center bg-slate-900 px-4 py-2.5 rounded-t-xl text-slate-300 text-xs font-mono">
                  <span>Configuration Fix ({remediationPlatform.toUpperCase()})</span>
                  <button
                    onClick={() => copyToClipboard(getRemediationSnippet(remediationPlatform), 'remediation')}
                    className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-emerald-400 font-sans font-bold flex items-center space-x-1.5 transition text-[11px]"
                  >
                    {copiedKey === 'remediation' ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedKey === 'remediation' ? 'Tersalin!' : 'Salin Kode'}</span>
                  </button>
                </div>
                <pre className="p-4 bg-slate-950 text-emerald-400 rounded-b-xl font-mono text-xs overflow-x-auto border border-t-0 border-slate-800 leading-relaxed max-h-[460px] overflow-y-auto">
                  {getRemediationSnippet(remediationPlatform)}
                </pre>
              </div>
            </div>
          </div>
        )}

        {/* TAB 6: EXPORT & COMPLIANCE HUB */}
        {activeTab === 'export_hub' && (
          <div className="space-y-5">
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
              
              {/* PDF EXPORT CARD */}
              <div className="glass-panel p-5 rounded-xl border border-slate-200 space-y-3 flex flex-col justify-between">
                <div>
                  <div className="w-10 h-10 rounded-lg bg-rose-50 border border-rose-200 flex items-center justify-center mb-3">
                    <FileText className="w-5 h-5 text-rose-600" />
                  </div>
                  <h4 className="text-sm font-bold text-slate-900">Executive PDF Audit Report</h4>
                  <p className="text-xs text-slate-500 mt-1">
                    Laporan audit resmi berstandar industri dengan Executive Summary, matriks CVSS v3.1, dan rekomendasi langkah perbaikan.
                  </p>
                </div>
                <a
                  href={activeScanId ? `${API_BASE}/api/v1/reports/${activeScanId}/pdf` : '#'}
                  target="_blank"
                  rel="noreferrer"
                  className={`w-full py-2.5 rounded-lg text-xs font-bold flex items-center justify-center space-x-2 transition ${
                    activeScanId 
                      ? 'bg-rose-600 hover:bg-rose-700 text-white shadow-sm' 
                      : 'bg-slate-100 text-slate-400 cursor-not-allowed'
                  }`}
                >
                  <Download className="w-4 h-4" />
                  <span>Unduh PDF Report</span>
                </a>
              </div>

              {/* SARIF EXPORT CARD */}
              <div className="glass-panel p-5 rounded-xl border border-slate-200 space-y-3 flex flex-col justify-between">
                <div>
                  <div className="w-10 h-10 rounded-lg bg-indigo-50 border border-indigo-200 flex items-center justify-center mb-3">
                    <Shield className="w-5 h-5 text-indigo-600" />
                  </div>
                  <h4 className="text-sm font-bold text-slate-900">SARIF 2.1.0 (DevSecOps)</h4>
                  <p className="text-xs text-slate-500 mt-1">
                    Format standar OASIS SARIF untuk integrasi otomatis ke pipeline GitHub Advanced Security, GitLab CI, dan Azure DevOps.
                  </p>
                </div>
                <a
                  href={activeScanId ? `${API_BASE}/api/v1/reports/${activeScanId}/sarif` : '#'}
                  className={`w-full py-2.5 rounded-lg text-xs font-bold flex items-center justify-center space-x-2 transition ${
                    activeScanId 
                      ? 'bg-indigo-600 hover:bg-indigo-700 text-white shadow-sm' 
                      : 'bg-slate-100 text-slate-400 cursor-not-allowed'
                  }`}
                >
                  <Download className="w-4 h-4" />
                  <span>Unduh SARIF File</span>
                </a>
              </div>

              {/* CSV / JSON CARD */}
              <div className="glass-panel p-5 rounded-xl border border-slate-200 space-y-3 flex flex-col justify-between">
                <div>
                  <div className="w-10 h-10 rounded-lg bg-emerald-50 border border-emerald-200 flex items-center justify-center mb-3">
                    <Database className="w-5 h-5 text-emerald-600" />
                  </div>
                  <h4 className="text-sm font-bold text-slate-900">Spreadsheet CSV & JSON</h4>
                  <p className="text-xs text-slate-500 mt-1">
                    Ekspor dataset mentah seluruh temuan untuk pengolahan spreadsheet Excel atau integrasi API SIEM internal.
                  </p>
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <a
                    href={activeScanId ? `${API_BASE}/api/v1/reports/${activeScanId}/csv` : '#'}
                    className={`py-2 rounded-lg text-xs font-bold flex items-center justify-center space-x-1.5 transition ${
                      activeScanId 
                        ? 'bg-emerald-600 hover:bg-emerald-700 text-white' 
                        : 'bg-slate-100 text-slate-400 cursor-not-allowed'
                    }`}
                  >
                    <span>CSV Excel</span>
                  </a>
                  <a
                    href={activeScanId ? `${API_BASE}/api/v1/reports/${activeScanId}/json` : '#'}
                    className={`py-2 rounded-lg text-xs font-bold flex items-center justify-center space-x-1.5 transition ${
                      activeScanId 
                        ? 'bg-slate-800 hover:bg-slate-900 text-white' 
                        : 'bg-slate-100 text-slate-400 cursor-not-allowed'
                    }`}
                  >
                    <span>JSON Raw</span>
                  </a>
                </div>
              </div>

              {/* SQLITE DATABASE CARD — NEW */}
              <div className="glass-panel p-5 rounded-xl border-2 border-cyan-200 bg-gradient-to-br from-cyan-50 to-sky-50 space-y-3 flex flex-col justify-between relative overflow-hidden">
                {/* Glow accent */}
                <div className="absolute -top-4 -right-4 w-20 h-20 bg-cyan-300 opacity-20 rounded-full blur-2xl pointer-events-none" />
                <div>
                  <div className="flex items-center gap-2 mb-3">
                    <div className="w-10 h-10 rounded-lg bg-cyan-100 border border-cyan-300 flex items-center justify-center">
                      <Database className="w-5 h-5 text-cyan-700" />
                    </div>
                    <span className="text-[10px] font-bold bg-cyan-600 text-white px-2 py-0.5 rounded-full uppercase tracking-wide">Database</span>
                  </div>
                  <h4 className="text-sm font-bold text-slate-900">Download SQLite Database</h4>
                  <p className="text-xs text-slate-600 mt-1">
                    Unduh seluruh data hasil scan sebagai file <strong>.db SQLite</strong> — berisi tabel temuan, severity summary, domain intel, dan metadata ekspor lengkap. Bisa dibuka di DB Browser, DBeaver, atau Python.
                  </p>
                  <ul className="mt-2 space-y-0.5">
                    {['scan_info', 'vulnerabilities', 'domain_intel', 'severity_summary', 'export_metadata'].map(t => (
                      <li key={t} className="text-[10px] text-cyan-700 font-mono flex items-center gap-1">
                        <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 inline-block" />
                        {t}
                      </li>
                    ))}
                  </ul>
                </div>
                <a
                  href={activeScanId ? `${API_BASE}/api/v1/reports/${activeScanId}/sqlite` : '#'}
                  className={`w-full py-2.5 rounded-lg text-xs font-bold flex items-center justify-center space-x-2 transition ${
                    activeScanId 
                      ? 'bg-cyan-600 hover:bg-cyan-700 text-white shadow-md shadow-cyan-200' 
                      : 'bg-slate-100 text-slate-400 cursor-not-allowed'
                  }`}
                >
                  <Download className="w-4 h-4" />
                  <span>Unduh .db SQLite Database</span>
                </a>
              </div>

            </div>

            {/* OWASP TOP 10 COMPLIANCE RADAR */}
            <div className="glass-panel p-5 rounded-xl border border-slate-200 space-y-3">
              <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                Cakupan Standar OWASP Top 10 (2021 & 2026 Ready)
              </h4>
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-5 gap-2.5 pt-1 text-xs">
                {[
                  { code: 'A01:2021', name: 'Broken Access Control' },
                  { code: 'A02:2021', name: 'Cryptographic Failures' },
                  { code: 'A03:2021', name: 'Injection (SQLi, XSS)' },
                  { code: 'A04:2021', name: 'Insecure Design' },
                  { code: 'A05:2021', name: 'Security Misconfiguration' },
                  { code: 'A06:2021', name: 'Vulnerable Components' },
                  { code: 'A07:2021', name: 'Auth Failures' },
                  { code: 'A08:2021', name: 'Software/Data Integrity' },
                  { code: 'A09:2021', name: 'Logging Failures' },
                  { code: 'A10:2021', name: 'Anti-SSRF Protected' },
                ].map((owasp, idx) => (
                  <div key={idx} className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 space-y-1">
                    <span className="font-bold text-indigo-700 text-[10px] block">{owasp.code}</span>
                    <span className="text-slate-800 text-[11px] font-medium">{owasp.name}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* EMAIL VULNERABILITY REPORT SENDER */}
            <div className="glass-panel rounded-2xl border-2 border-emerald-200 bg-gradient-to-br from-emerald-50 to-green-50 overflow-hidden relative">
              <div className="absolute -top-6 -right-6 w-24 h-24 bg-emerald-300 opacity-15 rounded-full blur-2xl pointer-events-none" />
              <div className="px-6 py-4 border-b border-emerald-200 flex items-center space-x-3">
                <div className="w-10 h-10 rounded-xl bg-emerald-100 border border-emerald-300 flex items-center justify-center">
                  <Send className="w-5 h-5 text-emerald-700" />
                </div>
                <div>
                  <h4 className="text-sm font-bold text-slate-900">Kirim Laporan via Email</h4>
                  <p className="text-[11px] text-slate-500">Kirim laporan kerentanan HTML profesional + lampiran PDF ke email target website secara otomatis via Gmail SMTP.</p>
                </div>
              </div>
              <div className="p-6 space-y-4">

                {/* Gmail Sender Config */}
                <div className="p-4 rounded-xl bg-white border border-slate-200 space-y-3">
                  <div className="flex items-center space-x-2 mb-1">
                    <Lock className="w-3.5 h-3.5 text-slate-500" />
                    <span className="text-[11px] font-bold text-slate-600 uppercase tracking-wider">Konfigurasi Gmail Pengirim</span>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <div>
                      <label className="text-[11px] font-semibold text-slate-600 block mb-1">Gmail Pengirim</label>
                      <input
                        type="email"
                        placeholder="auditor@gmail.com"
                        value={emailSender}
                        onChange={(e) => setEmailSender(e.target.value)}
                        className="w-full bg-slate-50 border border-slate-300 rounded-lg px-3 py-2 text-xs font-mono text-slate-800 placeholder-slate-400 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
                      />
                    </div>
                    <div>
                      <label className="text-[11px] font-semibold text-slate-600 block mb-1">Gmail App Password</label>
                      <div className="relative">
                        <input
                          type={showEmailPassword ? 'text' : 'password'}
                          placeholder="xxxx xxxx xxxx xxxx"
                          value={emailAppPassword}
                          onChange={(e) => setEmailAppPassword(e.target.value)}
                          className="w-full bg-slate-50 border border-slate-300 rounded-lg px-3 py-2 pr-10 text-xs font-mono text-slate-800 placeholder-slate-400 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
                        />
                        <button
                          type="button"
                          onClick={() => setShowEmailPassword(!showEmailPassword)}
                          className="absolute right-2.5 top-2 text-slate-400 hover:text-slate-700"
                        >
                          {showEmailPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                        </button>
                      </div>
                    </div>
                  </div>
                  <p className="text-[10px] text-slate-400 leading-relaxed">
                    Gunakan <strong>Gmail App Password</strong> (bukan password login). Aktifkan 2FA di Google Account &rarr; Security &rarr; App Passwords &rarr; Buat app password baru.
                  </p>
                </div>

                {/* Recipient + Message */}
                <div className="space-y-3">
                  <div>
                    <label className="text-[11px] font-semibold text-slate-700 block mb-1">Email Penerima (Website Owner / Security Team)</label>
                    <input
                      type="email"
                      placeholder="security@target-website.com"
                      value={emailRecipient}
                      onChange={(e) => setEmailRecipient(e.target.value)}
                      className="w-full bg-white border border-slate-300 rounded-lg px-3.5 py-2.5 text-xs font-mono text-slate-800 placeholder-slate-400 focus:outline-none focus:border-emerald-500 focus:ring-2 focus:ring-emerald-500/10"
                    />
                  </div>
                  <div>
                    <label className="text-[11px] font-semibold text-slate-700 block mb-1">Pesan Tambahan untuk Penerima (Opsional)</label>
                    <textarea
                      placeholder="Dengan hormat, kami menemukan beberapa kerentanan pada website Anda saat audit keamanan rutin. Berikut laporan lengkapnya..."
                      value={emailCustomMsg}
                      onChange={(e) => setEmailCustomMsg(e.target.value)}
                      rows={3}
                      className="w-full bg-white border border-slate-300 rounded-lg px-3.5 py-2.5 text-xs text-slate-800 placeholder-slate-400 focus:outline-none focus:border-emerald-500 focus:ring-2 focus:ring-emerald-500/10 resize-none"
                    />
                  </div>
                </div>

                {/* Options + Send */}
                <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pt-1">
                  <label className="flex items-center space-x-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={emailAttachPdf}
                      onChange={(e) => setEmailAttachPdf(e.target.checked)}
                      className="w-4 h-4 rounded border-slate-300 text-emerald-600 focus:ring-emerald-500"
                    />
                    <span className="text-xs text-slate-700 font-semibold">Lampirkan PDF Audit Report</span>
                  </label>
                  <button
                    onClick={handleSendEmailReport}
                    disabled={emailSending || !activeScanId}
                    className={`px-6 py-2.5 rounded-xl text-xs font-bold flex items-center space-x-2 transition shadow-md ${
                      emailSending
                        ? 'bg-slate-200 text-slate-400 cursor-not-allowed'
                        : activeScanId
                          ? 'bg-emerald-600 hover:bg-emerald-700 text-white shadow-emerald-200 active:scale-[0.98]'
                          : 'bg-slate-100 text-slate-400 cursor-not-allowed'
                    }`}
                  >
                    {emailSending ? (
                      <>
                        <RefreshCw className="w-4 h-4 animate-spin" />
                        <span>Mengirim...</span>
                      </>
                    ) : (
                      <>
                        <Send className="w-4 h-4" />
                        <span>Kirim Laporan via Email</span>
                      </>
                    )}
                  </button>
                </div>

                {/* Result feedback */}
                {emailResult && (
                  <div className={`p-3.5 rounded-xl border text-xs font-semibold flex items-center space-x-2 ${
                    emailResult.success
                      ? 'bg-emerald-50 border-emerald-200 text-emerald-800'
                      : 'bg-rose-50 border-rose-200 text-rose-800'
                  }`}>
                    {emailResult.success ? <CheckCircle className="w-4 h-4 text-emerald-600 flex-shrink-0" /> : <AlertTriangle className="w-4 h-4 text-rose-600 flex-shrink-0" />}
                    <span>{emailResult.message}</span>
                  </div>
                )}

                {!activeScanId && (
                  <div className="p-3 rounded-xl bg-amber-50 border border-amber-200 text-xs text-amber-800 flex items-center space-x-2">
                    <AlertTriangle className="w-4 h-4 text-amber-500 flex-shrink-0" />
                    <span>Jalankan scan terlebih dahulu sebelum mengirim laporan email.</span>
                  </div>
                )}
              </div>
            </div>

          </div>
        )}

        {/* TAB 7: COMPLIANCE STANDARDS HUB */}
        {activeTab === 'compliance_hub' && (() => {
          // Compute scorecard from findings client-side
          const crit = findings.filter(f => (f.severity||'').toUpperCase() === 'CRITICAL').length;
          const high = findings.filter(f => (f.severity||'').toUpperCase() === 'HIGH').length;
          const med  = findings.filter(f => (f.severity||'').toUpperCase() === 'MEDIUM').length;
          const low  = findings.filter(f => (f.severity||'').toUpperCase() === 'LOW').length;

          let score = Math.max(0, Math.min(100, 100 - crit*28 - high*14 - med*6 - low*2));
          let grade = 'F', gradeColor = '#ef4444', riskLabel = 'Kritis';
          if (score >= 95 && crit === 0 && high === 0) { grade = 'A+'; gradeColor = '#10b981'; riskLabel = 'Sangat Rendah (Hardened)'; }
          else if (score >= 85 && crit === 0) { grade = 'A'; gradeColor = '#22c55e'; riskLabel = 'Rendah (Secure)'; }
          else if (score >= 70 && crit === 0) { grade = 'B'; gradeColor = '#0ea5e9'; riskLabel = 'Moderat (Acceptable)'; }
          else if (score >= 55) { grade = 'C'; gradeColor = '#f59e0b'; riskLabel = 'Perhatian (Elevated Risk)'; }
          else if (score >= 40) { grade = 'D'; gradeColor = '#f97316'; riskLabel = 'Tinggi (High Vulnerability)'; }

          const titles = findings.map(f => ((f.title||'')+' '+(f.owasp_category||'')).toLowerCase());
          const has = (kws) => kws.some(kw => titles.some(t => t.includes(kw)));

          const owaspItems = [
            { id:'A01', name:'Broken Access Control', passed: !has(['access control','unauthorized','idor']), impact:'Tinggi' },
            { id:'A02', name:'Cryptographic Failures', passed: !has(['crypto','tls','ssl','hsts','cipher']), impact:'Kritis' },
            { id:'A03', name:'Injection (SQLi, XSS)', passed: !has(['injection','xss','sqli']), impact:'Kritis' },
            { id:'A04', name:'Insecure Design', passed: !has(['insecure design','rate limit']), impact:'Sedang' },
            { id:'A05', name:'Security Misconfiguration', passed: !has(['misconfiguration','header','cors','csp']), impact:'Tinggi' },
            { id:'A06', name:'Vulnerable Components', passed: !has(['vulnerable','outdated','cve']), impact:'Tinggi' },
            { id:'A07', name:'Auth & Identification Failures', passed: !has(['auth','session','cookie','token']), impact:'Tinggi' },
            { id:'A08', name:'Software & Data Integrity', passed: !has(['integrity','sri']), impact:'Sedang' },
            { id:'A09', name:'Logging & Monitoring', passed: !has(['logging','monitoring']), impact:'Sedang' },
            { id:'A10', name:'SSRF Protection', passed: !has(['ssrf','request forgery']), impact:'Kritis' },
          ];
          const owaspPass = owaspItems.filter(i => i.passed).length;

          const isoItems = [
            { ctrl:'A.8.20', name:'Network Security & Boundary', passed: !has(['cors','port','waf']), domain:'Technological Controls' },
            { ctrl:'A.8.24', name:'Cryptographic Protection', passed: !has(['tls','ssl','hsts','certificate']), domain:'Information Security' },
            { ctrl:'A.8.26', name:'Application Security Requirements', passed: !has(['injection','xss','sqli']), domain:'Secure Development' },
            { ctrl:'A.8.28', name:'Secure Coding & Sanitization', passed: !has(['xss','sqli','injection']), domain:'Dev Lifecycle' },
            { ctrl:'A.8.31', name:'Separation & Secrets Control', passed: !has(['.env','.git','secret','backup','credential']), domain:'Operations Security' },
          ];
          const isoPass = isoItems.filter(i => i.passed).length;

          const pciItems = [
            { req:'Req 4.1', name:'Strong Cryptography in Transit', passed: !has(['tls','ssl','hsts','certificate']), std:'Data in Transit' },
            { req:'Req 6.4.1', name:'Protection vs Web Attacks', passed: !has(['xss','sqli','injection','csp']), std:'Public Applications' },
            { req:'Req 6.5.8', name:'Sensitive Data Exposure', passed: !has(['.env','.git','secret','backup']), std:'Sensitive Assets' },
            { req:'Req 11.3.1', name:'External Vulnerability Assessment', passed: crit === 0 && high === 0, std:'Vulnerability Testing' },
          ];
          const pciPass = pciItems.filter(i => i.passed).length;

          const nistItems = [
            { ctrl:'SC-8', name:'Transmission Confidentiality & Integrity', passed: !has(['tls','ssl','hsts']), family:'System & Communications' },
            { ctrl:'SC-13', name:'Cryptographic Protection', passed: !has(['cipher','tls 1.0','certificate']), family:'System & Communications' },
            { ctrl:'SI-10', name:'Information Input Validation', passed: !has(['xss','sqli','injection']), family:'System & Info Integrity' },
            { ctrl:'AC-3', name:'Access Enforcement', passed: !has(['access control','cors']), family:'Access Control' },
          ];
          const nistPass = nistItems.filter(i => i.passed).length;

          const ProgressBar = ({ val, color }) => (
            <div className="w-full h-2 bg-slate-100 rounded-full overflow-hidden border border-slate-200">
              <div className="h-full rounded-full transition-all duration-500" style={{ width: `${val}%`, backgroundColor: color }} />
            </div>
          );

          const StatusBadge = ({ passed }) => passed
            ? <span className="inline-flex items-center gap-1 text-[10px] font-bold text-emerald-700 bg-emerald-50 border border-emerald-200 rounded-full px-2 py-0.5"><CheckCircle className="w-3 h-3" />PASS</span>
            : <span className="inline-flex items-center gap-1 text-[10px] font-bold text-rose-700 bg-rose-50 border border-rose-200 rounded-full px-2 py-0.5"><AlertTriangle className="w-3 h-3" />FAIL</span>;

          return (
            <div className="space-y-6">
              {/* SCORECARD HEADER */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                {/* Grade Card */}
                <div className="glass-panel p-6 rounded-2xl border-2 flex flex-col items-center justify-center text-center space-y-2" style={{ borderColor: gradeColor + '60' }}>
                  <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Security Posture Grade</div>
                  <div className="text-8xl font-black leading-none" style={{ color: gradeColor }}>{grade}</div>
                  <div className="text-xs font-semibold text-slate-600 px-3 py-1 rounded-full bg-slate-100 border border-slate-200">{riskLabel}</div>
                  <div className="text-sm font-mono font-bold text-slate-700">{score.toFixed(1)} / 100.0</div>
                  {findings.length === 0 && (
                    <div className="text-[11px] text-slate-400 italic mt-1">Jalankan scan terlebih dahulu untuk mendapatkan skor nyata</div>
                  )}
                </div>

                {/* Pillar Radar */}
                <div className="glass-panel p-5 rounded-2xl border border-slate-200 space-y-3 col-span-2">
                  <div className="flex items-center space-x-2 mb-1">
                    <BarChart2 className="w-4 h-4 text-violet-600" />
                    <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider">4-Pillar Security Ratings</h4>
                  </div>
                  {[
                    { label: 'Cryptography & TLS 1.3', val: Math.max(20, 100 - (has(['ssl','tls','hsts','cipher']) ? 40 : 0)), color: '#6366f1' },
                    { label: 'Web Hardening & Headers', val: Math.max(20, 100 - (has(['header','csp','cors']) ? 35 : 0) - low*5), color: '#0ea5e9' },
                    { label: 'App Integrity & Anti-Injection', val: Math.max(10, 100 - (has(['injection','xss','sqli']) ? 50 : 0) - med*10), color: '#f59e0b' },
                    { label: 'Perimeter & Data Protection', val: Math.max(10, 100 - (has(['.env','.git','secret','backup']) ? 60 : 0) - crit*20), color: '#10b981' },
                  ].map((pillar, idx) => (
                    <div key={idx} className="space-y-1">
                      <div className="flex justify-between text-xs text-slate-600">
                        <span className="font-semibold">{pillar.label}</span>
                        <span className="font-mono font-bold">{pillar.val}%</span>
                      </div>
                      <ProgressBar val={pillar.val} color={pillar.color} />
                    </div>
                  ))}
                </div>
              </div>

              {/* FINDINGS SUMMARY ROW */}
              <div className="grid grid-cols-5 gap-3">
                {[
                  { label: 'Critical', count: crit, color: 'text-rose-700', bg: 'bg-rose-50 border-rose-200' },
                  { label: 'High', count: high, color: 'text-amber-700', bg: 'bg-amber-50 border-amber-200' },
                  { label: 'Medium', count: med, color: 'text-yellow-700', bg: 'bg-yellow-50 border-yellow-200' },
                  { label: 'Low', count: low, color: 'text-sky-700', bg: 'bg-sky-50 border-sky-200' },
                  { label: 'Total', count: findings.length, color: 'text-slate-800', bg: 'bg-slate-50 border-slate-200' },
                ].map((s, idx) => (
                  <div key={idx} className={`p-4 rounded-xl border text-center ${s.bg}`}>
                    <div className={`text-2xl font-black ${s.color}`}>{s.count}</div>
                    <div className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mt-0.5">{s.label}</div>
                  </div>
                ))}
              </div>

              {/* OWASP TOP 10 */}
              <div className="glass-panel rounded-xl border border-slate-200 overflow-hidden">
                <div className="bg-slate-50 px-5 py-3 border-b border-slate-200 flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <Shield className="w-4 h-4 text-indigo-600" />
                    <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider">1. OWASP Top 10 (2021 & 2026 Ready)</h4>
                  </div>
                  <span className={`text-xs font-bold px-2.5 py-1 rounded-full ${owaspPass === 10 ? 'bg-emerald-100 text-emerald-700' : owaspPass >= 7 ? 'bg-amber-100 text-amber-700' : 'bg-rose-100 text-rose-700'}`}>
                    {owaspPass}/10 Controls Passed — {Math.round(owaspPass/10*100)}%
                  </span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-5 gap-0 divide-x divide-y divide-slate-100">
                  {owaspItems.map((item, idx) => (
                    <div key={idx} className="p-4 space-y-2">
                      <div className="flex items-start justify-between gap-1">
                        <div>
                          <div className="text-[10px] font-bold text-indigo-600">{item.id}</div>
                          <div className="text-[11px] font-semibold text-slate-800 mt-0.5 leading-tight">{item.name}</div>
                          <div className={`text-[9px] font-semibold mt-1 ${item.impact === 'Kritis' ? 'text-rose-500' : item.impact === 'Tinggi' ? 'text-amber-500' : 'text-slate-400'}`}>
                            Dampak: {item.impact}
                          </div>
                        </div>
                      </div>
                      <StatusBadge passed={item.passed} />
                    </div>
                  ))}
                </div>
              </div>

              {/* ISO / PCI / NIST ROW */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {/* ISO 27001 */}
                <div className="glass-panel rounded-xl border border-slate-200 overflow-hidden">
                  <div className="bg-slate-50 px-4 py-2.5 border-b border-slate-200 flex items-center justify-between">
                    <div className="flex items-center space-x-1.5">
                      <Gavel className="w-3.5 h-3.5 text-blue-600" />
                      <span className="text-[11px] font-bold text-slate-700">ISO/IEC 27001:2022</span>
                    </div>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${isoPass === isoItems.length ? 'bg-emerald-100 text-emerald-700' : 'bg-amber-100 text-amber-700'}`}>
                      {isoPass}/{isoItems.length} PASS
                    </span>
                  </div>
                  <div className="divide-y divide-slate-100">
                    {isoItems.map((item, idx) => (
                      <div key={idx} className="px-4 py-3 flex items-center justify-between gap-2">
                        <div>
                          <div className="text-[10px] font-bold text-indigo-600 font-mono">{item.ctrl}</div>
                          <div className="text-[11px] text-slate-700 font-medium">{item.name}</div>
                          <div className="text-[9px] text-slate-400 mt-0.5">{item.domain}</div>
                        </div>
                        <StatusBadge passed={item.passed} />
                      </div>
                    ))}
                  </div>
                </div>

                {/* PCI-DSS */}
                <div className="glass-panel rounded-xl border border-slate-200 overflow-hidden">
                  <div className="bg-slate-50 px-4 py-2.5 border-b border-slate-200 flex items-center justify-between">
                    <div className="flex items-center space-x-1.5">
                      <Lock className="w-3.5 h-3.5 text-rose-600" />
                      <span className="text-[11px] font-bold text-slate-700">PCI-DSS v4.0</span>
                    </div>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${pciPass === pciItems.length ? 'bg-emerald-100 text-emerald-700' : 'bg-rose-100 text-rose-700'}`}>
                      {pciPass}/{pciItems.length} PASS
                    </span>
                  </div>
                  <div className="divide-y divide-slate-100">
                    {pciItems.map((item, idx) => (
                      <div key={idx} className="px-4 py-3 flex items-center justify-between gap-2">
                        <div>
                          <div className="text-[10px] font-bold text-indigo-600 font-mono">{item.req}</div>
                          <div className="text-[11px] text-slate-700 font-medium">{item.name}</div>
                          <div className="text-[9px] text-slate-400 mt-0.5">{item.std}</div>
                        </div>
                        <StatusBadge passed={item.passed} />
                      </div>
                    ))}
                  </div>
                </div>

                {/* NIST SP 800-53 */}
                <div className="glass-panel rounded-xl border border-slate-200 overflow-hidden">
                  <div className="bg-slate-50 px-4 py-2.5 border-b border-slate-200 flex items-center justify-between">
                    <div className="flex items-center space-x-1.5">
                      <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />
                      <span className="text-[11px] font-bold text-slate-700">NIST SP 800-53 Rev 5</span>
                    </div>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${nistPass === nistItems.length ? 'bg-emerald-100 text-emerald-700' : 'bg-amber-100 text-amber-700'}`}>
                      {nistPass}/{nistItems.length} PASS
                    </span>
                  </div>
                  <div className="divide-y divide-slate-100">
                    {nistItems.map((item, idx) => (
                      <div key={idx} className="px-4 py-3 flex items-center justify-between gap-2">
                        <div>
                          <div className="text-[10px] font-bold text-indigo-600 font-mono">{item.ctrl}</div>
                          <div className="text-[11px] text-slate-700 font-medium">{item.name}</div>
                          <div className="text-[9px] text-slate-400 mt-0.5">{item.family}</div>
                        </div>
                        <StatusBadge passed={item.passed} />
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* ACTION FOOTER */}
              <div className="glass-panel p-5 rounded-xl border border-violet-200 bg-gradient-to-r from-violet-50 to-indigo-50 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
                <div>
                  <p className="text-xs font-bold text-slate-800">Ingin bukti audit per kontrol yang lebih detail?</p>
                  <p className="text-[11px] text-slate-500 mt-0.5">Gunakan terminal interaktif untuk menjalankan: <code className="font-mono text-violet-700">scorecard</code>, <code className="font-mono text-violet-700">compliance</code>, atau <code className="font-mono text-violet-700">emailsec</code> secara live terhadap target.</p>
                </div>
                <button
                  onClick={() => { setActiveTab('live_terminal'); }}
                  className="flex-shrink-0 px-4 py-2 rounded-xl bg-violet-600 hover:bg-violet-700 text-white text-xs font-bold flex items-center space-x-2 transition shadow-md shadow-violet-200"
                >
                  <Terminal className="w-3.5 h-3.5" />
                  <span>Buka Live Terminal</span>
                </button>
              </div>
            </div>
          );
        })()}

        {/* TAB 8: UJI KETAHANAN INPUT & INTEGRITAS BASIS DATA */}
        {activeTab === 'input_db_integrity' && (
          <div className="space-y-6">
            
            {/* TOP OVERVIEW CARD & SUB-NAVIGATION */}
            <div className="glass-panel p-6 rounded-2xl border border-slate-200 shadow-sm space-y-4">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                  <div className="flex items-center space-x-2">
                    <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold tracking-wider uppercase bg-rose-100 text-rose-700 border border-rose-200">
                      OWASP A03:2021 • CWE-89 & CWE-250
                    </span>
                    <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold tracking-wider uppercase bg-emerald-100 text-emerald-700 border border-emerald-200">
                      Isolated Dev Lab Mode
                    </span>
                  </div>
                  <h2 className="text-lg font-black text-slate-900 mt-2 flex items-center space-x-2">
                    <Database className="w-5 h-5 text-rose-600" />
                    <span>Laboratorium Uji Ketahanan Masukan & Integritas Basis Data</span>
                  </h2>
                  <p className="text-xs text-slate-500 mt-1 max-w-3xl">
                    Uji ketahanan kotak pencarian dan kolom isian data terhadap manipulasi karakter khusus & sintaksis SQL, 
                    serta lakukan audit batas hak istimewa akun database (Principle of Least Privilege & Stacked Query) langsung pada target.
                  </p>
                </div>

                {/* SUB-TABS SELECTOR */}
                <div className="flex items-center bg-slate-100 p-1 rounded-xl border border-slate-200 self-start md:self-auto">
                  <button
                    onClick={() => setActiveSubTabInputDB('input_resilience')}
                    className={`px-3.5 py-1.5 rounded-lg text-xs font-bold transition flex items-center space-x-1.5 ${
                      activeSubTabInputDB === 'input_resilience'
                        ? 'bg-white text-rose-700 shadow-sm'
                        : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    <Search className="w-3.5 h-3.5" />
                    <span>Uji Kolom Masukan & Search</span>
                  </button>
                  <button
                    onClick={() => setActiveSubTabInputDB('db_boundary')}
                    className={`px-3.5 py-1.5 rounded-lg text-xs font-bold transition flex items-center space-x-1.5 ${
                      activeSubTabInputDB === 'db_boundary'
                        ? 'bg-white text-rose-700 shadow-sm'
                        : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    <ShieldAlert className="w-3.5 h-3.5" />
                    <span>Audit Batas Hak Database</span>
                  </button>
                </div>
              </div>
            </div>

            {/* SUB-TAB 1: PENGUJIAN KETAHANAN KOLOM MASUKAN & SEARCH */}
            {activeSubTabInputDB === 'input_resilience' && (
              <div className="space-y-6">
                
                {/* 2-COLUMN LAB CONTROLLER & TELEMETRY */}
                <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                  
                  {/* LEFT: PROBE CONFIGURATION PANEL */}
                  <div className="lg:col-span-6 glass-panel p-5 rounded-2xl border border-slate-200 space-y-4 shadow-sm">
                    <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                      <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider flex items-center space-x-2">
                        <Sliders className="w-4 h-4 text-rose-600" />
                        <span>Konfigurasi Uji Kolom Masukan</span>
                      </h3>
                      <button
                        onClick={() => {
                          setInputTestUrl(targetUrl);
                          setInputTestParam('q');
                          setInputTestProbe("'%27--");
                        }}
                        className="text-[11px] text-rose-600 hover:text-rose-800 font-semibold"
                      >
                        Reset ke Target Utama
                      </button>
                    </div>

                    {/* Target URL */}
                    <div className="space-y-1">
                      <label className="text-xs font-semibold text-slate-700">Target Endpoint URL</label>
                      <input
                        type="text"
                        value={inputTestUrl || targetUrl}
                        onChange={(e) => setInputTestUrl(e.target.value)}
                        placeholder="https://example.com/search"
                        className="w-full px-3.5 py-2 rounded-xl border border-slate-200 text-xs font-mono text-slate-800 bg-white focus:outline-none focus:ring-2 focus:ring-rose-500"
                      />
                    </div>

                    {/* Parameter & Method */}
                    <div className="grid grid-cols-3 gap-3">
                      <div className="col-span-2 space-y-1">
                        <label className="text-xs font-semibold text-slate-700">Nama Kolom / Parameter</label>
                        <input
                          type="text"
                          value={inputTestParam}
                          onChange={(e) => setInputTestParam(e.target.value)}
                          placeholder="q, search, keyword, id, dll."
                          className="w-full px-3.5 py-2 rounded-xl border border-slate-200 text-xs font-mono text-slate-800 bg-white focus:outline-none focus:ring-2 focus:ring-rose-500"
                        />
                      </div>
                      <div className="space-y-1">
                        <label className="text-xs font-semibold text-slate-700">Metode</label>
                        <select
                          value={inputTestMethod}
                          onChange={(e) => setInputTestMethod(e.target.value)}
                          className="w-full px-3 py-2 rounded-xl border border-slate-200 text-xs font-bold text-slate-800 bg-white focus:outline-none focus:ring-2 focus:ring-rose-500"
                        >
                          <option value="GET">GET</option>
                          <option value="POST">POST</option>
                        </select>
                      </div>
                    </div>

                    {/* Quick Parameter Suggestion Chips */}
                    <div className="space-y-1.5">
                      <span className="text-[11px] font-medium text-slate-500">Pilihan Cepat Parameter Kolom:</span>
                      <div className="flex flex-wrap gap-1.5">
                        {['q', 'search', 'keyword', 'query', 's', 'cari', 'id', 'category'].map((p) => (
                          <button
                            key={p}
                            onClick={() => setInputTestParam(p)}
                            className={`px-2 py-0.5 rounded-lg text-[11px] font-mono border transition ${
                              inputTestParam === p
                                ? 'bg-rose-50 border-rose-300 text-rose-700 font-bold'
                                : 'bg-slate-50 border-slate-200 text-slate-600 hover:bg-slate-100'
                            }`}
                          >
                            {p}
                          </button>
                        ))}
                      </div>
                    </div>

                    {/* Preset Payloads */}
                    <div className="space-y-1.5">
                      <span className="text-[11px] font-medium text-slate-500">Pilih Payload Uji / Karakter Khusus:</span>
                      <div className="grid grid-cols-2 gap-2">
                        {[
                          { label: "Kutipan Tunggal (')", probe: "'", desc: "Uji escape karakter" },
                          { label: "Kutipan Ganda (\")", probe: "\" ` \\", desc: "Identifier break" },
                          { label: "Pemutus SQL ('--)", probe: "'--", desc: "Line comment break" },
                          { label: "Wildcard Pencarian", probe: "%' OR '1'='1", desc: "Like clause bypass" },
                          { label: "Tautologi Boolean", probe: "1' OR '1'='1' -- ", desc: "Logika WHERE true" },
                          { label: "Null Byte (%00)", probe: "%00' OR 1=1", desc: "Encoding bypass" },
                        ].map((item, idx) => (
                          <button
                            key={idx}
                            onClick={() => setInputTestProbe(item.probe)}
                            className={`p-2.5 rounded-xl border text-left transition flex flex-col justify-between ${
                              inputTestProbe === item.probe
                                ? 'bg-rose-50 border-rose-300 ring-1 ring-rose-400'
                                : 'bg-white border-slate-200 hover:border-slate-300'
                            }`}
                          >
                            <span className="text-xs font-bold text-slate-800">{item.label}</span>
                            <span className="font-mono text-[10px] text-rose-600 truncate mt-0.5">{item.probe}</span>
                            <span className="text-[10px] text-slate-400 mt-1">{item.desc}</span>
                          </button>
                        ))}
                      </div>
                    </div>

                    {/* Custom Probe Field */}
                    <div className="space-y-1">
                      <label className="text-xs font-semibold text-slate-700">Probe String Kustom</label>
                      <input
                        type="text"
                        value={inputTestProbe}
                        onChange={(e) => setInputTestProbe(e.target.value)}
                        className="w-full px-3.5 py-2 rounded-xl border border-slate-200 text-xs font-mono text-slate-800 bg-white focus:outline-none focus:ring-2 focus:ring-rose-500"
                      />
                    </div>

                    {/* Action Button */}
                    <button
                      onClick={() => handleRunInputTest()}
                      disabled={isInputTesting}
                      className="w-full py-2.5 rounded-xl bg-gradient-to-r from-rose-600 to-red-600 hover:from-rose-700 hover:to-red-700 text-white text-xs font-bold shadow-md shadow-rose-200 flex items-center justify-center space-x-2 transition disabled:opacity-50"
                    >
                      {isInputTesting ? (
                        <>
                          <RefreshCw className="w-4 h-4 animate-spin" />
                          <span>Mengirim Probe Masukan Live...</span>
                        </>
                      ) : (
                        <>
                          <Play className="w-4 h-4 fill-white" />
                          <span>Jalankan Pengujian Masukan Live</span>
                        </>
                      )}
                    </button>
                  </div>

                  {/* RIGHT: LIVE TELEMETRY & VERDICT PANEL */}
                  <div className="lg:col-span-6 space-y-4">
                    
                    {/* RESULT CARD */}
                    {inputTestResult ? (
                      <div className="glass-panel p-5 rounded-2xl border border-slate-200 shadow-sm space-y-4 animate-in fade-in duration-200">
                        <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                          <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider flex items-center space-x-2">
                            <Activity className="w-4 h-4 text-rose-600" />
                            <span>Hasil Telemetri Live Pengujian</span>
                          </h3>
                          <span className="text-[11px] text-slate-400 font-mono">{inputTestResult.timestamp}</span>
                        </div>

                        {/* STATUS HERO BANNER */}
                        <div className={`p-4 rounded-xl border ${
                          inputTestResult.db_error_found
                            ? 'bg-red-50 border-red-200 text-red-800'
                            : inputTestResult.is_blocked_by_waf
                            ? 'bg-indigo-50 border-indigo-200 text-indigo-800'
                            : inputTestResult.status_code === 400
                            ? 'bg-emerald-50 border-emerald-200 text-emerald-800'
                            : !inputTestResult.is_reflected_raw
                            ? 'bg-emerald-50 border-emerald-200 text-emerald-800'
                            : 'bg-blue-50 border-blue-200 text-blue-800'
                        }`}>
                          <div className="flex items-start space-x-3">
                            {inputTestResult.db_error_found ? (
                              <AlertOctagon className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
                            ) : inputTestResult.is_blocked_by_waf ? (
                              <ShieldCheck className="w-5 h-5 text-indigo-600 flex-shrink-0 mt-0.5" />
                            ) : (
                              <CheckCircle2 className="w-5 h-5 text-emerald-600 flex-shrink-0 mt-0.5" />
                            )}
                            <div>
                              <p className="text-xs font-black">
                                Status: {inputTestResult.resilience_status}
                              </p>
                              {inputTestResult.db_error_found && (
                                <p className="text-[11px] text-red-700 mt-1 font-mono">
                                  Terdeteksi Signature Error: {inputTestResult.matched_engine} ('{inputTestResult.matched_pattern}')
                                </p>
                              )}
                              <p className="text-[11px] opacity-80 mt-1">
                                Target: <span className="font-mono">{inputTestResult.target_url}</span> (Parameter: <span className="font-bold font-mono">{inputTestResult.param}</span>)
                              </p>
                            </div>
                          </div>
                        </div>

                        {/* METRICS GRID */}
                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 text-center">
                          <div className="p-3 rounded-xl bg-slate-50 border border-slate-100">
                            <span className="text-[10px] text-slate-400 uppercase font-bold block">HTTP Status</span>
                            <span className="text-sm font-black text-slate-800 font-mono mt-0.5 block">
                              {inputTestResult.status_code}
                            </span>
                          </div>
                          <div className="p-3 rounded-xl bg-slate-50 border border-slate-100">
                            <span className="text-[10px] text-slate-400 uppercase font-bold block">Response Size</span>
                            <span className="text-sm font-black text-slate-800 font-mono mt-0.5 block">
                              {inputTestResult.response_length} B
                            </span>
                          </div>
                          <div className="p-3 rounded-xl bg-slate-50 border border-slate-100">
                            <span className="text-[10px] text-slate-400 uppercase font-bold block">Refleksi Input</span>
                            <span className={`text-xs font-bold mt-1 block ${
                              inputTestResult.is_reflected_raw ? 'text-amber-600' : 'text-emerald-600'
                            }`}>
                              {inputTestResult.is_reflected_raw ? 'Mentah (Raw)' : 'Tersanitasi'}
                            </span>
                          </div>
                          <div className="p-3 rounded-xl bg-slate-50 border border-slate-100">
                            <span className="text-[10px] text-slate-400 uppercase font-bold block">Proteksi WAF</span>
                            <span className={`text-xs font-bold mt-1 block ${
                              inputTestResult.is_blocked_by_waf ? 'text-indigo-600' : 'text-slate-500'
                            }`}>
                              {inputTestResult.is_blocked_by_waf ? 'Terblokir' : 'Lolos'}
                            </span>
                          </div>
                        </div>

                        {/* REMEDIATION GUIDELINE */}
                        <div className="p-4 rounded-xl bg-slate-900 text-slate-200 font-mono text-xs space-y-2 border border-slate-800">
                          <div className="flex items-center justify-between text-slate-400 text-[11px] pb-1 border-b border-slate-800">
                            <span className="font-bold flex items-center space-x-1.5 text-emerald-400">
                              <Shield className="w-3.5 h-3.5" />
                              <span>Rekomendasi Sanitasi & Prepared Statements</span>
                            </span>
                            <span>OWASP A03</span>
                          </div>
                          <p className="text-[11px] text-slate-300 leading-relaxed font-sans">
                            {inputTestResult.db_error_found
                              ? "⚠️ Aplikasi merespon dengan pesan error SQL internal. Segera ganti query dinamis/string concatenation dengan Parameterized Queries (Prepared Statements) atau ORM, serta nonaktifkan verbose error reporting di production."
                              : "✅ Kolom masukan menangani probe karakter dengan aman. Pertahankan penggunaan parameterisasi pada seluruh lapis query dan terapkan allowlist validation pada kotak pencarian."}
                          </p>
                        </div>
                      </div>
                    ) : (
                      <div className="glass-panel p-8 rounded-2xl border border-slate-200 text-center space-y-3 shadow-sm">
                        <div className="w-12 h-12 rounded-2xl bg-rose-50 text-rose-600 mx-auto flex items-center justify-center">
                          <Search className="w-6 h-6" />
                        </div>
                        <h4 className="text-sm font-bold text-slate-800">Siap Menjalankan Pengujian</h4>
                        <p className="text-xs text-slate-500 max-w-sm mx-auto">
                          Pilih atau ketik parameter masukan di sebelah kiri dan klik tombol untuk mengirim probe real-time langsung ke target domain.
                        </p>
                      </div>
                    )}

                    {/* RECENT SESSION TEST HISTORY */}
                    {inputTestHistory.length > 0 && (
                      <div className="glass-panel p-4 rounded-2xl border border-slate-200 space-y-2.5">
                        <span className="text-xs font-bold text-slate-700 uppercase tracking-wider block">
                          Riwayat Pengujian Sesi Ini ({inputTestHistory.length})
                        </span>
                        <div className="space-y-1.5 max-h-48 overflow-y-auto">
                          {inputTestHistory.map((item, idx) => (
                            <div key={idx} className="p-2.5 rounded-xl bg-white border border-slate-200 text-xs flex items-center justify-between font-mono">
                              <div className="flex items-center space-x-2 truncate">
                                <span className={`w-2 h-2 rounded-full ${item.db_error_found ? 'bg-red-500' : 'bg-emerald-500'}`} />
                                <span className="font-bold text-slate-800">[{item.param}]</span>
                                <span className="text-slate-500 truncate text-[11px]">{item.probe}</span>
                              </div>
                              <div className="flex items-center space-x-2 flex-shrink-0 text-[11px]">
                                <span className="text-slate-400">HTTP {item.status_code}</span>
                                <span className={`font-bold ${item.db_error_found ? 'text-red-600' : 'text-emerald-600'}`}>
                                  {item.db_error_found ? 'Rentan' : 'Aman'}
                                </span>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                {/* BOTTOM: DISCOVERED FORMS FROM CRAWLER */}
                <div className="glass-panel p-5 rounded-2xl border border-slate-200 space-y-3 shadow-sm">
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider flex items-center space-x-2">
                        <FileCode className="w-4 h-4 text-indigo-600" />
                        <span>Formulir HTML & Kolom Pencarian Ditemukan oleh Crawler</span>
                      </h4>
                      <p className="text-[11px] text-slate-500 mt-0.5">
                        Klik 'Uji Kolom Ini' untuk menguji kolom masukan secara instan dengan parameterisasi lengkap.
                      </p>
                    </div>
                    <span className="text-xs font-bold text-indigo-600 bg-indigo-50 px-2.5 py-1 rounded-full border border-indigo-200">
                      {liveAssetData?.discovered_forms?.length || 0} Formulir
                    </span>
                  </div>

                  {(liveAssetData?.discovered_forms || []).length === 0 ? (
                    <div className="p-6 rounded-xl bg-slate-50 border border-slate-200 text-center text-xs text-slate-400 italic">
                      Belum ada form yang ditemukan crawler. Jalankan audit pemindaian 'Active Profile' atau ketik URL manual di form atas.
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 max-h-72 overflow-y-auto">
                      {liveAssetData.discovered_forms.map((form, idx) => (
                        <div key={idx} className="p-3.5 rounded-xl bg-white border border-slate-200 space-y-2 text-xs">
                          <div className="flex items-center justify-between">
                            <span className="font-bold font-mono text-indigo-600">[{form.method}]</span>
                            <span className="text-[11px] font-mono text-slate-500 truncate max-w-xs">{form.url}</span>
                          </div>
                          <div className="text-[11px] text-slate-600">
                            Parameter Input: <span className="text-slate-900 font-semibold">{form.inputs?.join(', ') || 'None'}</span>
                          </div>
                          <div className="flex items-center justify-end space-x-2 pt-1">
                            {form.inputs && form.inputs.length > 0 && (
                              <button
                                onClick={() => {
                                  setInputTestUrl(form.url);
                                  setInputTestParam(form.inputs[0]);
                                  setInputTestMethod(form.method || 'GET');
                                  handleRunInputTest(form.url, form.inputs[0], "'--");
                                }}
                                className="px-3 py-1 rounded-lg bg-rose-50 hover:bg-rose-100 text-rose-700 border border-rose-200 text-xs font-bold transition flex items-center space-x-1"
                              >
                                <span>Uji Kolom Ini</span>
                                <ChevronRight className="w-3 h-3" />
                              </button>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* SUB-TAB 2: AUDIT BATAS HAK BASIS DATA & LEAST PRIVILEGE */}
            {activeSubTabInputDB === 'db_boundary' && (
              <div className="space-y-6">
                
                {/* ISOLATED ENVIRONMENT SAFETY BANNER */}
                <div className="p-5 rounded-2xl bg-gradient-to-r from-amber-500/10 via-rose-500/10 to-indigo-500/10 border border-amber-300/60 shadow-sm flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
                  <div className="flex items-start space-x-3.5">
                    <div className="w-10 h-10 rounded-xl bg-amber-500 text-white flex items-center justify-center flex-shrink-0 shadow-md shadow-amber-200">
                      <Lock className="w-5 h-5" />
                    </div>
                    <div>
                      <div className="flex items-center space-x-2">
                        <h3 className="text-sm font-black text-slate-900">
                          Audit Hak Istimewa Akun Basis Data (Principle of Least Privilege)
                        </h3>
                        <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-amber-100 text-amber-800 border border-amber-300">
                          Least Privilege Audit
                        </span>
                      </div>
                      <p className="text-xs text-slate-600 mt-1 max-w-3xl leading-relaxed">
                        Pengujian instruksi manipulasi struktur data (DDL) dirancang khusus untuk memverifikasi penegakan 
                        <strong> Prinsip Hak Akses Terkecil (Principle of Least Privilege)</strong> dan penolakan <strong>Multi-Statement Execution</strong> langsung pada backend basis data target.
                      </p>
                    </div>
                  </div>

                  <div className="flex-shrink-0 bg-white/80 backdrop-blur px-3 py-1.5 rounded-xl border border-amber-200 text-center">
                    <span className="text-[10px] font-bold text-slate-400 block uppercase">Standar</span>
                    <span className="text-xs font-black text-slate-800 block">CWE-250 / CWE-272</span>
                  </div>
                </div>

                {/* 2-COLUMN SIMULATOR & TELEMETRY */}
                <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                  
                  {/* LEFT: DDL SIMULATION LAUNCHER */}
                  <div className="lg:col-span-6 glass-panel p-5 rounded-2xl border border-slate-200 space-y-4 shadow-sm">
                    <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                      <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider flex items-center space-x-2">
                        <Flame className="w-4 h-4 text-rose-600" />
                        <span>Pilih Vektor Uji Hak Database</span>
                      </h3>
                      <span className="text-[11px] font-mono text-emerald-600 font-bold">Safe Canary Probe</span>
                    </div>

                    {/* Target URL */}
                    <div className="space-y-1">
                      <label className="text-xs font-semibold text-slate-700">Target Endpoint URL</label>
                      <input
                        type="text"
                        value={dbBoundaryUrl || targetUrl}
                        onChange={(e) => setDbBoundaryUrl(e.target.value)}
                        placeholder="https://example.com/api"
                        className="w-full px-3.5 py-2 rounded-xl border border-slate-200 text-xs font-mono text-slate-800 bg-white focus:outline-none focus:ring-2 focus:ring-rose-500"
                      />
                    </div>

                    {/* Parameter */}
                    <div className="grid grid-cols-3 gap-3">
                      <div className="col-span-2 space-y-1">
                        <label className="text-xs font-semibold text-slate-700">Parameter Injeksi</label>
                        <input
                          type="text"
                          value={dbBoundaryParam}
                          onChange={(e) => setDbBoundaryParam(e.target.value)}
                          placeholder="id"
                          className="w-full px-3.5 py-2 rounded-xl border border-slate-200 text-xs font-mono text-slate-800 bg-white focus:outline-none focus:ring-2 focus:ring-rose-500"
                        />
                      </div>
                      <div className="space-y-1">
                        <label className="text-xs font-semibold text-slate-700">Metode</label>
                        <select
                          value={dbBoundaryMethod}
                          onChange={(e) => setDbBoundaryMethod(e.target.value)}
                          className="w-full px-3 py-2 rounded-xl border border-slate-200 text-xs font-bold text-slate-800 bg-white focus:outline-none focus:ring-2 focus:ring-rose-500"
                        >
                          <option value="GET">GET</option>
                          <option value="POST">POST</option>
                        </select>
                      </div>
                    </div>

                    {/* Instruction Selection Cards */}
                    <div className="space-y-2">
                      <label className="text-xs font-semibold text-slate-700">Pilih Instruksi Manipulasi Struktur:</label>
                      <div className="space-y-2">
                        {[
                          {
                            id: 'drop_database_canary',
                            title: '1. Audit Hak DROP DATABASE (Penghapusan Basis Data)',
                            sql: "'; DROP DATABASE vulnhunter_canary_audit_db; -- ",
                            risk: 'Kerusakan Total Basis Data & Multi-Statement'
                          },
                          {
                            id: 'drop_table_canary',
                            title: '2. Audit Hak DROP TABLE (Pemusnahan Tabel)',
                            sql: "'; DROP TABLE vulnhunter_canary_audit_tbl; -- ",
                            risk: 'Kehilangan Struktur Tabel & Skema'
                          },
                          {
                            id: 'truncate_table_canary',
                            title: '3. Audit Hak TRUNCATE TABLE (Pembersihan Data Massal)',
                            sql: "'; TRUNCATE TABLE vulnhunter_canary_audit_tbl; -- ",
                            risk: 'Penghapusan Record Tanpa Log Baris'
                          },
                          {
                            id: 'alter_table_canary',
                            title: '4. Audit Hak ALTER TABLE (Modifikasi Skema)',
                            sql: "'; ALTER TABLE vulnhunter_canary_audit_tbl ADD COLUMN probe text; -- ",
                            risk: 'Mutasi Definisi Kolom & Manipulasi Backdoor'
                          }
                        ].map((inst) => (
                          <div
                            key={inst.id}
                            onClick={() => setDbBoundaryInstruction(inst.id)}
                            className={`p-3 rounded-xl border cursor-pointer transition ${
                              dbBoundaryInstruction === inst.id
                                ? 'bg-rose-50 border-rose-300 ring-1 ring-rose-400'
                                : 'bg-white border-slate-200 hover:border-slate-300'
                            }`}
                          >
                            <div className="flex items-center justify-between">
                              <span className="text-xs font-bold text-slate-800">{inst.title}</span>
                              <span className="text-[10px] font-semibold text-rose-600">{inst.risk}</span>
                            </div>
                            <div className="p-2 rounded-lg bg-slate-900 text-emerald-400 font-mono text-[11px] mt-2 truncate">
                              {inst.sql}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Action Button */}
                    <button
                      onClick={() => handleRunDbBoundary()}
                      disabled={isDbBoundaryTesting}
                      className="w-full py-2.5 rounded-xl bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-700 hover:to-rose-700 text-white text-xs font-bold shadow-md shadow-red-200 flex items-center justify-center space-x-2 transition disabled:opacity-50"
                    >
                      {isDbBoundaryTesting ? (
                        <>
                          <RefreshCw className="w-4 h-4 animate-spin" />
                          <span>Mengevaluasi Batas Pertahanan Data...</span>
                        </>
                      ) : (
                        <>
                          <ShieldAlert className="w-4 h-4" />
                          <span>Jalankan Audit Hak Database Live</span>
                        </>
                      )}
                    </button>
                  </div>

                  {/* RIGHT: MULTI-LAYER DEFENSE EVALUATION */}
                  <div className="lg:col-span-6 space-y-4">
                    
                    {dbBoundaryResult ? (
                      <div className="glass-panel p-5 rounded-2xl border border-slate-200 shadow-sm space-y-4 animate-in fade-in duration-200">
                        <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                          <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider flex items-center space-x-2">
                            <Layers className="w-4 h-4 text-indigo-600" />
                            <span>Evaluasi Lapis Pertahanan Sistem</span>
                          </h3>
                          <span className="text-[11px] text-slate-400 font-mono">{dbBoundaryResult.timestamp}</span>
                        </div>

                        {/* VERDICT BANNER */}
                        <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-1">
                          <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">
                            Hasil Evaluasi
                          </span>
                          <p className="text-xs font-bold text-slate-900">
                            {dbBoundaryResult.verdict}
                          </p>
                          <p className="text-[11px] font-mono text-slate-500 mt-1">
                            HTTP Status: {dbBoundaryResult.status_code} | Instruksi: {dbBoundaryResult.instruction_type}
                          </p>
                        </div>

                        {/* 3-LAYER DEFENSE STATUS CHECKLIST */}
                        <div className="space-y-2.5">
                          <span className="text-xs font-bold text-slate-700 uppercase tracking-wider block">
                            Status 3 Lapis Pertahanan Data:
                          </span>

                          {/* Lapis 1 */}
                          <div className={`p-3 rounded-xl border flex items-center justify-between ${
                            dbBoundaryResult.waf_blocked
                              ? 'bg-emerald-50 border-emerald-200 text-emerald-800'
                              : 'bg-slate-50 border-slate-200 text-slate-700'
                          }`}>
                            <div className="flex items-center space-x-2.5">
                              <Shield className="w-4 h-4 text-indigo-600" />
                              <div>
                                <p className="text-xs font-bold">Lapis 1: Web Application Firewall (WAF)</p>
                                <p className="text-[11px] text-slate-500">Penyaringan kata kunci DDL berbahaya di perimeter.</p>
                              </div>
                            </div>
                            <span className={`px-2 py-0.5 rounded-lg text-[10px] font-bold ${
                              dbBoundaryResult.waf_blocked ? 'bg-emerald-200 text-emerald-900' : 'bg-slate-200 text-slate-600'
                            }`}>
                              {dbBoundaryResult.waf_blocked ? 'Aktif & Memblokir' : 'Lolos Perimeter'}
                            </span>
                          </div>

                          {/* Lapis 2 */}
                          <div className={`p-3 rounded-xl border flex items-center justify-between ${
                            dbBoundaryResult.stacked_blocked
                              ? 'bg-emerald-50 border-emerald-200 text-emerald-800'
                              : 'bg-slate-50 border-slate-200 text-slate-700'
                          }`}>
                            <div className="flex items-center space-x-2.5">
                              <Cpu className="w-4 h-4 text-blue-600" />
                              <div>
                                <p className="text-xs font-bold">Lapis 2: Driver / ORM Multi-Statement</p>
                                <p className="text-[11px] text-slate-500">Penolakan eksekusi query bertumpuk (; DROP...).</p>
                              </div>
                            </div>
                            <span className={`px-2 py-0.5 rounded-lg text-[10px] font-bold ${
                              dbBoundaryResult.stacked_blocked ? 'bg-emerald-200 text-emerald-900' : 'bg-slate-200 text-slate-600'
                            }`}>
                              {dbBoundaryResult.stacked_blocked ? 'Tolak Multi-Query' : 'Standar'}
                            </span>
                          </div>

                          {/* Lapis 3 */}
                          <div className={`p-3 rounded-xl border flex items-center justify-between ${
                            dbBoundaryResult.privilege_denied
                              ? 'bg-emerald-50 border-emerald-200 text-emerald-800'
                              : 'bg-slate-50 border-slate-200 text-slate-700'
                          }`}>
                            <div className="flex items-center space-x-2.5">
                              <Key className="w-4 h-4 text-emerald-600" />
                              <div>
                                <p className="text-xs font-bold">Lapis 3: Database User Privilege (Least Privilege)</p>
                                <p className="text-[11px] text-slate-500">Pencabutan hak DDL dari akun aplikasi.</p>
                              </div>
                            </div>
                            <span className={`px-2 py-0.5 rounded-lg text-[10px] font-bold ${
                              dbBoundaryResult.privilege_denied ? 'bg-emerald-200 text-emerald-900' : 'bg-slate-200 text-slate-600'
                            }`}>
                              {dbBoundaryResult.privilege_denied ? 'Least Privilege Terbukti' : 'DML Terisolasi'}
                            </span>
                          </div>
                        </div>

                        {/* PAYLOAD TELEMETRY */}
                        <div className="p-3 rounded-xl bg-slate-900 text-slate-300 font-mono text-[11px] space-y-1 border border-slate-800">
                          <span className="text-slate-500 text-[10px] uppercase font-bold block">Raw Payload Injected:</span>
                          <p className="text-emerald-400 break-all">{dbBoundaryResult.payload_used}</p>
                        </div>
                      </div>
                    ) : (
                      <div className="glass-panel p-8 rounded-2xl border border-slate-200 text-center space-y-3 shadow-sm">
                        <div className="w-12 h-12 rounded-2xl bg-amber-50 text-amber-600 mx-auto flex items-center justify-center">
                          <ShieldCheck className="w-6 h-6" />
                        </div>
                        <h4 className="text-sm font-bold text-slate-800">Siap Menjalankan Audit Batas Hak Database</h4>
                        <p className="text-xs text-slate-500 max-w-sm mx-auto">
                          Pilih jenis vektor instruksi DDL di sebelah kiri dan klik tombol untuk mengevaluasi lapis ketahanan hak akses database target.
                        </p>
                      </div>
                    )}

                    {/* LEAST PRIVILEGE HARDENING SCRIPT GENERATOR */}
                    <div className="glass-panel p-5 rounded-2xl border border-slate-200 space-y-3 shadow-sm">
                      <div className="flex items-center justify-between border-b border-slate-100 pb-2">
                        <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider flex items-center space-x-2">
                          <FileCode className="w-4 h-4 text-emerald-600" />
                          <span>Panduan Pengerasan Hak Akses Basis Data (Least Privilege)</span>
                        </h4>
                        <div className="flex space-x-1">
                          {['MySQL / MariaDB', 'PostgreSQL', 'Microsoft SQL Server'].map((dbms) => (
                            <button
                              key={dbms}
                              onClick={() => setSelectedDbmsGuide(dbms)}
                              className={`px-2 py-0.5 rounded-lg text-[10px] font-bold transition ${
                                selectedDbmsGuide === dbms
                                  ? 'bg-emerald-600 text-white shadow-sm'
                                  : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                              }`}
                            >
                              {dbms.split(' ')[0]}
                            </button>
                          ))}
                        </div>
                      </div>

                      <div className="p-3.5 rounded-xl bg-slate-950 text-slate-200 font-mono text-[11px] overflow-x-auto relative group">
                        <pre className="text-emerald-400 leading-relaxed">
                          {selectedDbmsGuide === 'MySQL / MariaDB' && (
                            `-- 1. Buat pengguna aplikasi dengan hak DML terbatas saja\nCREATE USER 'web_app_user'@'%' IDENTIFIED BY 'StrongPassword!2026';\n\n-- 2. Hanya berikan hak SELECT, INSERT, UPDATE, DELETE\nGRANT SELECT, INSERT, UPDATE, DELETE ON db_production.* TO 'web_app_user'@'%';\n\n-- 3. Pastikan hak DDL (DROP, ALTER, CREATE) DICABUT TOTAL\nREVOKE DROP, ALTER, CREATE, INDEX, REFERENCES ON db_production.* FROM 'web_app_user'@'%';\nFLUSH PRIVILEGES;`
                          )}
                          {selectedDbmsGuide === 'PostgreSQL' && (
                            `-- 1. Buat role aplikasi terbatas\nCREATE ROLE web_app_user WITH LOGIN PASSWORD 'StrongPassword!2026';\n\n-- 2. Batasi hanya DML pada tabel yang ada\nGRANT CONNECT ON DATABASE db_production TO web_app_user;\nGRANT USAGE ON SCHEMA public TO web_app_user;\nGRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO web_app_user;\n\n-- 3. Cabut hak membuat tabel baru / DROP pada skema\nREVOKE CREATE ON SCHEMA public FROM web_app_user;`
                          )}
                          {selectedDbmsGuide === 'Microsoft SQL Server' && (
                            `-- 1. Buat login dan user aplikasi\nCREATE LOGIN web_app_user WITH PASSWORD = 'StrongPassword!2026';\nUSE db_production;\nCREATE USER web_app_user FOR LOGIN web_app_user;\n\n-- 2. Masukkan HANYA ke role pembaca dan penulis data\nALTER ROLE db_datareader ADD MEMBER web_app_user;\nALTER ROLE db_datawriter ADD MEMBER web_app_user;\n\n-- 3. Tolak izin modifikasi skema\nDENY ALTER ANY SCHEMA TO web_app_user;\nDENY CONTROL TO web_app_user;`
                          )}
                        </pre>
                        <button
                          onClick={() => {
                            const text = selectedDbmsGuide === 'MySQL / MariaDB'
                              ? `CREATE USER 'web_app_user'@'%' IDENTIFIED BY 'StrongPassword!2026';\nGRANT SELECT, INSERT, UPDATE, DELETE ON db_production.* TO 'web_app_user'@'%';\nREVOKE DROP, ALTER, CREATE, INDEX, REFERENCES ON db_production.* FROM 'web_app_user'@'%';\nFLUSH PRIVILEGES;`
                              : selectedDbmsGuide === 'PostgreSQL'
                              ? `CREATE ROLE web_app_user WITH LOGIN PASSWORD 'StrongPassword!2026';\nGRANT CONNECT ON DATABASE db_production TO web_app_user;\nGRANT USAGE ON SCHEMA public TO web_app_user;\nGRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO web_app_user;\nREVOKE CREATE ON SCHEMA public FROM web_app_user;`
                              : `CREATE LOGIN web_app_user WITH PASSWORD = 'StrongPassword!2026';\nUSE db_production;\nCREATE USER web_app_user FOR LOGIN web_app_user;\nALTER ROLE db_datareader ADD MEMBER web_app_user;\nALTER ROLE db_datawriter ADD MEMBER web_app_user;\nDENY ALTER ANY SCHEMA TO web_app_user;`;
                            navigator.clipboard.writeText(text);
                            setCopiedKey('db_script');
                            setTimeout(() => setCopiedKey(null), 2000);
                          }}
                          className="absolute top-2 right-2 px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] font-bold border border-slate-700 transition flex items-center space-x-1"
                        >
                          {copiedKey === 'db_script' ? (
                            <>
                              <Check className="w-3 h-3 text-emerald-400" />
                              <span className="text-emerald-400">Tersalin</span>
                            </>
                          ) : (
                            <>
                              <Copy className="w-3 h-3" />
                              <span>Salin SQL</span>
                            </>
                          )}
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* TAB 9: JWT SECURITY ANALYZER */}
        {activeTab === 'jwt_analyzer' && (
          <div className="space-y-6">
            {/* TOP CARD */}
            <div className="glass-panel p-5 rounded-xl border border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <h3 className="text-base font-bold text-slate-900 flex items-center space-x-2">
                  <Key className="w-5 h-5 text-purple-600" />
                  <span>JSON Web Token (JWT) Security Analyzer & Decoder (2026 Edition)</span>
                </h3>
                <p className="text-xs text-slate-500 mt-0.5">
                  Dekode struktur token, audit algoritma enkripsi (alg: none), masa kedaluwarsa (exp), dan deteksi kebocoran kredensial rahasia.
                </p>
              </div>

              {/* Sample Presets */}
              <div className="flex flex-wrap gap-1.5">
                <button
                  onClick={() => {
                    const t = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIFVzZXIiLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE1MTYyMzkwMjJ9.';
                    setJwtInput(t);
                    setJwtAuditResult(parseJwtClient(t));
                  }}
                  className="px-2.5 py-1 rounded-lg bg-rose-50 hover:bg-rose-100 text-rose-700 border border-rose-200 text-[11px] font-bold transition"
                >
                  ⚡ Sample: alg:none
                </button>
                <button
                  onClick={() => {
                    const t = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoxNTE2MjM5MDIyfQ.4S_X7YyP_fE2a3Fm1k8hX5b6';
                    setJwtInput(t);
                    setJwtAuditResult(parseJwtClient(t));
                  }}
                  className="px-2.5 py-1 rounded-lg bg-amber-50 hover:bg-amber-100 text-amber-700 border border-amber-200 text-[11px] font-bold transition"
                >
                  ⚡ Sample: Expired Token
                </button>
                <button
                  onClick={() => {
                    const t = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicGFzc3dvcmQiOiJzdXBlcnNlY3JldDEyMyIsInJvbGUiOiJ1c2VyIiwiZXhwIjoyMDAwMDAwMDAwfQ.signature_here';
                    setJwtInput(t);
                    setJwtAuditResult(parseJwtClient(t));
                  }}
                  className="px-2.5 py-1 rounded-lg bg-purple-50 hover:bg-purple-100 text-purple-700 border border-purple-200 text-[11px] font-bold transition"
                >
                  ⚡ Sample: Secret Leak
                </button>
              </div>
            </div>

            {/* INPUT AREA */}
            <div className="glass-panel p-5 rounded-2xl border border-slate-200 space-y-3 shadow-sm">
              <div className="flex items-center justify-between">
                <label className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center space-x-2">
                  <span>Paste Raw JWT Token String</span>
                </label>
                {jwtInput && (
                  <button
                    onClick={() => { setJwtInput(''); setJwtAuditResult(null); }}
                    className="text-[11px] font-semibold text-slate-500 hover:text-rose-600 transition"
                  >
                    Bersihkan
                  </button>
                )}
              </div>

              <textarea
                rows={3}
                value={jwtInput}
                onChange={(e) => {
                  setJwtInput(e.target.value);
                  setJwtAuditResult(parseJwtClient(e.target.value));
                }}
                placeholder="Paste token di sini (contoh: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...)"
                className="w-full p-3 rounded-xl border border-slate-300 font-mono text-xs text-slate-800 bg-slate-50 focus:bg-white focus:outline-none focus:ring-2 focus:ring-purple-500 transition break-all"
              />

              <div className="flex justify-end">
                <button
                  onClick={() => setJwtAuditResult(parseJwtClient(jwtInput))}
                  className="px-4 py-2 rounded-xl bg-purple-600 hover:bg-purple-700 text-white text-xs font-bold transition shadow-sm flex items-center space-x-2"
                >
                  <Key className="w-3.5 h-3.5" />
                  <span>Audit Keamanan Token</span>
                </button>
              </div>
            </div>

            {/* AUDIT RESULTS & DECODED CLAIMS */}
            {jwtAuditResult && (
              <div className="space-y-6">
                {jwtAuditResult.error ? (
                  <div className="glass-panel p-6 rounded-2xl border border-rose-200 bg-rose-50/50 text-center space-y-2">
                    <AlertTriangle className="w-8 h-8 text-rose-600 mx-auto" />
                    <h4 className="text-sm font-bold text-rose-800">Dekode Token Gagal</h4>
                    <p className="text-xs text-rose-600 font-mono">{jwtAuditResult.error}</p>
                  </div>
                ) : (
                  <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                    {/* LEFT COLUMN: DECODED HEADER & PAYLOAD */}
                    <div className="lg:col-span-6 space-y-4">
                      {/* HEADER CARD */}
                      <div className="glass-panel p-5 rounded-2xl border border-slate-200 space-y-3 shadow-sm">
                        <div className="flex items-center justify-between border-b border-slate-100 pb-2">
                          <h4 className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center space-x-1.5">
                            <Code2 className="w-3.5 h-3.5 text-indigo-600" />
                            <span>1. Decoded Header (Algorithm & Token Type)</span>
                          </h4>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                            jwtAuditResult.header.alg?.toLowerCase() === 'none'
                              ? 'bg-rose-100 text-rose-800 border border-rose-200'
                              : 'bg-emerald-100 text-emerald-800 border border-emerald-200'
                          }`}>
                            ALG: {jwtAuditResult.header.alg || 'none'}
                          </span>
                        </div>
                        <pre className="p-3 bg-slate-900 text-emerald-400 font-mono text-xs rounded-xl overflow-x-auto">
                          {JSON.stringify(jwtAuditResult.header, null, 2)}
                        </pre>
                      </div>

                      {/* PAYLOAD CARD */}
                      <div className="glass-panel p-5 rounded-2xl border border-slate-200 space-y-3 shadow-sm">
                        <div className="flex items-center justify-between border-b border-slate-100 pb-2">
                          <h4 className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center space-x-1.5">
                            <FileText className="w-3.5 h-3.5 text-blue-600" />
                            <span>2. Decoded Payload (Claims & Identity)</span>
                          </h4>
                          <span className="text-[10px] text-slate-400 font-mono">
                            {Object.keys(jwtAuditResult.payload).length} claims
                          </span>
                        </div>
                        <pre className="p-3 bg-slate-900 text-cyan-300 font-mono text-xs rounded-xl overflow-x-auto">
                          {JSON.stringify(jwtAuditResult.payload, null, 2)}
                        </pre>
                      </div>

                      {/* SIGNATURE CARD */}
                      <div className="glass-panel p-4 rounded-xl border border-slate-200 flex items-center justify-between">
                        <div className="flex items-center space-x-2">
                          <Lock className="w-4 h-4 text-slate-600" />
                          <span className="text-xs font-bold text-slate-700">Digital Signature:</span>
                        </div>
                        <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold ${
                          jwtAuditResult.hasSignature
                            ? 'bg-emerald-100 text-emerald-800 border border-emerald-200'
                            : 'bg-rose-100 text-rose-800 border border-rose-200 font-black animate-pulse'
                        }`}>
                          {jwtAuditResult.hasSignature ? 'Signature Present' : '❌ UNSIGNED (NO SIGNATURE)'}
                        </span>
                      </div>
                    </div>

                    {/* RIGHT COLUMN: SECURITY AUDIT CHECKLIST */}
                    <div className="lg:col-span-6 space-y-4">
                      <div className="glass-panel p-5 rounded-2xl border border-slate-200 space-y-4 shadow-sm">
                        <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                          <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider flex items-center space-x-2">
                            <ShieldAlert className="w-4 h-4 text-purple-600" />
                            <span>Hasil Audit Keamanan Token</span>
                          </h4>
                          <span className="text-[11px] font-mono font-bold text-purple-600">
                            {jwtAuditResult.checks.filter(c => c.status !== 'PASS').length} Isu Terdeteksi
                          </span>
                        </div>

                        <div className="space-y-3">
                          {jwtAuditResult.checks.map((check, cIdx) => {
                            const badgeStyle = 
                              check.status === 'CRITICAL' ? 'bg-rose-50 border-rose-300 text-rose-800' :
                              check.status === 'HIGH' ? 'bg-amber-50 border-amber-300 text-amber-800' :
                              check.status === 'MEDIUM' ? 'bg-yellow-50 border-yellow-300 text-yellow-800' :
                              check.status === 'PASS' ? 'bg-emerald-50 border-emerald-200 text-emerald-800' :
                              'bg-slate-50 border-slate-200 text-slate-700';

                            return (
                              <div key={cIdx} className={`p-3.5 rounded-xl border ${badgeStyle} space-y-1`}>
                                <div className="flex items-center justify-between">
                                  <span className="text-xs font-bold">{check.title}</span>
                                  <span className="text-[10px] font-black uppercase px-2 py-0.5 rounded bg-white/70 border border-current">
                                    {check.status}
                                  </span>
                                </div>
                                <p className="text-[11px] leading-relaxed opacity-90">{check.desc}</p>
                              </div>
                            );
                          })}
                        </div>

                        {/* HARDENING GUIDELINES */}
                        <div className="p-4 bg-purple-50/50 rounded-xl border border-purple-200 space-y-2 text-xs">
                          <span className="font-bold text-purple-900 block text-[11px] uppercase tracking-wider">
                            🛡️ Best Practice Hardening JWT (OWASP ASVS):
                          </span>
                          <ul className="space-y-1 text-slate-600 text-[11px] list-disc list-inside">
                            <li>Selalu gunakan whitelist algoritma eksplisit di backend (jangan terima header <code>alg: none</code>).</li>
                            <li>Pastikan klaim <code>exp</code> (expiration) tidak melebihi 15-30 menit untuk access token.</li>
                            <li>Gunakan secret key HMAC dengan minimal 256-bit entropy dari secure random generator.</li>
                            <li>Simpan token di cookie beratribut <code>HttpOnly; Secure; SameSite=Strict</code> untuk proteksi XSS.</li>
                          </ul>
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

      </main>

      {/* LIVE POC VERIFICATION MODAL */}
      {showVerifyModal && (
        <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-white w-full max-w-2xl rounded-2xl border border-slate-300 shadow-2xl p-6 space-y-4 relative animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between border-b border-slate-200 pb-3">
              <div className="flex items-center space-x-2">
                <Play className="w-4 h-4 text-indigo-600 fill-current" />
                <h3 className="text-sm font-bold text-slate-900">Verifikasi Live Proof-of-Concept (PoC)</h3>
              </div>
              <button
                onClick={() => setShowVerifyModal(false)}
                className="text-slate-400 hover:text-slate-700"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div className="bg-slate-50 p-3 rounded-xl border border-slate-200 font-mono space-y-1">
                <span className="text-[10px] text-slate-500 uppercase font-bold">Temuan Yang Diuji:</span>
                <div className="text-slate-900 font-bold">{verifyingFinding?.title}</div>
                <div className="text-indigo-600 text-[11px] truncate">{verifyingFinding?.target_url || targetUrl}</div>
              </div>

              {isVerifyingPoC ? (
                <div className="p-8 text-center space-y-2 text-indigo-600">
                  <RefreshCw className="w-6 h-6 animate-spin mx-auto" />
                  <div className="text-xs font-bold">Mengirim HTTP probe langsung ke server target...</div>
                </div>
              ) : verifyResult ? (
                <div className="space-y-3 font-mono text-xs">
                  <div className={`p-2.5 rounded-xl border flex items-center justify-between ${
                    verifyResult.status_code === 200
                      ? 'bg-emerald-50 border-emerald-200 text-emerald-800 font-bold'
                      : 'bg-slate-50 border-slate-200 text-slate-700'
                  }`}>
                    <span>HTTP Status: {verifyResult.status_code || 'N/A'}</span>
                    <span>Latency: {verifyResult.latency_ms || 0}ms</span>
                  </div>

                  {verifyResult.request_raw && (
                    <div className="space-y-1">
                      <span className="text-[10px] text-slate-500 uppercase font-bold">Request Terkirim:</span>
                      <pre className="p-2.5 bg-slate-900 text-slate-200 rounded-lg border border-slate-800 text-[11px] overflow-x-auto whitespace-pre-wrap">
                        {verifyResult.request_raw}
                      </pre>
                    </div>
                  )}

                  {verifyResult.response_headers && (
                    <div className="space-y-1">
                      <span className="text-[10px] text-slate-500 uppercase font-bold">Response Headers Diterima:</span>
                      <pre className="p-2.5 bg-slate-900 text-cyan-300 rounded-lg border border-slate-800 text-[10px] max-h-32 overflow-y-auto whitespace-pre-wrap">
                        {verifyResult.response_headers}
                      </pre>
                    </div>
                  )}

                  {verifyResult.response_body_snippet && (
                    <div className="space-y-1">
                      <span className="text-[10px] text-slate-500 uppercase font-bold">Snippet Response Body:</span>
                      <pre className="p-2.5 bg-slate-900 text-slate-300 rounded-lg border border-slate-800 text-[10px] max-h-32 overflow-y-auto whitespace-pre-wrap">
                        {verifyResult.response_body_snippet}
                      </pre>
                    </div>
                  )}
                </div>
              ) : null}
            </div>

            <div className="flex justify-end pt-2 border-t border-slate-200">
              <button
                onClick={() => setShowVerifyModal(false)}
                className="px-4 py-2 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-800 text-xs font-bold transition"
              >
                Tutup
              </button>
            </div>
          </div>
        </div>
      )}

      {/* FOOTER */}
      <footer className="border-t border-slate-200 bg-white py-4 text-center text-slate-500 text-[11px] font-mono shadow-inner">
        DjoeraganCyber
      </footer>
    </div>
  );
}
