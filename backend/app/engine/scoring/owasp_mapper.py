from typing import Dict, Any

OWASP_TOP_10_2021 = {
    "A01:2021": {
        "name": "Broken Access Control",
        "description": "Kegagalan penegakan pembatasan otorisasi pengguna sehingga pengguna dapat mengakses data atau fungsi yang bukan haknya.",
        "icon": "Lock"
    },
    "A02:2021": {
        "name": "Cryptographic Failures",
        "description": "Celah terkait transmisi data sensitif tanpa enkripsi (plaintext), sertifikat kadaluarsa, atau algoritma kriptografi yang usang.",
        "icon": "Key"
    },
    "A03:2021": {
        "name": "Injection",
        "description": "Penyusupan data berbahaya melalui input (seperti SQL, NoSQL, OS Command, XSS) yang dieksekusi oleh interpreter.",
        "icon": "Code"
    },
    "A04:2021": {
        "name": "Insecure Design",
        "description": "Celah arsitektural dan desain sistem yang tidak mempertimbangkan ancaman keamanan sejak awal fase perancangan.",
        "icon": "Layers"
    },
    "A05:2021": {
        "name": "Security Misconfiguration",
        "description": "Konfigurasi default yang tidak aman, port terbuka, header keamanan yang hilang, atau pesan error verbose.",
        "icon": "Sliders"
    },
    "A06:2021": {
        "name": "Vulnerable and Outdated Components",
        "description": "Penggunaan software pihak ketiga, library, atau framework yang sudah memiliki CVE yang belum di-patch.",
        "icon": "AlertOctagon"
    },
    "A07:2021": {
        "name": "Identification and Authentication Failures",
        "description": "Kelemahan pada manajemen sesi, brute-force login, atau ketiadaan proteksi kredensial default.",
        "icon": "UserX"
    },
    "A08:2021": {
        "name": "Software and Data Integrity Failures",
        "description": "Infrastruktur kode atau pipeline CI/CD yang mengonsumsi plugin/objek tanpa validasi integritas digital.",
        "icon": "ShieldAlert"
    },
    "A09:2021": {
        "name": "Security Logging and Monitoring Failures",
        "description": "Ketiadaan logging aktivitas keamanan yang memadai sehingga deteksi insiden terhambat.",
        "icon": "Activity"
    },
    "A10:2021": {
        "name": "Server-Side Request Forgery (SSRF)",
        "description": "Aplikasi web dapat dipaksa mengambil resource jarak jauh ke jaringan internal yang terproteksi.",
        "icon": "Radio"
    }
}

def get_owasp_info(category_code: str) -> Dict[str, Any]:
    code = category_code.split("-")[0] if "-" in category_code else category_code
    return OWASP_TOP_10_2021.get(code, {
        "name": category_code,
        "description": "Kategori keamanan standar OWASP.",
        "icon": "Shield"
    })
