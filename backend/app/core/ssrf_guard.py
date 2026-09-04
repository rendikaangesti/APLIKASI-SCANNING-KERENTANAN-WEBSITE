import socket
import ipaddress
from urllib.parse import urlparse
from typing import Tuple, List

# Strict IP range blocks for Anti-SSRF compliance
BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),       # IPv4 Loopback
    ipaddress.ip_network("10.0.0.0/8"),        # RFC 1918 Private Class A
    ipaddress.ip_network("172.16.0.0/12"),     # RFC 1918 Private Class B
    ipaddress.ip_network("192.168.0.0/16"),    # RFC 1918 Private Class C
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local / Cloud Metadata (169.254.169.254)
    ipaddress.ip_network("100.64.0.0/10"),     # Carrier-Grade NAT (CGNAT)
    ipaddress.ip_network("0.0.0.0/8"),         # Current local network
    ipaddress.ip_network("224.0.0.0/4"),       # Multicast
    ipaddress.ip_network("240.0.0.0/4"),       # Reserved
    ipaddress.ip_network("::1/128"),           # IPv6 Loopback
    ipaddress.ip_network("fc00::/7"),          # IPv6 Unique Local
    ipaddress.ip_network("fe80::/10"),         # IPv6 Link-Local
]

BLOCKED_HOSTNAMES = [
    "localhost", "metadata", "instance-data", "metadata.google.internal"
]

def validate_and_sanitize_target(url_str: str) -> Tuple[bool, str, str]:
    """
    Validasi URL target terhadap SSRF, DNS Rebinding, dan format URI standar.
    Returns: (is_valid, normalized_url, error_message)
    """
    if not url_str:
        return False, "", "URL target tidak boleh kosong."

    url_str = url_str.strip()
    if not url_str.startswith(("http://", "https://")):
        url_str = "https://" + url_str

    try:
        parsed = urlparse(url_str)
        hostname = parsed.hostname

        if not hostname:
            return False, "", "Format URL tidak valid (hostname tidak ditemukan)."

        hostname_lower = hostname.lower()

        # Check blocked hostnames
        if hostname_lower in BLOCKED_HOSTNAMES or hostname_lower.endswith((".local", ".internal", ".corp", ".lan")):
            return False, "", f"Target hostname '{hostname}' diblokir demi keamanan internal (Anti-SSRF)."

        # Resolve DNS to all IPv4 & IPv6 records
        addr_info = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        if not addr_info:
            return False, "", f"Gagal me-resolve DNS untuk host: {hostname}"

        for entry in addr_info:
            ip_str = entry[4][0]
            ip_obj = ipaddress.ip_address(ip_str)

            for blocked_net in BLOCKED_IP_NETWORKS:
                if ip_obj in blocked_net:
                    return (
                        False,
                        "",
                        f"Akses ke IP Private/Internal ({ip_str}) diblokir demi keamanan (Anti-SSRF Standard)."
                    )

        port_suffix = f":{parsed.port}" if parsed.port and parsed.port not in (80, 443) else ""
        normalized_url = f"{parsed.scheme}://{hostname}{port_suffix}"
        return True, normalized_url, ""

    except socket.gaierror:
        return False, "", f"Domain atau hostname tidak ditemukan / DNS resolution failed: {url_str}"
    except Exception as e:
        return False, "", f"Validasi URL gagal: {str(e)}"
