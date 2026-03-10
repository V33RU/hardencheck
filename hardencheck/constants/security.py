from hardencheck.models import Severity

# ============================================================================
# Security Testing: Weak Crypto Patterns
# ============================================================================
WEAK_CRYPTO_PATTERNS = [
    (r'ssl_protocols?\s+SSLv2', "SSLv2 protocol enabled (deprecated, insecure)", Severity.CRITICAL),
    (r'ssl_protocols?\s+SSLv3', "SSLv3 protocol enabled (deprecated, POODLE vulnerable)", Severity.HIGH),
    (r'tls_protocols?\s+TLSv1\s', "TLSv1.0 enabled (deprecated, weak)", Severity.HIGH),
    (r'tls_protocols?\s+TLSv1\.1\s', "TLSv1.1 enabled (deprecated)", Severity.MEDIUM),
    (r'CipherSuite\s+.*RC4', "RC4 cipher enabled (deprecated, weak)", Severity.HIGH),
    (r'CipherSuite\s+.*MD5', "MD5 hash in cipher suite (weak)", Severity.MEDIUM),
    (r'CipherSuite\s+.*DES', "DES cipher enabled (deprecated, weak)", Severity.HIGH),
    (r'CipherSuite\s+.*3DES', "3DES cipher enabled (deprecated)", Severity.MEDIUM),
    (r'--tls-version-min\s+1\.0', "Minimum TLS version 1.0 (weak)", Severity.HIGH),
    (r'--tls-version-min\s+1\.1', "Minimum TLS version 1.1 (deprecated)", Severity.MEDIUM),
    (r'openssl\s+.*-ssl2', "OpenSSL SSLv2 support", Severity.CRITICAL),
    (r'openssl\s+.*-ssl3', "OpenSSL SSLv3 support", Severity.HIGH),
    (r'cipher\s+.*RC4', "RC4 cipher usage", Severity.HIGH),
    (r'cipher\s+.*DES', "DES cipher usage", Severity.HIGH),
]

# Known vulnerable component versions (simplified - in production, use CVE DB)
VULNERABLE_VERSIONS = {
    "openssl": {
        "<1.0.1": "Multiple critical CVEs (Heartbleed, etc.)",
        "<1.0.2": "Multiple high-severity CVEs",
        "<1.1.0": "Several medium-severity CVEs",
    },
    "dropbear": {
        "<2018.76": "CVE-2018-15599 (pre-auth remote code execution)",
        "<2020.80": "Multiple security fixes",
    },
    "busybox": {
        "<1.28.0": "Multiple CVEs including shell injection",
        "<1.31.0": "Several security fixes",
    },
    "dnsmasq": {
        "<2.78": "CVE-2017-14491-14496 (multiple RCE vulnerabilities)",
        "<2.80": "Additional security fixes",
    },
    "nginx": {
        "<1.10.0": "Multiple CVEs",
        "<1.14.0": "Security fixes",
    },
    "lighttpd": {
        "<1.4.50": "Multiple CVEs",
    },
}

# Default credentials to test (service -> [(username, password), ...])
DEFAULT_CREDENTIALS = {
    "ssh": [("root", "root"), ("admin", "admin"), ("root", ""), ("admin", ""), ("root", "toor")],
    "telnet": [("root", "root"), ("admin", "admin"), ("root", ""), ("admin", "")],
    "http": [("admin", "admin"), ("root", "root"), ("admin", ""), ("", "")],
    "ftp": [("anonymous", ""), ("ftp", "ftp"), ("admin", "admin")],
    "snmp": [("public", ""), ("private", "")],
}
