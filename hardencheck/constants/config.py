from hardencheck.models import Severity

CONFIG_PATTERNS = [
    (r'^\s*PermitRootLogin\s+yes\s*$', "sshd_config", "SSH root login enabled", Severity.HIGH),
    (r'^\s*PermitEmptyPasswords\s+yes\s*$', "sshd_config", "SSH empty passwords allowed", Severity.CRITICAL),
    (r'^\s*telnet\s+stream\s+tcp', "inetd.conf", "Telnet service enabled", Severity.CRITICAL),
    (r'::respawn:.*/telnetd', "inittab", "Telnet auto-start enabled", Severity.CRITICAL),
    (r'^root::0:', "shadow", "Root has empty password", Severity.CRITICAL),
]

CONFIG_INFO_PATTERNS = [
    (r'^\s*PasswordAuthentication\s+yes', "sshd_config", "SSH password auth enabled (consider keys)", Severity.INFO),
    (r'^root:\*:', "shadow", "Root account locked", Severity.INFO),
]

CERT_EXTENSIONS = {".pem", ".crt", ".cer", ".der", ".key", ".p12", ".pfx", ".jks"}
