from hardencheck.models import Severity

ARCH_ASLR_ENTROPY = {
    "x86_64": (47, 28, 22),
    "x86": (32, 8, 8),
    "ARM64": (48, 24, 18),
    "ARM": (32, 8, 8),
    "MIPS64": (40, 18, 14),
    "MIPS": (32, 8, 8),
    "PowerPC64": (46, 28, 22),
    "PowerPC": (32, 8, 8),
    "RISC-V": (39, 18, 14),
}

BANNED_FUNCTIONS = {
    "gets":     ("fgets(buf, size, stdin)", Severity.CRITICAL, "CWE-120, OWASP-I4"),
    "strcpy":   ("strlcpy() or strncpy()+null", Severity.HIGH, "CWE-120, OWASP-I4"),
    "strcat":   ("strlcat() or strncat()+null", Severity.HIGH, "CWE-120, OWASP-I4"),
    "sprintf":  ("snprintf(buf, size, ...)", Severity.HIGH, "CWE-120, OWASP-I4"),
    "vsprintf": ("vsnprintf(buf, size, ...)", Severity.HIGH, "CWE-120, OWASP-I4"),
    "scanf":    ("fgets() + sscanf() or strtol()", Severity.MEDIUM, "CWE-134, OWASP-I4"),
    "system":   ("execve() with hardcoded path + validated args", Severity.HIGH, "CWE-78, OWASP-I4"),
    "popen":    ("pipe()+fork()+execve() with validated args", Severity.HIGH, "CWE-78, OWASP-I4"),
    "mktemp":   ("mkstemp() or mkdtemp()", Severity.HIGH, "CWE-377, NIST SI-16"),
    "tmpnam":   ("mkstemp() or tmpfile()", Severity.HIGH, "CWE-377, NIST SI-16"),
    "tempnam":  ("mkstemp()", Severity.HIGH, "CWE-377, NIST SI-16"),
}

LOW_RISK_FUNCTIONS = {
    "fscanf":   ("fgets() + sscanf()", Severity.LOW, "CWE-134"),
    "sscanf":   ("strtol/strtod with validation", Severity.INFO, "CWE-134"),
    "rand":     ("getrandom() for crypto use", Severity.INFO, "CWE-338"),
    "srand":    ("getrandom() for crypto use", Severity.INFO, "CWE-338"),
    "random":   ("getrandom() for crypto use", Severity.INFO, "CWE-338"),
    "strtok":   ("strtok_r() for thread safety", Severity.INFO, "CWE-362"),
    "asctime":  ("strftime()", Severity.INFO, "CWE-362"),
    "ctime":    ("ctime_r() or strftime()", Severity.INFO, "CWE-362"),
    "gmtime":   ("gmtime_r()", Severity.INFO, "CWE-362"),
    "localtime":("localtime_r()", Severity.INFO, "CWE-362"),
}
