<p align="center">
  <strong>HardenCheck</strong>
</p>

<p align="center">
  <strong>Firmware binary security analyzer with ASLR entropy analysis & SBOM generation.</strong>
</p>

<p align="center">
  <a href="https://github.com/v33ru/hardencheck">
    <img src="https://img.shields.io/badge/version-1.1-blue.svg" />
  </a>
  <a href="https://www.python.org/">
    <img src="https://img.shields.io/badge/python-3.7+-green.svg" />
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/license-MIT-orange.svg" />
  </a>
  <a href="https://buymeacoffee.com/v33ru">
    <img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-support-yellow?logo=buy-me-a-coffee&logoColor=black" />
  </a>
</p>

---

## Architecture

HardenCheck is a modular Python package with strict layered dependencies:

```
models → constants → core → analyzers → reports → scanner → cli
```

```
hardencheck/
├── hardencheck.py              # Entry point wrapper
├── hardencheck/
│   ├── __init__.py             # Public API
│   ├── __main__.py             # python -m hardencheck
│   ├── cli.py                  # Argument parsing & orchestration
│   ├── scanner.py              # HardenCheck orchestrator (17-step pipeline)
│   ├── models.py               # 18 dataclasses + 3 enums
│   ├── constants/              # All lookup tables & configuration
│   │   ├── core.py             # VERSION, BANNER, SECURE_ENV
│   │   ├── binary.py           # ELF patterns, scoring weights
│   │   ├── services.py         # 95+ known daemons & risk ratings
│   │   ├── credentials.py      # Credential detection patterns
│   │   ├── config.py           # Config weakness signatures
│   │   ├── security.py         # CVE patterns, banned functions
│   │   ├── firmware.py         # Firmware type signatures
│   │   ├── crypto.py           # Crypto binary patterns
│   │   ├── pqc.py              # Post-quantum crypto detection patterns
│   │   └── sbom.py             # CPE 2.3 mapping (90+ components)
│   ├── core/                   # Shared infrastructure
│   │   ├── context.py          # ScanContext (shared state)
│   │   ├── base.py             # BaseAnalyzer (abstract base)
│   │   └── utils.py            # safe_read_file, version_compare
│   ├── analyzers/              # 18 pluggable analyzer modules
│   │   ├── file_discovery.py       # ELF, source, config file discovery
│   │   ├── firmware_profile.py     # Architecture, libc, kernel fingerprint
│   │   ├── binary_analysis.py      # NX, Canary, PIE, RELRO, Fortify, CFI
│   │   ├── aslr_entropy.py         # Per-binary ASLR entropy analysis
│   │   ├── aslr_summary.py         # ASLR aggregate statistics
│   │   ├── daemon_detection.py     # Network service identification
│   │   ├── banned_functions.py     # Dangerous function usage scanner
│   │   ├── credential_scanner.py   # Hardcoded passwords, API keys
│   │   ├── certificate_scanner.py  # Certificate & key file analysis
│   │   ├── config_scanner.py       # Insecure configuration detection
│   │   ├── security_testing.py     # CVE checks, weak crypto, default creds
│   │   ├── crypto_binary.py        # Cryptographic utility analysis
│   │   ├── firmware_signing.py     # Secure boot & signing verification
│   │   ├── service_privileges.py   # Service privilege & isolation audit
│   │   ├── kernel_hardening.py     # Kernel security config analysis
│   │   ├── update_mechanism.py     # OTA / update security analysis
│   │   ├── pqc_readiness.py        # Post-quantum crypto readiness analyzer
│   │   └── sbom_generator.py       # Software Bill of Materials generator
│   └── reports/                # Output generators
│       ├── grading.py          # Security grading (A-F) & classification
│       ├── html_report.py      # Interactive HTML report (sidebar, toggles)
│       ├── json_report.py      # Machine-readable JSON report
│       ├── text_report.py      # Plain-text CI summary
│       ├── csv_report.py       # CSV summary for tooling
│       ├── cyclonedx_sbom.py   # CycloneDX 1.5 SBOM
│       └── spdx_sbom.py        # SPDX 2.3 SBOM
```

---

## Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              HARDENCHECK FLOW                               │
└─────────────────────────────────────────────────────────────────────────────┘

    ┌──────────────┐
    │   FIRMWARE   │
    │  (extracted) │
    └──────┬───────┘
           │
           ▼
┌─────────────────────┐
│   FILE DISCOVERY    │
│  ─────────────────  │
│  • ELF Binaries     │
│  • Source Files     │
│  • Config Files     │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  FIRMWARE PROFILE   │
│  ─────────────────  │
│  • Architecture     │
│  • Libc / Kernel    │
│  • SSL / Web / SSH  │
│  • Firmware Type    │
└──────────┬──────────┘
           │
           ▼
┌───────────────────────────────────────────────────────────────────────────┐
│                           SECURITY ANALYSIS                               │
├──────────────┬──────────────┬──────────────┬──────────────┬───────────────┤
│              │              │              │              │               │
▼              ▼              ▼              ▼              ▼               │
┌───────────┐ ┌───────────┐ ┌────────────┐ ┌────────────┐ ┌──────────────┐  │
│  BINARY   │ │   ASLR    │ │   DAEMON   │ │   BANNED   │ │ SECRETS SCAN │  │
│ HARDENING │ │  ENTROPY  │ │ DETECTION  │ │ FUNCTIONS  │ │ ──────────── │  │
│ ───────── │ │ ───────── │ │ ────────── │ │ ────────── │ │ • Creds      │  │
│ • NX      │ │ • ELF hdr │ │ • telnetd  │ │ • gets()   │ │ • Certs      │  │
│ • Canary  │ │ • Entropy │ │ • httpd    │ │ • strcpy() │ │ • Configs    │  │
│ • PIE     │ │ • Rating  │ │ • sshd     │ │ • sprintf()│ │ • Deps       │  │
│ • RELRO   │ │ • x86/ARM │ │ • ftpd     │ │ • system() │ └──────────────┘  │
│ • Fortify │ │ • MIPS/RV │ │ • snmpd    │ │ • rand()   │                   │
│ • CFI     │ │ • PPC     │ │ • upnpd    │ │ • mktemp() │                   │
└─────┬─────┘ └─────┬─────┘ └─────┬──────┘ └─────┬──────┘                   │
      │             │             │              │                          │
      └──────┬──────┴─────────────┴──────────────┘                          │
             │                                                              │
             ▼                                                              │
┌───────────────────────────────────────────────────────────────────────────┤
│                    ADVANCED SECURITY CHECKS                               │
│  ─────────────────────────────────────────                                │
│  • Cryptographic Binary Analysis (purpose, flags, risk)                   │
│  • Firmware Signing & Secure Boot Verification                           │
│  • Service Privilege & Isolation Audit                                    │
│  • Kernel Hardening (KASLR, SMEP, SMAP, stack protector)                 │
│  • OTA / Update Mechanism Security                                       │
│  • Vulnerable Version Detection (CVE patterns)                           │
│  • Default Credential Checks                                             │
├───────────────────────────────────────────────────────────────────────────┤
│                        SBOM GENERATION                                    │
│  ─────────────────────────────────────────                                │
│  Layer 1: Package Manager (opkg / dpkg)                                   │
│  Layer 2: ELF Analysis (NEEDED + soname + strings)                        │
│  Layer 3: Firmware Profile (kernel, busybox, known components)            │
│                                                                           │
│  • CPE 2.3 mapping (90+ IoT components)                                   │
│  • PURL generation                                                        │
│  • License resolution                                                     │
│  • Dependency tree (binary → NEEDED libs)                                 │
│  • Security flags per component                                           │
└──────────────────────┬────────────────────────────────────────────────────┘
                       │
                       ▼
          ┌─────────────────────┐
          │   CLASSIFICATION    │
          │  ─────────────────  │
          │  SECURED            │
          │  PARTIAL            │
          │  INSECURE           │
          └──────────┬──────────┘
                     │
                     ▼
          ┌─────────────────────┐
          │    GRADE (A-F)      │
          │  ─────────────────  │
          │  A: >= 90 /100      │
          │  B: >= 80 /100      │
          │  C: >= 70 /100      │
          │  D: >= 60 /100      │
          │  F: <  60 /100      │
          └──────────┬──────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│                           OUTPUT                                │
├───────────┬───────────┬──────────┬──────────┬─────────┬─────────┤
│  HTML     │  JSON     │ CycloneDX│  SPDX    │  Text   │  CSV    │
│  Report   │  Report   │ 1.5 SBOM │ 2.3 SBOM │ Summary │ Summary │
│ (sidebar, │ (machine  │(Grype,   │(ISO 5962)│  (CI)   │  (CI)   │
│  toggles) │ readable) │ Trivy)   │          │         │         │
└───────────┴───────────┴──────────┴──────────┴─────────┴─────────┘
```

---

## Quick Start

```bash
# 1. Install dependencies
# radare2: https://github.com/radareorg/radare2/releases
sudo apt install devscripts pax-utils elfutils binutils openssl

# 2. Clone & run
git clone https://github.com/v33ru/hardencheck.git
cd hardencheck
python3 hardencheck.py /path/to/firmware -o report.html --json

# 3. With SBOM
python3 hardencheck.py /path/to/firmware --sbom all --json

# 4. As a Python module
python3 -m hardencheck /path/to/firmware -o report.html
```

---

## Features

| Feature | Description |
|---------|-------------|
| **Binary Hardening** | NX, Canary, PIE, RELRO, Fortify, CFI, Stack Clash |
| **ASLR Entropy** | ELF header parsing, effective entropy per arch (x86/ARM/MIPS/RISC-V/PPC) |
| **Daemon Detection** | 95+ known services, network symbols, init script cross-reference |
| **Banned Functions** | gets, strcpy, sprintf, system, rand, mktemp + CWE/OWASP mapping |
| **Credential Scan** | Hardcoded passwords, API keys, AWS secrets, private keys |
| **Certificate Scan** | Expiry, key size, self-signed, PKCS12 analysis |
| **Config Analysis** | SSH, Telnet, debug mode, empty passwords |
| **Dependency Risks** | Insecure shared library chain tracking |
| **Crypto Binary Audit** | Cryptographic utility purpose, risk level, security flags |
| **Firmware Signing** | Secure boot verification, signature file detection |
| **Service Privileges** | Root service audit, capability analysis, isolation checks |
| **Kernel Hardening** | KASLR, SMEP/SMAP, stack protector, fortify, dmesg |
| **Update Mechanism** | OTA security, HTTPS, signing, rollback protection |
| **Vuln Versions** | CVE pattern matching, weak crypto detection, default creds |
| **PQC Readiness** | Post-quantum crypto assessment: detects RSA/ECDSA/DH usage, checks for ML-KEM/ML-DSA/SLH-DSA adoption |
| **SBOM Generation** | CycloneDX 1.5 + SPDX 2.3, CPE 2.3, PURL, licenses, dependency tree |
| **Cross-Validation** | Up to 4 tools per binary, confidence scoring (rabin2 x readelf x scanelf) |

---

## Usage

```bash
# Basic scan
python3 hardencheck.py /opt/firmware/squashfs-root

# Full audit
python3 hardencheck.py /opt/firmware/squashfs-root \
    -o audit.html --json --sbom all -t 8 -v --extended

# CycloneDX SBOM only (feed into Grype/Trivy)
python3 hardencheck.py /opt/firmware/squashfs-root --sbom cyclonedx

# SPDX SBOM only (regulatory compliance)
python3 hardencheck.py /opt/firmware/squashfs-root --sbom spdx

# CI pipeline with grade gate
python3 hardencheck.py /opt/firmware/squashfs-root --fail-on-grade B -q

# Text / CSV summary for CI
python3 hardencheck.py /opt/firmware/squashfs-root --summary text
python3 hardencheck.py /opt/firmware/squashfs-root --summary csv

# Filter specific paths
python3 hardencheck.py /opt/firmware/squashfs-root \
    --include 'bin/*' --include 'usr/sbin/*' --exclude 'usr/lib/*'

# As a Python module
python3 -m hardencheck /opt/firmware/squashfs-root -o report.html
```

| Flag | Description |
|------|-------------|
| `-o`, `--output` | HTML report path (default: `hardencheck_report.html`) |
| `-t`, `--threads` | Analysis threads, 1-16 (default: 4) |
| `-v`, `--verbose` | Verbose debug output |
| `-q`, `--quiet` | Suppress banner and progress; print only report paths (CI mode) |
| `--json` | Also generate JSON report |
| `--slim` | Minimal CSS for smaller HTML |
| `--extended` | Enable Stack Clash + CFI checks (requires `hardening-check`) |
| `--sbom` | Generate SBOM: `cyclonedx`, `spdx`, or `all` |
| `--summary` | Generate plain-text or CSV summary: `text` or `csv` |
| `--fail-on-grade` | Exit code 1 if grade below threshold (e.g. `--fail-on-grade B`) |
| `--include` | Only scan paths matching GLOB (repeatable) |
| `--exclude` | Skip paths matching GLOB (repeatable) |
| `--version` | Print version and exit |

---

## Output Example

```
Grade: D (Score: 56/100)

Binaries:     847 (12 secured, 156 partial, 679 insecure)
ASLR Analysis:12 PIE binaries analyzed
Daemons:      18 detected
Dependencies: 5 risks
Banned Funcs: 423 hits
Credentials:  7 findings
Certificates: 14 files
Config Issues:9 findings
SBOM:         142 components (119 with CPE)

Duration: 34.2s

[+] HTML Report: audit_report.html
[+] JSON Report: audit_report.json
[+] CycloneDX 1.5 SBOM: audit_report_sbom_cyclonedx.json
[+] SPDX 2.3 SBOM: audit_report_sbom_spdx.json
```

---

## HTML Report

Interactive HTML report with sidebar navigation, collapsible sections, executive summary, and print support.

| Feature | Description |
|---------|-------------|
| **Sidebar** | Fixed left navigation with section links and active highlight |
| **Executive Summary** | Security score /100, grade, severity counters, top 5 findings |
| **Toggle Sections** | Collapsible cards with arrow buttons for each section |
| **Search & Filter** | In-table search across binary analysis, SBOM, and classification |
| **Print Report** | Print button outputs full expanded report |

**Report Sections:**

| # | Section |
|---|---------|
| 1 | Executive Summary (score, grade, severity counters, top findings) |
| 2 | Firmware Profile (24-field fingerprint) |
| 3 | Binary Hardening (protection matrix with search) |
| 4 | ASLR Entropy Analysis (per-binary entropy & rating) |
| 5 | Network Services & Daemons |
| 6 | Kernel Hardening Configuration |
| 7 | Firmware Signing & Secure Boot |
| 8 | Dependency Risks |
| 9 | Banned Functions |
| 10 | Vulnerable Versions & Security Tests |
| 11 | Hardcoded Credentials |
| 12 | Certificates & Keys |
| 13 | Configuration Issues |
| 14 | Post-Quantum Crypto Readiness (per-binary PQC assessment) |
| 15 | SBOM Components (searchable + type filter) |
| 16 | Classification (SECURED / PARTIAL / INSECURE) |

---

## SBOM

Three-layer detection with industry-standard output:

| Layer | Source | Confidence |
|-------|--------|------------|
| Package Manager | opkg / dpkg status files | Highest |
| ELF Analysis | readelf NEEDED + soname + strings | High |
| Firmware Profile | Kernel, BusyBox, known components | Medium |

| Output | Format | Use Case |
|--------|--------|----------|
| CycloneDX 1.5 | JSON | Grype, Trivy, OWASP Dependency-Track |
| SPDX 2.3 | JSON | ISO/IEC 5962 compliance, license audit |
| JSON (embedded) | HardenCheck | `--json` report under `sbom` key |
| HTML (embedded) | Interactive | Summary + table + dep tree in report |

CPE 2.3 mapping for 90+ components: BusyBox, OpenSSL, curl, dnsmasq, dropbear, nginx, mosquitto, hostapd, zlib, libxml2, SQLite, iptables, and more.

---

## Scoring

Score is normalized to **/100** in the HTML report.

| Protection | Points |
|------------|--------|
| NX | 15 |
| Stack Canary | 15 |
| PIE | 15 |
| Full RELRO | 15 |
| Fortify | 10 |
| Stack Clash | 10 |
| CFI | 10 |
| Stripped | 5 |
| No TEXTREL | 5 |
| No RPATH | 5 |
| **Max (raw)** | **110** |

| Grade | Threshold |
|-------|-----------|
| **A** | >= 90 /100 |
| **B** | >= 80 /100 |
| **C** | >= 70 /100 |
| **D** | >= 60 /100 |
| **F** | < 60 /100 |

---

## Programmatic API

```python
from hardencheck import HardenCheck, ScanResult

scanner = HardenCheck("/path/to/firmware", threads=8, extended=True)
result = scanner.scan()

print(f"Grade: {result.profile.arch}")
print(f"Binaries: {len(result.binaries)}")
print(f"Daemons: {len(result.daemons)}")
```

---

## Dependencies

**Python:** stdlib only (3.7+), zero pip installs.

**System Tools:**

| Tool | Package | Priority |
|------|---------|----------|
| `readelf` | `binutils` / `elfutils` | Critical |
| `file` | `file` | High |
| `strings` | `binutils` | High |
| `rabin2` | `radare2` | Medium |
| `hardening-check` | `devscripts` | Medium |
| `scanelf` | `pax-utils` | Low |
| `openssl` | `openssl` | Low |

```bash
sudo apt install binutils elfutils file radare2 devscripts pax-utils openssl
```

> Degrades gracefully — missing tools reduce confidence scores, not crash.

---

## License

[MIT](LICENSE) - @v33ru | IOTSRG
