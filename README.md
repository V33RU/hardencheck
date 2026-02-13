<p align="center">
  <strong>HardenCheck</strong>
</p>

<p align="center">
  <strong>Firmware binary security analyzer with ASLR entropy analysis &amp; SBOM generation.</strong>
</p>

<p align="center">
  <a href="https://github.com/v33ru/hardencheck">
    <img src="https://img.shields.io/badge/version-1.0-blue.svg" />
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
          │  🟢 SECURED         │
          │  🟡 PARTIAL         │
          │  🔴 INSECURE        │
          └──────────┬──────────┘
                     │
                     ▼
          ┌─────────────────────┐
          │    GRADE (A-F)      │
          │  ─────────────────  │
          │  A: 90-110 pts      │
          │  B: 80-89 pts       │
          │  C: 70-79 pts       │
          │  D: 60-69 pts       │
          │  F: 0-59 pts        │
          └──────────┬──────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│                           OUTPUT                                │
├───────────────┬───────────────┬─────────────────┬───────────────┤
│  HTML Report  │  JSON Report  │  CycloneDX 1.5  │  SPDX 2.3     │
│  (Interactive │  (Machine     │  SBOM           │  SBOM         │
│   + Search)   │   Readable)   │  (→ Grype/Trivy)│  (ISO 5962)   │
└───────────────┴───────────────┴─────────────────┴───────────────┘
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
```
---

## Features

| Feature | Description |
|---------|-------------|
| **Binary Hardening** | NX, Canary, PIE, RELRO, Fortify, CFI, Stack Clash |
| **ASLR Entropy** | ELF header parsing → effective entropy per arch (x86/ARM/MIPS/RISC-V/PPC) |
| **Daemon Detection** | 95+ known services, network symbols, init script cross-reference |
| **Banned Functions** | gets, strcpy, sprintf, system, rand, mktemp + CWE/OWASP mapping |
| **Credential Scan** | Hardcoded passwords, API keys, AWS secrets, private keys |
| **Certificate Scan** | Expiry, key size, self-signed, PKCS12 analysis |
| **Config Analysis** | SSH, Telnet, debug mode, empty passwords |
| **Dependency Risks** | Insecure shared library chain tracking |
| **SBOM Generation** | CycloneDX 1.5 + SPDX 2.3, CPE 2.3, PURL, licenses, dependency tree |
| **Cross-Validation** | Up to 4 tools per binary, confidence scoring (rabin2 × readelf × scanelf) |

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
```

| Flag | Description |
|------|-------------|
| `-o`, `--output` | HTML report path (default: `hardencheck_report.html`) |
| `-t`, `--threads` | Analysis threads, 1–16 (default: 4) |
| `-v`, `--verbose` | Verbose debug output |
| `--json` | Generate JSON report |
| `--slim` | Minimal CSS for smaller HTML |
| `--extended` | Enable Stack Clash + CFI checks |
| `--sbom` | Generate SBOM: `cyclonedx`, `spdx`, or `all` |

---

## Output Example

```
Grade: D (Score: 62/110)

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

## HTML Report (16 Sections)

| # | Section |
|---|---------|
| 1 | Security Grade (A–F) |
| 2 | Firmware Profile (24-field fingerprint) |
| 3 | Protection Coverage (progress bars) |
| 4 | ASLR Entropy Summary |
| 5 | ASLR Entropy Table (per-binary) |
| 6 | Daemons & Services |
| 7 | Dependency Risks |
| 8 | Binary Analysis (hardening matrix) |
| 9 | Banned Functions |
| 10 | Hardcoded Credentials |
| 11 | Certificates & Keys |
| 12 | Configuration Issues |
| 13 | SBOM Summary |
| 14 | SBOM Components (searchable + filter) |
| 15 | Dependency Tree (binary → NEEDED libs) |
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
| **Total** | **110** |

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

> Degrades gracefully-missing tools reduce confidence scores, not crash.
