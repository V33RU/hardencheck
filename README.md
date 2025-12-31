# HardenCheck

**Firmware Binary Security Analyzer**

<p align="center">
  <a href="https://github.com/v33ru/hardencheck">
    <img src="https://img.shields.io/badge/version-1.0-blue.svg" />
  </a>
  <a href="https://www.python.org/">
    <img src="https://img.shields.io/badge/python-3.8+-green.svg" />
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
│  • Libc Version     │
│  • Kernel Version   │
│  • Firmware Type    │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────────────────────────────────────────────────┐
│                      SECURITY ANALYSIS                          │
├─────────────────┬─────────────────┬─────────────────────────────┤
│                 │                 │                             │
▼                 ▼                 ▼                             ▼
┌───────────┐ ┌───────────┐ ┌───────────────┐ ┌─────────────────────┐
│  BINARY   │ │  DAEMON   │ │    BANNED     │ │   SECRETS SCAN      │
│ HARDENING │ │ DETECTION │ │   FUNCTIONS   │ │  ─────────────────  │
│ ───────── │ │ ───────── │ │  ───────────  │ │  • Credentials      │
│ • NX      │ │ • telnetd │ │  • gets()     │ │  • Certificates     │
│ • Canary  │ │ • httpd   │ │  • strcpy()   │ │  • Config Issues    │
│ • PIE     │ │ • sshd    │ │  • sprintf()  │ │  • Dependencies     │
│ • RELRO   │ │ • ftpd    │ │  • system()   │ └─────────────────────┘
│ • Fortify │ │ • snmpd   │ │  • rand()     │
│ • CFI     │ │ • upnpd   │ └───────────────┘
└─────┬─────┘ └─────┬─────┘         │
      │             │               │
      └──────┬──────┴───────────────┘
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
┌─────────────────────────────────────────┐
│               OUTPUT                    │
├───────────────┬─────────────────────────┤
│  HTML Report  │      JSON Report        │
│  (Interactive │   (Machine Readable)    │
│   + Search)   │                         │
└───────────────┴─────────────────────────┘
```

---

## Quick Start

```bash
# 1. Install dependencies
sudo apt install radare2 devscripts pax-utils elfutils binutils

# 2. Clone & run
git clone https://github.com/v33ru/hardencheck.git
cd hardencheck
python3 hardencheck.py /path/to/firmware -o report.html --json
```

---

## Features

| Feature | Description |
|---------|-------------|
| **Binary Hardening** | NX, Canary, PIE, RELRO, Fortify, CFI |
| **Daemon Detection** | Auto-detect network services + risk level |
| **Banned Functions** | gets, strcpy, sprintf, system, rand |
| **Credential Scan** | Hardcoded passwords, API keys |
| **Certificate Scan** | Private keys, expired/weak certs |
| **Config Analysis** | SSH, Telnet, debug mode issues |
| **Dependency Risks** | Insecure shared library tracking |

---

## Output Example

```
Grade: D (Score: 62/110)

Binaries:     847 (12 secured, 156 partial, 679 insecure)
Daemons:      18 detected
Banned Funcs: 423 hits
Credentials:  7 findings
Certificates: 14 files
```

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

## Author

**v33ru (Mr-IoT)**

- GitHub: [@v33ru](https://github.com/v33ru)
- Community: [IOTSRG](https://github.com/IOTSRG)

---

## License

MIT License - See [LICENSE](LICENSE)
