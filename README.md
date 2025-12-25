# HardenCheck v3.0

Firmware binary security analyzer using multiple tools.

## Flow

```
┌─────────────────┐
│ Target Dir      │
└────────┬────────┘
         ▼
┌─────────────────┐
│ Find ELF Files  │
└────────┬────────┘
         ▼
┌─────────────────┐
│ rabin2 -Ij      │──► NX, Canary, PIE, RELRO, Stripped, ASAN
└────────┬────────┘
         ▼
┌─────────────────┐
│ hardening-check │──► Stack Clash, CFI, Fortify
└────────┬────────┘
         ▼
┌─────────────────┐
│ scanelf         │──► TEXTREL, BIND NOW
└────────┬────────┘
         ▼
┌─────────────────┐
│ eu-readelf      │──► Fallback if rabin2 unavailable
└────────┬────────┘
         ▼
┌─────────────────┐
│ Scan Banned     │──► gets, strcpy, system, etc.
└────────┬────────┘
         ▼
┌─────────────────┐
│ Classify        │──► SECURED / PARTIAL / INSECURE
└────────┬────────┘
         ▼
┌─────────────────┐
│ HTML Report     │──► Black/White + Fira Code
└─────────────────┘
```

## Tools Required

| Tool | Package | Install |
|------|---------|---------|
| rabin2 | radare2 | `apt install radare2` or `snap install radare2 --classic` |
| hardening-check | devscripts | `apt install devscripts` |
| scanelf | pax-utils | `apt install pax-utils` |
| eu-readelf | elfutils | `apt install elfutils` |
| cppcheck | cppcheck | `apt install cppcheck` (optional) |

```bash
# Install all
sudo apt install radare2 devscripts pax-utils elfutils cppcheck
```

## Checks

| Check | Tool | Good | Bad |
|-------|------|------|-----|
| NX | rabin2 | true | false |
| Canary | rabin2 | true | false |
| PIE | rabin2 | true | false |
| RELRO | rabin2 | full | partial/none |
| Fortify | hardening-check | yes | no |
| Stripped | rabin2 | true | false |
| Stack Clash | hardening-check | yes | no/unknown |
| CFI | hardening-check | yes | no |
| TEXTREL | scanelf | none | present |
| RPATH | rabin2 | empty | set |

## Classification

- **SECURED**: All protections enabled
- **PARTIAL**: Has NX + Canary but missing others
- **INSECURE**: Missing NX or Canary

## Banned Functions

| Function | Severity | Impact | Alternative |
|----------|----------|--------|-------------|
| gets | CRITICAL | No bounds, overflow | fgets |
| strcpy | HIGH | No length limit | strlcpy |
| sprintf | HIGH | No output limit | snprintf |
| system | HIGH | Shell injection | execve |
| mktemp | HIGH | Race condition | mkstemp |
| rand | MEDIUM | Weak PRNG | getrandom |

## Usage

```bash
# Basic
python3 hardencheck.py /path/to/firmware

# With options
python3 hardencheck.py /path/to/firmware -o report.html --json -v

# Options
#   -o FILE     Output HTML (default: hardencheck_report.html)
#   -t NUM      Threads (default: 4)
#   -v          Verbose
#   --json      Also generate JSON
```

## Output

- HTML report with black/white theme and Fira Code font
- Security grade A-F
- Protection coverage bars
- Binary analysis table
- Banned functions list
- Classification summary
