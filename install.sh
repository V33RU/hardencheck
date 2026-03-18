#!/usr/bin/env bash
# =============================================================================
#  HardenCheck — Full Installer
#  Supported: macOS | Ubuntu 24.04 | Debian 12 | Arch Linux / Manjaro
#
#  No venv needed — HardenCheck has zero pip dependencies (pure stdlib).
#  This script installs system tools then registers the `hardencheck` command.
# =============================================================================
set -euo pipefail

# ── colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()  { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
die()   { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }

# ── banner ───────────────────────────────────────────────────────────────────
echo -e "${BOLD}"
cat <<'EOF'
    ╔════════════════════════════════════════╗
    ║   H A R D E N C H E C K  Installer     ║
    ║   Firmware Security Analyzer v1.0      ║
    ╚════════════════════════════════════════╝
EOF
echo -e "${NC}"

# ── parse flags ──────────────────────────────────────────────────────────────
DRY_RUN=0
EDITABLE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)     DRY_RUN=1 ;;
        --editable|-e) EDITABLE=1 ;;
        --help|-h)
            echo "Usage: $0 [--dry-run] [--editable|-e]"
            echo
            echo "  --dry-run     Print commands without executing them"
            echo "  --editable    pip install -e . (useful for development)"
            exit 0 ;;
        *) warn "Unknown flag: $1" ;;
    esac
    shift
done

run() {
    echo -e "  ${CYAN}\$${NC} $*"
    [[ $DRY_RUN -eq 0 ]] && eval "$@"
}

# ── helpers ───────────────────────────────────────────────────────────────────
have() { command -v "$1" &>/dev/null; }

require_python() {
    for candidate in python3.12 python3.11 python3.10 python3.9 python3 python; do
        if have "$candidate"; then
            if "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3,9) else 1)' 2>/dev/null; then
                echo "$candidate"
                return
            fi
        fi
    done
    die "Python 3.9+ not found. Please install it first."
}

# ── detect OS ────────────────────────────────────────────────────────────────
OS="$(uname -s)"
DISTRO="unknown"

if [[ "$OS" == "Linux" && -f /etc/os-release ]]; then
    source /etc/os-release
    ID_LOWER="${ID,,}"
    ID_LIKE_LOWER="${ID_LIKE:-}"
    if [[ "$ID_LOWER" == "ubuntu" || "$ID_LOWER" == "debian" || "$ID_LIKE_LOWER" == *"debian"* ]]; then
        DISTRO="debian"
    elif [[ "$ID_LOWER" == "arch" || "$ID_LOWER" == "manjaro" || "$ID_LOWER" == "endeavouros" || "$ID_LIKE_LOWER" == *"arch"* ]]; then
        DISTRO="arch"
    fi
fi
# Fallback by package manager
if [[ "$DISTRO" == "unknown" && "$OS" == "Linux" ]]; then
    have apt-get && DISTRO="debian"
    have pacman  && DISTRO="arch"
fi
[[ "$OS" == "Darwin" ]] && DISTRO="macos"

info "Detected platform: ${BOLD}${OS}${NC} / ${BOLD}${DISTRO}${NC}"

# =============================================================================
#  1. SYSTEM TOOLS
# =============================================================================

install_debian() {
    info "Installing system tools via apt-get (Ubuntu 24.04 / Debian 12) ..."
    run "sudo apt-get update -qq"
    run "sudo apt-get install -y \
        binutils \
        elfutils \
        file \
        pax-utils \
        openssl \
        devscripts \
        radare2 \
        python3 \
        python3-pip"
    ok "apt-get install complete."
}

install_arch() {
    info "Installing system tools via pacman (Arch Linux / Manjaro) ..."
    run "sudo pacman -Sy --noconfirm \
        binutils \
        elfutils \
        file \
        pax-utils \
        openssl \
        radare2 \
        python \
        python-pip"

    # hardening-check is in AUR
    if have yay || have paru; then
        local aur_helper
        have yay && aur_helper="yay" || aur_helper="paru"
        info "Installing hardening-check from AUR via ${aur_helper} ..."
        run "$aur_helper -S --noconfirm hardening-check"
    else
        warn "No AUR helper found. Skipping hardening-check (optional)."
        warn "Install later with: yay -S hardening-check"
    fi
    ok "pacman install complete."
}

install_macos() {
    info "Installing system tools via Homebrew (macOS) ..."
    if ! have brew; then
        die "Homebrew not found. Install it first:
  /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
    fi

    run "brew update --quiet"
    run "brew install binutils openssl radare2"

    warn "scanelf (pax-utils) and hardening-check are Linux-only — skipped on macOS."

    # GNU binutils installs as greadelf/gstrings — symlink to plain names
    local brew_prefix
    brew_prefix="$(brew --prefix)"
    local gnu_bin="${brew_prefix}/opt/binutils/bin"
    local link_dir="${brew_prefix}/bin"

    for pair in "greadelf readelf" "gstrings strings" "gobjdump objdump"; do
        local src_name="${pair%% *}" dst_name="${pair##* }"
        local src="${gnu_bin}/${src_name}" dst="${link_dir}/${dst_name}"
        if [[ -f "$src" && ! -e "$dst" ]]; then
            info "Symlinking ${src_name} → ${dst_name}"
            run "ln -sf \"$src\" \"$dst\""
        fi
    done
    ok "Homebrew install complete."
}

case "$DISTRO" in
    debian) install_debian ;;
    arch)   install_arch   ;;
    macos)  install_macos  ;;
    *)
        warn "Unrecognised distro. Skipping system tool install."
        warn "Please install manually: binutils elfutils file openssl pax-utils radare2"
        ;;
esac

# =============================================================================
#  2. INSTALL PYTHON PACKAGE  (no venv — pure stdlib, nothing to isolate)
# =============================================================================

PYTHON=$(require_python)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

info "Using Python: $("$PYTHON" --version) at $(command -v $PYTHON)"
info "Project root: ${SCRIPT_DIR}"

PIP_FLAGS="--quiet"
# Ubuntu/Debian 24.04+ enforce PEP 668 (externally-managed-environment).
# --break-system-packages lets pip install into the system site-packages,
# which is safe here because we have no third-party deps to conflict with.
if "$PYTHON" -m pip install --help 2>&1 | grep -q "break-system-packages"; then
    PIP_FLAGS="$PIP_FLAGS --break-system-packages"
fi

if [[ $EDITABLE -eq 1 ]]; then
    info "Installing HardenCheck in editable mode ..."
    run "\"$PYTHON\" -m pip install $PIP_FLAGS -e \"${SCRIPT_DIR}\""
else
    info "Installing HardenCheck ..."
    run "\"$PYTHON\" -m pip install $PIP_FLAGS \"${SCRIPT_DIR}\""
fi

# =============================================================================
#  3. VERIFY TOOLS
# =============================================================================

echo
info "Tool availability summary:"

declare -A TOOL_CANDIDATES=(
    ["readelf"]="eu-readelf readelf greadelf"
    ["strings"]="strings gstrings"
    ["file"]="file"
    ["openssl"]="openssl"
    ["scanelf"]="scanelf"
    ["rabin2"]="rabin2"
    ["hardening-check"]="hardening-check"
)

ALL_REQUIRED_OK=1

for label in readelf strings file openssl scanelf rabin2 "hardening-check"; do
    candidates="${TOOL_CANDIDATES[$label]}"
    found=""
    for c in $candidates; do
        if have "$c"; then
            found="$(command -v $c)"
            break
        fi
    done

    if [[ -n "$found" ]]; then
        echo -e "  ${GREEN}✓${NC}  ${BOLD}${label}${NC}  →  ${found}"
    else
        case "$label" in
            readelf|strings|file)
                echo -e "  ${RED}✗${NC}  ${BOLD}${label}${NC}  →  MISSING (REQUIRED)"
                ALL_REQUIRED_OK=0
                ;;
            *)
                echo -e "  ${YELLOW}–${NC}  ${BOLD}${label}${NC}  →  not found (optional)"
                ;;
        esac
    fi
done

# =============================================================================
#  4. DONE
# =============================================================================

echo
if [[ $ALL_REQUIRED_OK -eq 1 ]]; then
    ok "HardenCheck installed successfully!"
else
    warn "Some required tools are missing — see above."
fi

echo
echo -e "${BOLD}Run:${NC}  ${CYAN}hardencheck /path/to/extracted-firmware${NC}"
echo
