"""
HardenCheck — Firmware Binary Security Analyzer
Setup script for: macOS, Ubuntu 24.04, Debian 12, Arch Linux

Usage
-----
  # Standard install (Python package only):
  pip install .

  # Development / editable install:
  pip install -e .

  # Install system tool dependencies then the package:
  python setup.py install_system_deps
  pip install .   # or: pip install --break-system-packages .

System tools required (installed automatically by install.sh):
  readelf / eu-readelf  — ELF binary inspection
  strings               — Extract printable strings from binaries
  file                  — Binary type identification
  openssl               — Certificate inspection
  scanelf               — PaX/security flags (Linux only)
  rabin2 (radare2)      — Advanced binary analysis (optional but recommended)
  hardening-check       — Hardening flag checker (Linux/Debian/Arch only)
"""

import subprocess
import sys
import platform
import shutil
from setuptools import setup, find_packages, Command


# ---------------------------------------------------------------------------
# Project metadata
# ---------------------------------------------------------------------------

with open("hardencheck/constants/core.py") as f:
    for line in f:
        if line.startswith("VERSION"):
            VERSION = line.split("=")[1].strip().strip('"').strip("'")
            break
    else:
        VERSION = "1.0"

try:
    with open("LICENSE") as f:
        LICENSE_TEXT = f.read()
except FileNotFoundError:
    LICENSE_TEXT = "GPL-3.0"


# ---------------------------------------------------------------------------
# Custom command: install_system_deps
# ---------------------------------------------------------------------------

class InstallSystemDeps(Command):
    """Install system-level binary analysis tools for the current platform."""

    description = "Install required system tools (readelf, strings, file, etc.)"
    user_options = [
        ("dry-run", None, "Print commands without executing them"),
    ]

    def initialize_options(self):
        self.dry_run = False

    def finalize_options(self):
        pass

    def run(self):
        os_name = platform.system()
        if os_name == "Linux":
            self._install_linux()
        elif os_name == "Darwin":
            self._install_macos()
        else:
            print(f"[!] Unsupported platform: {os_name}")
            print("    Please install the following tools manually:")
            print("    binutils, elfutils, file, openssl, radare2, pax-utils")
            sys.exit(1)

    def _run(self, cmd):
        print(f"  $ {' '.join(cmd)}")
        if not self.dry_run:
            result = subprocess.run(cmd)
            if result.returncode != 0:
                print(f"[!] Command failed (exit {result.returncode}): {' '.join(cmd)}")
                print("    You may need to run this with sudo or install manually.")

    def _detect_linux_distro(self):
        """Return one of: debian, arch, unknown."""
        try:
            with open("/etc/os-release") as f:
                content = f.read().lower()
            if "ubuntu" in content or "debian" in content:
                return "debian"
            if "arch" in content or "manjaro" in content or "endeavouros" in content:
                return "arch"
        except FileNotFoundError:
            pass
        if shutil.which("apt-get"):
            return "debian"
        if shutil.which("pacman"):
            return "arch"
        return "unknown"

    def _install_linux(self):
        distro = self._detect_linux_distro()
        print(f"[+] Detected Linux distro family: {distro}")

        if distro == "debian":
            self._install_debian()
        elif distro == "arch":
            self._install_arch()
        else:
            print("[!] Unknown Linux distro. Trying apt-get first, then pacman.")
            if shutil.which("apt-get"):
                self._install_debian()
            elif shutil.which("pacman"):
                self._install_arch()
            else:
                print("[!] No supported package manager found.")
                print("    Install manually: binutils elfutils file pax-utils openssl radare2")

    def _install_debian(self):
        """Ubuntu 24.04 / Debian 12 dependencies."""
        print("[+] Installing system tools via apt-get ...")
        self._run(["sudo", "apt-get", "update", "-qq"])
        packages = [
            # Core ELF tools
            "binutils",          # readelf, strings, objdump
            "elfutils",          # eu-readelf (often more reliable than binutils readelf)
            # File identification
            "file",
            # PaX / security flag scanner
            "pax-utils",         # scanelf
            # TLS inspection
            "openssl",
            # Hardening checks (Perl script bundled in devscripts)
            "devscripts",        # hardening-check
            # Radare2 (optional but heavily recommended)
            "radare2",
        ]
        self._run(["sudo", "apt-get", "install", "-y"] + packages)
        print("[+] apt-get install complete.")
        self._verify_tools()

    def _install_arch(self):
        """Arch Linux / Manjaro dependencies."""
        print("[+] Installing system tools via pacman ...")
        packages = [
            "binutils",          # readelf, strings
            "elfutils",          # eu-readelf
            "file",
            "pax-utils",         # scanelf
            "openssl",
            "radare2",
        ]
        self._run(["sudo", "pacman", "-Sy", "--noconfirm"] + packages)

        # hardening-check is available via AUR (hardening-check or checksec)
        if shutil.which("yay") or shutil.which("paru"):
            aur = shutil.which("yay") or shutil.which("paru")
            print("[+] Installing hardening-check from AUR ...")
            self._run([aur, "-S", "--noconfirm", "hardening-check"])
        else:
            print("[!] No AUR helper found. Skipping hardening-check (optional).")
            print("    Install manually: yay -S hardening-check")

        print("[+] pacman install complete.")
        self._verify_tools()

    def _install_macos(self):
        """macOS (Homebrew) dependencies."""
        if not shutil.which("brew"):
            print("[!] Homebrew not found. Install it first:")
            print('    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"')
            sys.exit(1)

        print("[+] Installing system tools via Homebrew ...")
        packages = [
            "binutils",          # GNU readelf, strings (installed as greadelf, gstrings)
            "openssl",
            "radare2",
            # file and strings are pre-installed on macOS
        ]
        self._run(["brew", "install"] + packages)

        # macOS note: scanelf (pax-utils) and hardening-check are Linux-only.
        # The tool handles their absence gracefully.
        print("[!] Note: scanelf and hardening-check are Linux-only tools.")
        print("    HardenCheck will run without them on macOS (reduced coverage).")

        # On macOS, GNU binutils installs as greadelf, gstrings.
        # Symlink them into PATH if not already present.
        self._macos_symlink_gnu_tools()

        print("[+] Homebrew install complete.")
        self._verify_tools()

    def _macos_symlink_gnu_tools(self):
        """Create symlinks for GNU tools installed with 'g' prefix by Homebrew."""
        brew_prefix = subprocess.run(
            ["brew", "--prefix"], capture_output=True, text=True
        ).stdout.strip()
        gnu_bin = f"{brew_prefix}/opt/binutils/bin"
        local_bin = f"{brew_prefix}/bin"

        tool_map = {
            "greadelf": "readelf",
            "gstrings": "strings",
            "gobjdump": "objdump",
        }
        for src_name, dst_name in tool_map.items():
            src = f"{gnu_bin}/{src_name}"
            dst = f"{local_bin}/{dst_name}"
            if shutil.which(dst_name):
                continue
            import os
            if os.path.exists(src):
                print(f"  Symlinking {src} -> {dst}")
                if not self.dry_run:
                    try:
                        os.symlink(src, dst)
                    except FileExistsError:
                        pass
                    except PermissionError:
                        print(f"  [!] Cannot create symlink (permission denied). Run manually:")
                        print(f"      ln -s {src} {dst}")

    def _verify_tools(self):
        """Print tool availability summary after installation."""
        print()
        print("[+] Tool availability after install:")
        tools = {
            "readelf":          ["readelf", "eu-readelf", "greadelf"],
            "strings":          ["strings", "gstrings"],
            "file":             ["file"],
            "openssl":          ["openssl"],
            "scanelf":          ["scanelf"],
            "rabin2":           ["rabin2"],
            "hardening-check":  ["hardening-check"],
        }
        all_ok = True
        for label, candidates in tools.items():
            found = next((shutil.which(c) for c in candidates if shutil.which(c)), None)
            status = f"OK  ({found})" if found else "MISSING (optional)"
            if not found and label in ("readelf", "strings", "file"):
                status = "MISSING *** REQUIRED ***"
                all_ok = False
            print(f"  {label:<20} {status}")

        print()
        if all_ok:
            print("[+] All required tools found. HardenCheck is ready.")
        else:
            print("[!] Some required tools are missing. Check the output above.")


# ---------------------------------------------------------------------------
# setup()
# ---------------------------------------------------------------------------

setup(
    name="hardencheck",
    version=VERSION,
    description="Firmware Binary Security Analyzer — hardening, SBOM, CVE correlation",
    long_description=__doc__,
    author="v33ru / IOTSRG",
    license="GPL-3.0",

    python_requires=">=3.9",

    # Pure Python — all stdlib, no pip dependencies
    install_requires=[],

    packages=find_packages(
        exclude=["tests", "tests.*", "*.tests", "*.tests.*"]
    ),

    entry_points={
        "console_scripts": [
            "hardencheck=hardencheck.cli:main",
        ],
    },

    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
    ],

    cmdclass={
        "install_system_deps": InstallSystemDeps,
    },
)
