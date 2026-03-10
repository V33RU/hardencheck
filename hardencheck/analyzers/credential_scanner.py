import os
import re
from pathlib import Path
from typing import List

from hardencheck.models import Severity, CredentialFinding
from hardencheck.constants.credentials import CREDENTIAL_PATTERNS, FALSE_POSITIVE_INDICATORS, WEAK_PASSWORDS
from hardencheck.core.base import BaseAnalyzer
from hardencheck.core.utils import safe_read_file


class CredentialScanner(BaseAnalyzer):
    """Scan for hardcoded credentials."""

    def scan_credentials(self, config_files: List[Path], sources: List[Path]) -> List[CredentialFinding]:
        """Scan for hardcoded credentials."""
        findings = []
        scanned_files = set()

        skip_patterns = {
            "/locales/", "/locale/", "/i18n/", "/translations/", "/lang/",
            "translation.json", "translations.json", "messages.json",
            "/doc/", "/docs/", "/documentation/", "/examples/", "/samples/",
            "/share/doc/", "/usr/share/doc/", "/man/", "/help/",
            "README", "CHANGELOG", "LICENSE", "COPYING",
            "/test/", "/tests/", "/spec/", "/specs/", "/__tests__/",
            "_test.py", "_test.go", "_test.js", ".test.js", ".spec.js",
            "test_", "mock_", "fake_", "stub_",
            "UserInterfaceConfig.json", "device-payload",
            "/templates/", "/views/", "/layouts/",
            "package.json", "package-lock.json", "yarn.lock",
            "Cargo.lock", "go.sum", "requirements.txt", "Gemfile.lock",
            "/node_modules/", "/vendor/", "/dist/", "/build/",
            "/.git/", "/.svn/", "/.hg/",
            ".pyc", ".pyo", ".class", ".o", ".obj",
        }

        all_files = list(config_files) + list(sources)

        for root, dirs, files in os.walk(self.target):
            dirs[:] = [d for d in dirs if not d.startswith(".")][:20]
            for filename in files:
                filepath = Path(root) / filename
                if filepath.suffix in {".sh", ".py", ".pl", ".rb", ".php"}:
                    all_files.append(filepath)
                elif filename in {"config", "settings", "credentials", ".env", "secrets"}:
                    all_files.append(filepath)

        for filepath in all_files:
            if filepath in scanned_files:
                continue

            filepath_str = str(filepath)
            if any(skip in filepath_str for skip in skip_patterns):
                continue
            scanned_files.add(filepath)

            content = safe_read_file(filepath, max_size=512 * 1024)
            if not content:
                continue

            try:
                rel_path = str(filepath.relative_to(self.target))
            except ValueError:
                rel_path = str(filepath)

            lines = content.split("\n")

            for line_num, line in enumerate(lines, start=1):
                line_stripped = line.strip()

                if line_stripped.startswith("#") or line_stripped.startswith("//"):
                    continue

                for pattern, description in CREDENTIAL_PATTERNS:
                    match = re.search(pattern, line)
                    if match:
                        value = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)

                        if self._is_placeholder(value, line):
                            continue

                        if any(x in line_stripped.lower() for x in ["example", "sample", "usage:", "e.g.", "// ", "# "]):
                            continue

                        findings.append(CredentialFinding(
                            file=rel_path,
                            line=line_num,
                            pattern=description,
                            snippet=line_stripped[:80],
                            severity=Severity.HIGH
                        ))
                        break

                for weak_pass in WEAK_PASSWORDS:
                    weak_pattern = rf'(?i)(?:password|passwd|pwd|secret|key_passwd)\s*[=:]\s*["\']({re.escape(weak_pass)})["\']'
                    if re.search(weak_pattern, line):
                        if re.search(r'"Password"\s*:\s*"[^"]*"', line):
                            json_match = re.search(r'"Password"\s*:\s*"([^"]*)"', line)
                            if json_match:
                                json_value = json_match.group(1).lower()
                                if json_value not in WEAK_PASSWORDS or len(json_value) > 20:
                                    continue
                                if json_value in {"", "false", "true", "set", "get not supported"}:
                                    continue

                        findings.append(CredentialFinding(
                            file=rel_path,
                            line=line_num,
                            pattern=f"weak password: {weak_pass}",
                            snippet=line_stripped[:80],
                            severity=Severity.CRITICAL
                        ))
                        break

        return findings[:100]

    def _is_placeholder(self, value: str, line: str = "") -> bool:
        """Check if value is a placeholder, not a real credential."""
        value_lower = value.lower().strip()
        line_lower = line.lower()

        for indicator in FALSE_POSITIVE_INDICATORS:
            if indicator in line_lower:
                return True

        placeholders = {
            "xxx", "yyy", "zzz", "changeme", "placeholder", "example",
            "your_password", "your_secret", "insert_here", "todo",
            "fixme", "none", "null", "undefined", "empty", "test",
            "password", "secret", "token", "key", "value", "string",
            "change_me", "replace_me", "enter_password", "your_key",
            "default", "sample", "demo", "temp", "tmp", "foo", "bar",
            "baz", "qux", "asdf", "1234", "abcd", "testing", "development",
            "redacted", "hidden", "masked", "removed", "deleted",
            "notset", "not_set", "unset", "blank", "n/a", "na", "tbd",
        }
        if value_lower in placeholders:
            return True

        if re.match(r"^[\$%]\{?\w+\}?$", value):
            return True
        if re.match(r"^\$\(\w+\)$", value):
            return True
        if re.match(r"^<[a-zA-Z_]+>$", value):
            return True
        if re.match(r"^\{\{?\w+\}?\}$", value):
            return True
        if re.match(r"^%[a-zA-Z_]+%$", value):
            return True
        if re.match(r"^<%[=]?\s*\w+\s*%>$", value):
            return True
        if re.match(r"^\{\{\s*\w+\s*\}\}$", value):
            return True

        if len(set(value)) <= 2 and len(value) >= 3:
            return True

        if re.match(r"^[a-z_]+$", value) and len(value) < 20:
            return True

        if len(value) >= 4:
            half = len(value) // 2
            if value[:half] == value[half:2*half]:
                return True

        if re.match(r"^[./\\]", value) or value.endswith((".txt", ".json", ".xml", ".yaml", ".yml")):
            return True

        if re.match(r"^https?://", value_lower):
            return True

        if value.isdigit():
            return True

        if len(value) < 4:
            return True

        return False
