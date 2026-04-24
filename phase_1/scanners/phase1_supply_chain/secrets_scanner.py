"""
Growler Security v2 — Secrets Scanner.

Scans file CONTENTS (not names!) for leaked secrets using regex patterns
and Shannon entropy analysis for unknown secret formats.
"""

import re
import math
from collections import Counter
from phase_1.scanners.base_scanner import BaseScanner

SECRET_PATTERNS = {
    'aws_key': r'AKIA[0-9A-Z]{16}',
    'github_token': r'ghp_[A-Za-z0-9]{36}',
    'openai_key': r'sk-[A-Za-z0-9]{48}',
    'hf_token': r'hf_[A-Za-z0-9]{34}',
    'private_key': r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
    'generic_password': r'(?i)(password|passwd|secret|token)\s*[=:]\s*["\'][^"\']{6,}["\']',
    'connection_string': r'(?i)(mongodb|postgres|mysql|redis):\/\/[^\s]+',
}

TEXT_EXTENSIONS = {'py', 'txt', 'yaml', 'yml', 'json', 'md', 'env', 'cfg', 'ini', 'toml'}


class SecretsScanner(BaseScanner):

    def scan(self, manifest):
        findings = []

        for file in manifest.files:
            if file.content and file.file_type in TEXT_EXTENSIONS:
                findings.extend(self._scan_content(file.content, file.name))

        return findings

    def _scan_content(self, content, filename):
        findings = []

        #pattern matching
        for secret_type, pattern in SECRET_PATTERNS.items():
            for m in re.finditer(pattern, content):
                val = m.group(0)
                redacted = val[:4] + '****' + val[-4:] if len(val) > 8 else '****'
                findings.append(self._make_finding(
                    'CRITICAL', 'GROWLER-SEC-001',
                    f'Possible {secret_type} detected: {redacted}',
                    filename, cwe='CWE-312', owasp='LLM06',
                ))

        #entropy analysis — catches unknown secret formats
        for lineno, line in enumerate(content.splitlines(), 1):
            for token in re.findall(r'[A-Za-z0-9+/]{20,}', line):
                if self._entropy(token) > 4.5 and len(token) >= 24:
                    redacted = token[:4] + '****' + token[-4:]
                    findings.append(self._make_finding(
                        'HIGH', 'GROWLER-SEC-002',
                        f'High-entropy string (possible secret): {redacted}',
                        filename, line=lineno, cwe='CWE-312', owasp='LLM06',
                    ))

        return findings

    @staticmethod
    def _entropy(s):
        """Calculate Shannon entropy of a string."""
        if not s:
            return 0.0
        counts = Counter(s)
        total = len(s)
        return -sum((c / total) * math.log2(c / total) for c in counts.values())
