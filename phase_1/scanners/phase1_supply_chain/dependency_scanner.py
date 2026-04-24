"""
Growler Security v2 — Dependency Scanner.

Parses requirements.txt, calls OSV.dev API per package, returns CVE data.
"""

import re
import requests
from phase_1.scanners.base_scanner import BaseScanner


class DependencyScanner(BaseScanner):

    OSV_URL = 'https://api.osv.dev/v1/query'

    def scan(self, manifest):
        findings = []

        if not manifest.requirements_lines:
            return findings

        for line in manifest.requirements_lines:
            name, version = self._parse_dep(line)

            if not name:
                continue

            if not version:
                findings.append(self._make_finding(
                    'MEDIUM', 'GROWLER-DEP-001',
                    f'Unpinned dependency: {name}',
                    'requirements.txt',
                    owasp='LLM05', cwe='CWE-937',
                ))
                continue

            vulns = self._query_osv(name, version)
            for v in vulns:
                findings.append(self._make_finding(
                    self._osv_severity(v), 'GROWLER-DEP-002',
                    f'{name}=={version} has {v["id"]}: {v.get("summary", "")[:100]}',
                    'requirements.txt',
                    owasp='LLM05', cwe='CWE-937',
                    cve_id=v['id'],
                ))

        return findings

    def _parse_dep(self, line):
        """parse dependency line. returns (name, version) or (name, none)."""
        #package==1.0, package>=1.0, package~=1.0
        m = re.match(r'^([A-Za-z0-9_.\-]+)\s*[=~><!]+\s*([A-Za-z0-9._\-]+)', line)
        if m:
            return m.group(1), m.group(2)
        m = re.match(r'^([A-Za-z0-9_.\-]+)$', line)
        if m:
            return m.group(1), None
        return None, None

    def _query_osv(self, package, version):
        """query osv.dev for known vulnerabilities."""
        try:
            r = requests.post(
                self.OSV_URL,
                json={
                    'package': {'name': package, 'ecosystem': 'PyPI'},
                    'version': version,
                },
                timeout=10,
            )
            return r.json().get('vulns', []) if r.ok else []
        except Exception:
            return []

    def _osv_severity(self, vuln):
        """Map OSV severity to our severity levels."""
        severity = vuln.get('database_specific', {}).get('severity', '')
        return {
            'CRITICAL': 'CRITICAL',
            'HIGH': 'HIGH',
            'MODERATE': 'MEDIUM',
            'LOW': 'LOW',
        }.get(severity, 'MEDIUM')
