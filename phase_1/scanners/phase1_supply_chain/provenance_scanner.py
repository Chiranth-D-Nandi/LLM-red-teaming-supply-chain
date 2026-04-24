"""
Growler Security v2 — Provenance Scanner.

Checks model card contents for required sections and license file existence.
"""

from phase_1.scanners.base_scanner import BaseScanner

REQUIRED_SECTIONS = [
    'intended use', 'limitations', 'training data',
    'evaluation', 'ethical',
]


class ProvenanceScanner(BaseScanner):

    def scan(self, manifest):
        findings = []

        card = manifest.model_card_text

        if card is None:
            findings.append(self._make_finding(
                'MEDIUM', 'PROV-001',
                'No model card found — origin and intended use unknown',
                'README.md', owasp='LLM03',
            ))
            return findings

        #check for required documentation sections
        card_lower = card.lower()
        for section in REQUIRED_SECTIONS:
            if section not in card_lower:
                findings.append(self._make_finding(
                    'LOW', 'PROV-002',
                    f'Model card missing section: "{section}"',
                    'README.md', owasp='LLM03',
                ))

        #check license
        has_license = any(
            f.name.upper().startswith('LICENSE')
            for f in manifest.files
        )
        if not has_license:
            findings.append(self._make_finding(
                'MEDIUM', 'PROV-003',
                'No license file — legal risk for deployment',
                'LICENSE', owasp='LLM09',
            ))

        return findings
