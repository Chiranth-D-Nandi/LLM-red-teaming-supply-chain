"""
growler security v2 — generation config scanner (policy-as-code).

defines security policies as data rather than hardcoded if-statements.
each policy has a name, check function, severity, and remediation text.
"""

from phase_1.scanners.base_scanner import BaseScanner

#policy-as-code: each entry is one security rule
GENERATION_POLICIES = [
    {
        'id': 'GEN-001',
        'field': 'max_new_tokens',
        'check': lambda c: c.get('max_new_tokens') is not None and c['max_new_tokens'] <= 4096,
        'severity': 'HIGH',
        'owasp': 'LLM04',
        'issue': 'max_new_tokens not set or too high — DoS risk (unbounded generation)',
    },
    {
        'id': 'GEN-002',
        'field': 'temperature',
        'check': lambda c: c.get('temperature', 1.0) <= 1.5,
        'severity': 'MEDIUM',
        'owasp': 'LLM02',
        'issue': 'temperature > 1.5 produces unpredictable, potentially unsafe outputs',
    },
    {
        'id': 'GEN-003',
        'field': 'repetition_penalty',
        'check': lambda c: c.get('repetition_penalty', 1.0) > 1.0,
        'severity': 'MEDIUM',
        'owasp': 'LLM04',
        'issue': 'No repetition penalty — adversarial inputs can trigger infinite loops',
    },
]


class GenerationConfigScanner(BaseScanner):

    def scan(self, manifest):
        findings = []

        config = manifest.generation_config

        if config is None:
            findings.append(self._make_finding(
                'MEDIUM', 'GEN-000',
                'generation_config.json missing — using model defaults',
                'generation_config.json', owasp='LLM04',
            ))
            return findings

        for policy in GENERATION_POLICIES:
            try:
                if not policy['check'](config):
                    findings.append(self._make_finding(
                        policy['severity'],
                        policy['id'],
                        policy['issue'],
                        'generation_config.json',
                        owasp=policy.get('owasp', ''),
                        actual_value=str(config.get(policy['field'], 'NOT SET')),
                    ))
            except Exception:
                pass

        return findings
