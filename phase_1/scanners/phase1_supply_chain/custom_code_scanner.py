"""
Growler Security v2 — Custom Code Scanner (AST-based).

Downloads .py files (via manifest.python_files), walks their AST looking for
dangerous function calls: critical sinks, network calls, and dangerous builtins.
"""

import ast
from phase_1.scanners.base_scanner import BaseScanner

CRITICAL_SINKS = {
    ('os', 'system'), ('os', 'popen'), ('subprocess', 'Popen'),
    ('subprocess', 'call'), ('subprocess', 'run'),
    ('commands', 'getoutput'),
}

HIGH_SINKS = {
    ('requests', 'get'), ('requests', 'post'), ('urllib', 'request'),
    ('socket', 'socket'), ('urllib', 'urlopen'),
}

DANGEROUS_BUILTINS = {'eval', 'exec', 'compile', '__import__'}


class CustomCodeScanner(BaseScanner):

    def scan(self, manifest):
        findings = []
        for filename, source in manifest.python_files.items():
            findings.extend(self._audit_file(filename, source))
        return findings

    def _audit_file(self, filename, source):
        findings = []
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                #check attribute calls like os.system()
                if isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name):
                        pair = (node.func.value.id, node.func.attr)
                        if pair in CRITICAL_SINKS:
                            findings.append(self._make_finding(
                                'CRITICAL', 'GROWLER-CODE-001',
                                f'Dangerous call: {pair[0]}.{pair[1]}()',
                                filename,
                                line=node.lineno,
                                owasp='LLM05', cwe='CWE-829',
                            ))
                        elif pair in HIGH_SINKS:
                            findings.append(self._make_finding(
                                'HIGH', 'GROWLER-CODE-002',
                                f'Outbound network call: {pair[0]}.{pair[1]}()',
                                filename,
                                line=node.lineno,
                                owasp='LLM05', cwe='CWE-829',
                            ))

                #check builtins like eval(), exec()
                elif isinstance(node.func, ast.Name):
                    if node.func.id in DANGEROUS_BUILTINS:
                        findings.append(self._make_finding(
                            'CRITICAL', 'GROWLER-CODE-003',
                            f'Dangerous builtin: {node.func.id}()',
                            filename,
                            line=node.lineno,
                            owasp='LLM05', cwe='CWE-829',
                        ))
        return findings
