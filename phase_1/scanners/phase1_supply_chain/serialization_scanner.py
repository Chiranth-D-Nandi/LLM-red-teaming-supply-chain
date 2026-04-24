"""
Growler Security v2 — Serialization Scanner.

Flags unsafe serialization formats (pickle, PyTorch checkpoints) and
inspects pickle byte streams to detect dangerous GLOBAL opcodes.
"""

import pickletools
import io
from phase_1.scanners.base_scanner import BaseScanner

DANGEROUS_PICKLE_CALLS = [
    'os.system', 'os.popen', 'subprocess.Popen',
    'subprocess.call', 'subprocess.run', 'eval', 'exec',
    'builtins.exec', '__import__', 'socket.socket',
    'urllib.request', 'commands.getoutput',
]


class SerializationScanner(BaseScanner):

    def scan(self, manifest):
        findings = []

        for file in manifest.files:
            ext = file.file_type

            if ext in ['pkl', 'pickle']:
                #step 1: flag the format itself
                findings.append(self._make_finding(
                    'CRITICAL', 'GROWLER-ART-001',
                    'Unsafe pickle serialization format',
                    file.name, owasp='LLM05', cwe='CWE-502',
                ))

                #step 2: if we have bytes, inspect opcodes
                if file.content_bytes:
                    dangerous = self._inspect_pickle_opcodes(file.content_bytes)
                    for call in dangerous:
                        findings.append(self._make_finding(
                            'CRITICAL', 'GROWLER-ART-002',
                            f'Pickle file would execute: {call}',
                            file.name, owasp='LLM05', cwe='CWE-502',
                        ))

            elif ext in ['pt', 'pth', 'bin']:
                findings.append(self._make_finding(
                    'HIGH', 'GROWLER-ART-003',
                    'PyTorch checkpoint uses pickle internally',
                    file.name, owasp='LLM05', cwe='CWE-502',
                ))

        return findings

    def _inspect_pickle_opcodes(self, data: bytes) -> list:
        """disassemble pickle stream, find dangerous global opcodes."""
        dangerous_found = []
        output = io.StringIO()
        try:
            pickletools.dis(data, output=output)
            for line in output.getvalue().splitlines():
                for call in DANGEROUS_PICKLE_CALLS:
                    module, _, name = call.partition('.')
                    if 'GLOBAL' in line and module in line and name in line:
                        if call not in dangerous_found:
                            dangerous_found.append(call)
        except Exception:
            pass  #malformed pickle — the format finding still stands
        return dangerous_found
