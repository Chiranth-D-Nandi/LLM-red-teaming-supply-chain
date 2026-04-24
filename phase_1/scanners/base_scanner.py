"""Base scanner class for all Growler Security scanners."""


class BaseScanner:

    def scan(self, manifest):
        raise NotImplementedError

    @staticmethod
    def _make_finding(severity, rule_id, issue, filename, **kwargs):
        """Create a standardised finding dict."""
        finding = {
            'severity': severity,
            'rule_id': rule_id,
            'issue': issue,
            'file': filename,
        }
        finding.update(kwargs)
        return finding
