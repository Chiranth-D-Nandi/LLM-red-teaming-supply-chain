"""
growler security v2 — sarif 2.1.0 export.

generates sarif (static analysis results interchange format) json output.
github, azure devops, and gitlab display sarif natively.
"""

from datetime import datetime, timezone
from .compliance import map_compliance


def generate_sarif(assessment_result: dict) -> dict:
    """generate sarif 2.1.0 format output from assessment results."""
    findings = assessment_result.get('all_findings', [])

    #deduplicate rule definitions
    rules_seen = {}
    for f in findings:
        rid = f.get('rule_id', 'GROWLER-UNKNOWN')
        if rid not in rules_seen:
            compliance = map_compliance(f)
            tags = [
                t for t in [
                    compliance.get('owasp'),
                    compliance.get('mitre'),
                    compliance.get('cwe'),
                ] if t
            ]
            rules_seen[rid] = {
                'id': rid,
                'name': f.get('issue', rid)[:80],
                'shortDescription': {'text': f.get('issue', '')},
                'properties': {'tags': tags},
            }

    sarif_results = []
    for f in findings:
        level = {
            'CRITICAL': 'error',
            'HIGH': 'error',
            'MEDIUM': 'warning',
            'LOW': 'note',
            'INFO': 'none',
        }.get(f.get('severity', 'INFO'), 'note')

        result = {
            'ruleId': f.get('rule_id', 'GROWLER-UNKNOWN'),
            'level': level,
            'message': {'text': f.get('issue', '')},
            'locations': [{
                'physicalLocation': {
                    'artifactLocation': {'uri': f.get('file', 'unknown')},
                }
            }],
        }

        if f.get('line'):
            result['locations'][0]['physicalLocation']['region'] = {
                'startLine': f['line']
            }

        sarif_results.append(result)

    now = datetime.now(timezone.utc).isoformat()

    return {
        '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        'version': '2.1.0',
        'runs': [{
            'tool': {
                'driver': {
                    'name': 'Growler Security',
                    'version': '2.0.0',
                    'semanticVersion': '2.0.0',
                    'rules': list(rules_seen.values()),
                }
            },
            'results': sarif_results,
            'invocations': [{
                'executionSuccessful': True,
                'startTimeUtc': now,
                'endTimeUtc': now,
            }],
        }],
    }
