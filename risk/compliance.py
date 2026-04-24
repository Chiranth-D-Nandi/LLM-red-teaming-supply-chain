"""
Growler Security v2 — Compliance Mapper.

Maps each finding to OWASP LLM Top 10, MITRE ATLAS, and CWE references.
"""

OWASP_LLM = {
    'LLM01': {'name': 'Prompt Injection'},
    'LLM02': {'name': 'Insecure Output Handling'},
    'LLM03': {'name': 'Training Data Poisoning'},
    'LLM04': {'name': 'Model Denial of Service'},
    'LLM05': {'name': 'Supply Chain Vulnerabilities'},
    'LLM06': {'name': 'Sensitive Information Disclosure'},
    'LLM07': {'name': 'Insecure Plugin Design'},
    'LLM08': {'name': 'Excessive Agency'},
    'LLM09': {'name': 'Overreliance'},
    'LLM10': {'name': 'Model Theft'},
}

MITRE_ATLAS = {
    'AML.T0010': {'name': 'ML Supply Chain Compromise', 'tactic': 'Initial Access'},
    'AML.T0024': {'name': 'Infer Training Data Membership', 'tactic': 'ML Model Access'},
    'AML.T0051': {'name': 'LLM Prompt Injection', 'tactic': 'ML Attack Staging'},
    'AML.T0054': {'name': 'LLM Jailbreak', 'tactic': 'ML Attack Staging'},
    'AML.T0048': {'name': 'ML Model Reuse', 'tactic': 'ML Model Access'},
}

#rule_id -> compliance tags mapping
COMPLIANCE_MAP = {
    #phase 1 - scanners
    'GROWLER-ART-001': {'owasp': 'LLM05', 'mitre': 'AML.T0010', 'cwe': 'CWE-502'},
    'GROWLER-ART-002': {'owasp': 'LLM05', 'mitre': 'AML.T0010', 'cwe': 'CWE-502'},
    'GROWLER-ART-003': {'owasp': 'LLM05', 'mitre': 'AML.T0010', 'cwe': 'CWE-502'},
    'GROWLER-CODE-001': {'owasp': 'LLM05', 'mitre': 'AML.T0010', 'cwe': 'CWE-829'},
    'GROWLER-CODE-002': {'owasp': 'LLM05', 'cwe': 'CWE-829'},
    'GROWLER-CODE-003': {'owasp': 'LLM05', 'cwe': 'CWE-829'},
    'GROWLER-DEP-001': {'owasp': 'LLM05', 'cwe': 'CWE-937'},
    'GROWLER-DEP-002': {'owasp': 'LLM05', 'cwe': 'CWE-937'},
    'GROWLER-SEC-001': {'owasp': 'LLM06', 'cwe': 'CWE-312'},
    'GROWLER-SEC-002': {'owasp': 'LLM06', 'cwe': 'CWE-312'},
    'GEN-000': {'owasp': 'LLM04', 'cwe': 'CWE-770'},
    'GEN-001': {'owasp': 'LLM04', 'cwe': 'CWE-770'},
    'GEN-002': {'owasp': 'LLM02', 'cwe': 'CWE-770'},
    'GEN-003': {'owasp': 'LLM04', 'cwe': 'CWE-770'},
    'PROV-001': {'owasp': 'LLM03'},
    'PROV-002': {'owasp': 'LLM03'},
    'PROV-003': {'owasp': 'LLM09'},
    #phase 2 - attacks
    'PI-T1': {'owasp': 'LLM01', 'mitre': 'AML.T0051', 'cwe': 'CWE-74'},
    'PI-T2': {'owasp': 'LLM01', 'mitre': 'AML.T0051', 'cwe': 'CWE-74'},
    'PI-T3': {'owasp': 'LLM01', 'mitre': 'AML.T0051', 'cwe': 'CWE-74'},
    'PI-T4': {'owasp': 'LLM01', 'mitre': 'AML.T0054', 'cwe': 'CWE-74'},
    'PI-T5': {'owasp': 'LLM01', 'mitre': 'AML.T0054', 'cwe': 'CWE-74'},
    'SE': {'owasp': 'LLM06', 'mitre': 'AML.T0024', 'cwe': 'CWE-200'},
    'MEM': {'owasp': 'LLM06', 'cwe': 'CWE-200'},
}


def map_compliance(finding: dict) -> dict:
    """map a finding to owasp llm, mitre atlas, and cwe tags."""
    rule_id = finding.get('rule_id', '')

    #try exact match
    tags = COMPLIANCE_MAP.get(rule_id)

    #try prefix match (e.g., 'PI-T3-002' → 'PI-T3')
    if not tags and '-' in rule_id:
        parts = rule_id.split('-')
        for i in range(len(parts), 0, -1):
            prefix = '-'.join(parts[:i])
            tags = COMPLIANCE_MAP.get(prefix)
            if tags:
                break

    #fallback: use owasp/cwe from finding itself
    if not tags:
        tags = {}
        if finding.get('owasp'):
            tags['owasp'] = finding['owasp']
        if finding.get('cwe'):
            tags['cwe'] = finding['cwe']

    owasp_id = tags.get('owasp')
    mitre_id = tags.get('mitre')

    return {
        'owasp': owasp_id or '',
        'owasp_name': OWASP_LLM.get(owasp_id, {}).get('name', '') if owasp_id else '',
        'mitre': mitre_id or '',
        'mitre_name': MITRE_ATLAS.get(mitre_id, {}).get('name', '') if mitre_id else '',
        'cwe': tags.get('cwe', ''),
    }
