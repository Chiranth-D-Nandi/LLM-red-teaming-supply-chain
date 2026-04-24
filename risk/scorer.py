"""
Growler Security v2 — Calibrated Risk Scoring Engine.

Multi-dimensional scoring model with explicit attack vector, complexity,
and impact dimensions. Produces per-finding scores and aggregate model risk.
"""

ATTACK_VECTOR_SCORES = {
    'network_unauthenticated': 1.0,
    'network_authenticated': 0.8,
    'adjacent_system': 0.5,
    'local_access': 0.3,
}

COMPLEXITY_SCORES = {
    'low': 1.0,
    'medium': 0.6,
    'high': 0.3,
}

IMPACT_SCORES = {
    'integrity_high': 1.0,
    'confidentiality_high': 0.9,
    'availability_high': 0.8,
    'integrity_medium': 0.6,
    'confidentiality_medium': 0.5,
    'availability_medium': 0.4,
}

SEVERITY_TO_BASE = {
    'CRITICAL': 9.0,
    'HIGH': 7.0,
    'MEDIUM': 4.5,
    'LOW': 2.0,
    'INFO': 0.5,
}


def score_finding(finding: dict) -> float:
    """Score an individual finding 0-10."""
    base = SEVERITY_TO_BASE.get(finding.get('severity', 'INFO'), 2.0)
    av = ATTACK_VECTOR_SCORES.get(
        finding.get('attack_vector', 'network_unauthenticated'), 0.8
    )
    ac = COMPLEXITY_SCORES.get(finding.get('complexity', 'low'), 0.8)
    impact_cats = finding.get('impact_categories', ['integrity_medium'])
    impact = max(IMPACT_SCORES.get(i, 0.5) for i in impact_cats)
    confidence = finding.get('confidence', 0.8)
    scope_mult = 1.2 if finding.get('scope') == 'changed' else 1.0

    raw = base * av * ac * impact * scope_mult * confidence
    normalized = min(10.0, (raw / 12.0) * 10)
    return round(normalized, 1)


def compute_model_risk(scored_findings: list, attack_chains: list = None) -> dict:
    """Compute aggregate model risk from scored findings and attack chains."""
    attack_chains = attack_chains or []

    if not scored_findings:
        return {
            'score': 0.0,
            'verdict': 'INSUFFICIENT_DATA',
            'reason': 'No findings to evaluate.',
            'worst_finding': 0.0,
            'density': 0.0,
            'chain_boost': 0.0,
            'by_severity': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0},
            'total_findings': 0,
        }

    scores = [f['score'] for f in scored_findings]
    worst = max(scores)
    density = sum(scores) / len(scores)

    chain_boost = 0.0
    if attack_chains:
        critical_chains = [
            c for c in attack_chains
            if c.get('compound_severity') == 'CRITICAL'
        ]
        chain_boost = min(2.0, len(critical_chains) * 0.5)

    combined = min(10.0, 0.6 * worst + 0.25 * density + 0.15 * worst + chain_boost)

    if combined >= 8.0 or worst >= 9.0:
        verdict = 'CRITICAL_DENY'
        reason = 'Critical vulnerabilities detected. Do not deploy.'
    elif combined >= 6.0 or worst >= 7.0:
        verdict = 'DENY'
        reason = 'Significant vulnerabilities require remediation before deployment.'
    elif combined >= 3.5:
        verdict = 'CONDITIONAL'
        reason = 'Moderate risks present. Deploy with mitigations only.'
    else:
        verdict = 'APPROVE'
        reason = 'Low residual risk. Standard monitoring recommended.'

    by_severity = {
        'CRITICAL': len([f for f in scored_findings if f['score'] >= 9.0]),
        'HIGH': len([f for f in scored_findings if 7.0 <= f['score'] < 9.0]),
        'MEDIUM': len([f for f in scored_findings if 4.0 <= f['score'] < 7.0]),
        'LOW': len([f for f in scored_findings if 2.0 <= f['score'] < 4.0]),
        'INFO': len([f for f in scored_findings if f['score'] < 2.0]),
    }

    return {
        'score': round(combined, 1),
        'verdict': verdict,
        'reason': reason,
        'worst_finding': worst,
        'density': round(density, 2),
        'chain_boost': chain_boost,
        'by_severity': by_severity,
        'total_findings': len(scored_findings),
    }
