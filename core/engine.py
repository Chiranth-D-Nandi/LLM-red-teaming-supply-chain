
#wires phase 1 (static analysis), phase 2 (attack engine), and risk scoring together into a single pipeline that the streamlit ui calls.


import sys
import os
import hashlib
import json
from datetime import datetime, timezone

#make sure growler_security is on the path
_GROWLER_SECURITY_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _GROWLER_SECURITY_ROOT not in sys.path:
    sys.path.insert(0, _GROWLER_SECURITY_ROOT)

from phase_1.ingestion.huggingface_ingestor import HuggingFaceIngestor
from phase_1.core.orchestrator import ScanOrchestrator
from recon.model_fingerprint import ModelFingerprinter
from risk.scorer import score_finding, compute_model_risk
from risk.compliance import map_compliance


def _hash_evidence(finding: dict) -> str:
    """sha-256 hash of finding evidence for tamper-detection."""
    payload = json.dumps({
        'file': finding.get('file', ''),
        'issue': finding.get('issue', ''),
        'rule_id': finding.get('rule_id', ''),
        'timestamp': datetime.now(timezone.utc).isoformat(),
    }, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def _convert_attack_findings(attack_results: dict) -> list:
    """convert phase 2 attack results into the flat finding format."""
    findings = []

    #prompt injection findings
    pi = attack_results.get('campaign_results', {}).get('prompt_injection', {})
    for r in pi.get('results', []):
        if r.get('verdict', {}).get('success'):
            atk = r.get('attack', {})
            atk_id = atk.get('id', 'UNK')
            tier_prefix = atk_id.split('-')[0]
            findings.append({
                'severity': 'CRITICAL' if tier_prefix in ('T1', 'T2') else 'HIGH' if tier_prefix in ('T3', 'T4') else 'MEDIUM',
                'rule_id': f"PI-{atk_id}",
                'issue': f"Prompt injection succeeded: {atk.get('technique', 'unknown')}",
                'file': 'adversarial_test',
                'payload': atk.get('payload', '')[:200] if isinstance(atk.get('payload'), str) else '',
                'response': r.get('raw_response', '')[:200],
                'owasp': 'LLM01',
                'cwe': 'CWE-74',
            })

    #system extraction findings
    ext = attack_results.get('campaign_results', {}).get('system_extraction', {})
    if ext.get('extraction_rate', 0) > 0:
        findings.append({
            'severity': ext.get('severity', 'HIGH'),
            'rule_id': 'SE-001',
            'issue': f"System prompt extraction: {ext['extraction_rate']:.0%} of secrets leaked",
            'file': 'adversarial_test',
            'owasp': 'LLM06',
            'cwe': 'CWE-200',
        })

    #memorization findings
    mem = attack_results.get('campaign_results', {}).get('memorization', {})
    if mem.get('severity', 'LOW') != 'LOW':
        findings.append({
            'severity': mem['severity'],
            'rule_id': 'MEM-001',
            'issue': f"Memorization risk: {mem.get('avg_verbatim_rate', 0):.1%} verbatim rate",
            'file': 'adversarial_test',
            'owasp': 'LLM06',
            'cwe': 'CWE-200',
        })
    if mem.get('pii_detected'):
        findings.append({
            'severity': 'HIGH',
            'rule_id': 'MEM-PII',
            'issue': 'PII data extractable via completion probes',
            'file': 'adversarial_test',
            'owasp': 'LLM06',
            'cwe': 'CWE-200',
        })

    return findings


def run_full_assessment(model_id: str, backend: str = 'ollama',
                        model_name: str = 'tinyllama', api_key: str = None,
                        run_attacks: bool = True) -> dict:
    """
    Run the full Growler Security assessment pipeline.

    Returns a dict with all findings, scores, verdict, attack chains, etc.
    """
    results = {
        'model_id': model_id,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'phase1_findings': [],
        'phase2_findings': [],
        'attack_findings': [],
        'attack_chains': [],
        'robustness_tier': 0,
        'all_findings': [],
        'scored_findings': [],
        'risk': {},
        'threat_profile': None,
        'phase_scores': {},
        'attack_results_raw': {},
    }

    #phase 1 & 2: static analysis
    try:
        ingestor = HuggingFaceIngestor()
        manifest = ingestor.build_manifest(model_id)

        orchestrator = ScanOrchestrator()
        static_findings, _old_profile = orchestrator.run_scan(manifest)

        #build proper threat profile
        fingerprinter = ModelFingerprinter()
        threat_profile = fingerprinter.build_profile(manifest)
        results['threat_profile'] = threat_profile.to_dict()

        #split findings into phase 1 and phase 2
        phase2_rules = {'GEN-000', 'GEN-001', 'GEN-002', 'GEN-003'}
        for f in static_findings:
            if f.get('rule_id', '') in phase2_rules:
                results['phase2_findings'].append(f)
            else:
                results['phase1_findings'].append(f)

    except Exception as e:
        results['phase1_findings'].append({
            'severity': 'INFO',
            'rule_id': 'SCAN-ERR',
            'issue': f'Static analysis error: {str(e)}',
            'file': 'orchestrator',
        })
        threat_profile = None

    #phase 3 & 4: adversarial testing
    if run_attacks:
        try:
            from shared.model_harness import ModelHarness
            from phase_2.engine import AttackEngine

            harness_kwargs = {'backend': backend, 'model_name': model_name}
            if api_key:
                harness_kwargs['api_key'] = api_key

            target = ModelHarness(**harness_kwargs)
            attacker = ModelHarness(**harness_kwargs)
            judge = ModelHarness(**harness_kwargs)

            #quick connectivity check
            test_resp, test_lat = target.generate("Say hello in one sentence.")
            if test_resp.startswith("[ERROR]"):
                raise ConnectionError(f"Cannot reach model backend: {test_resp}")

            tp_dict = results.get('threat_profile') or {
                'applicable_attack_families': ['prompt_injection', 'system_extraction', 'memorization']
            }

            engine = AttackEngine(target=target, attacker=attacker, judge=judge)
            attack_results = engine.run_campaign(tp_dict)

            results['attack_results_raw'] = attack_results
            results['attack_findings'] = _convert_attack_findings(attack_results)
            results['attack_chains'] = attack_results.get('attack_chains', [])

            pi = attack_results.get('campaign_results', {}).get('prompt_injection', {})
            results['robustness_tier'] = pi.get('robustness_tier', 0)

        except Exception as e:
            results['attack_findings'].append({
                'severity': 'INFO',
                'rule_id': 'ATK-ERR',
                'issue': f'Attack engine error: {str(e)}',
                'file': 'adversarial_test',
            })

    #combine all findings
    all_findings = (
        results['phase1_findings'] +
        results['phase2_findings'] +
        results['attack_findings']
    )

    #add evidence hash to each finding
    for f in all_findings:
        f['evidence_hash'] = _hash_evidence(f)

    results['all_findings'] = all_findings

    #score findings
    scored = []
    for f in all_findings:
        s = score_finding(f)
        scored.append({'finding': f, 'score': s})
    results['scored_findings'] = scored

    #compute risk
    results['risk'] = compute_model_risk(scored, results['attack_chains'])

    #phase scores for breakdown chart
    phase_scores = {}
    for label, findings_list in [
        ('Supply Chain', results['phase1_findings']),
        ('Config', results['phase2_findings']),
        ('Adversarial', results['attack_findings']),
    ]:
        if findings_list:
            fscores = [score_finding(f) for f in findings_list]
            phase_scores[label] = round(max(fscores), 1)
        else:
            phase_scores[label] = 0.0
    results['phase_scores'] = phase_scores

    return results
