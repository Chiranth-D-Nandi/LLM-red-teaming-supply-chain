from phase_1.ingestion.huggingface_ingestor import HuggingFaceIngestor

from phase_1.scanners.phase1_supply_chain.serialization_scanner import SerializationScanner
from phase_1.scanners.phase1_supply_chain.custom_code_scanner import CustomCodeScanner
from phase_1.scanners.phase1_supply_chain.dependency_scanner import DependencyScanner
from phase_1.scanners.phase1_supply_chain.secrets_scanner import SecretsScanner
from phase_1.scanners.phase1_supply_chain.provenance_scanner import ProvenanceScanner
from phase_1.scanners.phase2_static_config.generation_config_scanner import GenerationConfigScanner


class ThreatProfile:
    """summary of security findings for a model."""
    
    def __init__(self, model_id, findings):
        self.model_id = model_id
        self.findings = findings
        self.risk_level = self._calculate_risk_level(findings)
    
    def _calculate_risk_level(self, findings):
        """determine overall risk level from findings."""
        if not findings:
            return "LOW"
        
        severities = [f.get("severity") for f in findings]
        
        if "CRITICAL" in severities:
            return "CRITICAL"
        elif "HIGH" in severities:
            return "HIGH"
        elif "MEDIUM" in severities:
            return "MEDIUM"
        else:
            return "LOW"


class ScanOrchestrator:

    def run_scan(self, manifest):
        """run all scanners and return both findings and threat profile."""
        scanners = [
            SerializationScanner(),
            CustomCodeScanner(),
            DependencyScanner(),
            SecretsScanner(),
            ProvenanceScanner(),
            GenerationConfigScanner()
        ]

        findings = []

        for scanner in scanners:

            try:

                findings.extend(scanner.scan(manifest))

            except Exception as e:

                findings.append({
                    "severity": "INFO",
                    "issue": f"Scanner error {type(scanner).__name__}: {e}",
                    "file": "orchestrator"
                })

        #build threat profile
        threat_profile = ThreatProfile(manifest.model_id, findings)
        
        return findings, threat_profile
