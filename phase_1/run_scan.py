import sys
import os
#make sure root is on the path
_AEGIS_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _AEGIS_ROOT not in sys.path:
    sys.path.insert(0, _AEGIS_ROOT)

from phase_1.core.orchestrator import ScanOrchestrator
from phase_1.ingestion.huggingface_ingestor import HuggingFaceIngestor

model =  "glockr1/ballr7"
ingestor = HuggingFaceIngestor()
manifest = ingestor.build_manifest(model)

print("\n")
print(model,"is being scaned for risks...\n")
print("\nFILES FOUND IN MODEL\n")

for f in manifest.files:
    print(f.name)

orchestrator = ScanOrchestrator()
findings, threat_profile = orchestrator.run_scan(manifest)

print("\nSCAN RESULTS\n")

for r in findings:
    print(r)

print(f"\nOVERALL RISK LEVEL: {threat_profile.risk_level}\n")

if(findings == []):
    print("No Risks found!!\n")
