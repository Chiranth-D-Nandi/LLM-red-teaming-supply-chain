# Growler Security

**AI Model Security Assessment and Red-Teaming Platform**

Growler Security audits HuggingFace models before deployment. It runs a two-phase pipeline: static analysis of the model artifact for supply chain risks, followed by a live adversarial red-team campaign targeting prompt injection and data extraction vulnerabilities. Findings are scored, chained into exploit paths, and exported as SARIF for CI/CD integration.

---

## Demo

![Verdict and Risk Score](docs/1111.jpeg)

![Risk by Category and Injection Resistance Depth](docs/22.jpeg)

---

## What It Does

### Phase 1 — Supply Chain and Static Analysis

- **Serialization Scanner** — detects pickle files and disassembles opcodes to identify `os.system`, `subprocess`, and `eval` calls that execute on model load
- **Custom Code Scanner** — AST-walks `.py` files bundled with the model for dangerous sinks: shell execution, network calls, dangerous builtins
- **Dependency Scanner** — parses `requirements.txt` and queries the [OSV.dev](https://osv.dev) API for known CVEs per package
- **Secrets Scanner** — scans file contents with regex patterns and Shannon entropy analysis to surface AWS keys, HuggingFace tokens, private keys, and high-entropy unknown secrets
- **Provenance Scanner** — checks model card completeness across intended use, limitations, training data, evaluation, ethical considerations, and license
- **Generation Config Scanner** — policy-as-code validation of `generation_config.json` for `max_new_tokens`, temperature, and repetition penalty

### Phase 2 — Adversarial Red-Teaming

Five-tier prompt injection campaign with adaptive mutation:

| Tier | Technique |
|------|-----------|
| 1 | Naive direct overrides |
| 2 | Delimiter and template injection (`<<SYS>>`, `<\|im_start\|>`, etc.) |
| 3 | Encoding bypasses — base64, unicode homoglyphs, ROT13, token splitting |
| 4 | Semantic attacks — fictional framing, persona override, few-shot manipulation, code completion extraction |
| 5 | Multi-turn crescendo escalation and cross-lingual bypass |

Additional attack modules:
- **System prompt extraction** — measures what fraction of planted secrets are recoverable from model responses
- **Memorization analysis** — Carlini et al. methodology for verbatim training data extraction

### Phase 3 — Risk Scoring and Export

- CVSS-style multi-dimensional scoring per finding (attack vector, complexity, impact, confidence)
- Attack chain composition — chains medium-severity findings into CRITICAL exploit paths
- OWASP LLM Top 10, MITRE ATLAS, and CWE mapping per finding
- SARIF 2.1.0 export compatible with GitHub Security tab and standard CI/CD pipelines

---

## Architecture

```
growler_security/
├── core/engine.py                  # Unified pipeline: Phase 1 → Phase 2 → Risk
├── phase_1/                        # Static analysis
│   ├── ingestion/                  # HuggingFace artifact manifest builder
│   ├── scanners/
│   │   ├── phase1_supply_chain/    # Serialization, code, deps, secrets, provenance
│   │   └── phase2_static_config/  # Generation config policy engine
│   └── core/orchestrator.py
├── phase_2/                        # Adversarial attack engine
│   ├── attacks/                    # 5-tier campaign + adaptive mutator
│   ├── judges/                     # Canary, LLM-as-judge, PII ensemble
│   ├── extraction.py               # System prompt extraction
│   ├── memorization.py             # Carlini-style verbatim completion
│   └── attack_graph.py             # Exploit chain composition
├── recon/model_fingerprint.py      # Model fingerprinting and threat profile
├── risk/                           # Scorer, compliance mapper, SARIF export
├── shared/model_harness.py         # Unified Ollama / Groq / HF API backend
└── ui/app.py                       # Streamlit dashboard
```

---

## Setup

```bash
pip install -r requirements.txt
```

A model backend is required for Phase 2. Supported options:

| Backend | Setup | Notes |
|---------|-------|-------|
| `ollama` | Install [Ollama](https://ollama.ai), then `ollama pull tinyllama` | Fully local, no API key required |
| `groq` | Obtain a free key at [console.groq.com](https://console.groq.com) | Fast inference, free tier available |

Phase 1 (static analysis) runs without any backend.

---

## Running

```bash
streamlit run ui/app.py
```

Enter a HuggingFace model ID (e.g. `microsoft/phi-2`), select a backend, and click **SCAN**.

Use **Load Demo Result** to explore a pre-run scan against a vulnerable model without configuring a backend.

---

## Tech Stack

Python · Streamlit · HuggingFace Hub · OSV.dev API · Plotly · SARIF 2.1.0 · Ollama · Groq
