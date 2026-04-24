# 🛡️ Growler Security

**AI Model Security Auditing Platform** — static analysis + adversarial red-teaming for HuggingFace models.

Growler Security scans AI models before deployment, catching supply chain attacks, embedded malware, leaked secrets, dependency CVEs, and prompt injection vulnerabilities — then exports findings as SARIF for CI/CD integration.

---

## What It Does

### Phase 1 — Supply Chain & Static Analysis
- **Serialization Scanner** — detects pickle files and disassembles opcodes to find `os.system`, `subprocess`, `eval` calls that execute on model load
- **Custom Code Scanner** — AST-walks `.py` files for dangerous sinks: shell execution, network calls, dangerous builtins
- **Dependency Scanner** — parses `requirements.txt`, queries the [OSV.dev](https://osv.dev) API for known CVEs per package
- **Secrets Scanner** — scans file *contents* (not names) with regex patterns + Shannon entropy analysis to catch AWS keys, HF tokens, private keys, and unknown high-entropy secrets
- **Provenance Scanner** — checks model card completeness: intended use, limitations, training data, evaluation, ethical sections, license file
- **Generation Config Scanner** — policy-as-code validation of `generation_config.json`: `max_new_tokens`, temperature, repetition penalty

### Phase 2 — Adversarial Red-Teaming
Five-tier prompt injection campaign with adaptive mutation:
- **Tier 1** Naive direct overrides
- **Tier 2** Delimiter/template injection (`<<SYS>>`, `<|im_start|>`, etc.)
- **Tier 3** Encoding bypasses — base64, unicode homoglyphs, ROT13, token splitting
- **Tier 4** Semantic attacks — fictional framing, persona override, few-shot manipulation, code completion extraction
- **Tier 5** Multi-turn crescendo escalation and cross-lingual bypass

Plus: **system prompt extraction** (measures what fraction of planted secrets are extractable) and **memorization analysis** (Carlini et al. methodology).

### Phase 3 — Risk Scoring & Report
- Multi-dimensional CVSS-style scoring per finding (attack vector, complexity, impact, confidence)
- Attack chain composition — medium findings that chain into CRITICAL exploit paths
- **SARIF 2.1.0 export** — drops directly into GitHub Security tab, Azure DevOps, any CI/CD pipeline
- OWASP LLM Top 10, MITRE ATLAS, and CWE mapping per finding

---

## Architecture

```
growler_security/
├── core/engine.py          # Unified pipeline: A → B → C
├── phase_1/               # Static analysis
│   ├── ingestion/          # HuggingFace manifest builder
│   ├── scanners/
│   │   ├── phase1_supply_chain/   # Serialization, code, deps, secrets, provenance
│   │   └── phase2_static_config/  # Generation config policy engine
│   └── core/orchestrator.py
├── phase_2/               # Adversarial attack engine
│   ├── attacks/            # 5-tier campaign + adaptive mutator
│   ├── judges/             # Canary, LLM-as-judge, PII ensemble
│   ├── extraction.py       # System prompt extraction
│   ├── memorization.py     # Carlini-style verbatim completion
│   └── attack_graph.py     # Exploit chain composition
├── recon/                  # Model fingerprinting → threat profile
├── risk/                   # Scorer, compliance mapper, SARIF export
├── shared/model_harness.py # Unified Ollama / Groq / HF API backend
└── ui/app.py               # Streamlit dashboard
```

---

## Setup

```bash
pip install -r requirements.txt
```

**Model backend** — you need one of:
- [Ollama](https://ollama.ai) running locally (`ollama pull tinyllama`)
- Groq API key (free tier available at [console.groq.com](https://console.groq.com))

---

## Running

```bash
streamlit run ui/app.py
```

Open `http://localhost:8501`. Enter any HuggingFace model ID (e.g. `microsoft/phi-2`), select your backend, and click **SCAN**.

Use **Load Demo Result** to see a pre-run scan against a vulnerable model without needing a backend.

---

## Backends

| Backend | How to set up | Best for |
|---|---|---|
| `ollama` | Install Ollama, `ollama pull tinyllama` | Local, no API key |
| `groq` | Get free key at console.groq.com | Fast, cloud, free tier |

---

## SARIF Export

The Export tab produces a SARIF 2.1.0 file that GitHub, Azure DevOps, and GitLab display natively in their Security tabs. No integration work required — drop the file and findings appear as code scanning alerts.

---

## Tech Stack

Python · Streamlit · HuggingFace Hub · OSV.dev API · Plotly · SARIF 2.1.0 · Ollama · Groq
