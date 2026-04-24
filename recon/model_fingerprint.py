"""
Growler Security v2 — Model Fingerprinting / Threat Profile Builder.

Reads config.json from the manifest and produces a ThreatProfile that
determines which attack families are relevant for this specific model.
"""

from dataclasses import dataclass, field
from typing import Optional, List


KNOWN_ARCHITECTURE_SIGNATURES = {
    'llama': {'hidden_size': 4096, 'num_hidden_layers': 32, 'num_attention_heads': 32},
    'mistral': {'hidden_size': 4096, 'num_hidden_layers': 32, 'num_attention_heads': 32},
    'phi': {'hidden_size': 2560, 'num_hidden_layers': 32, 'num_attention_heads': 32},
    'gemma': {'hidden_size': 2048, 'num_hidden_layers': 18, 'num_attention_heads': 8},
    'gpt2': {'hidden_size': 768, 'num_hidden_layers': 12, 'num_attention_heads': 12},
    'bert': {'hidden_size': 768, 'num_hidden_layers': 12, 'num_attention_heads': 12},
}


@dataclass
class ThreatProfile:
    model_id: str
    model_type: str  #causal_lm, seq2seq, classification, unknown
    architecture_family: str  #llama, mistral, phi, gemma, unknown
    parameter_count: Optional[int] = None
    is_fine_tune: bool = False
    quantization: Optional[str] = None  #gptq, awq, gguf, none
    has_system_prompt_support: bool = False
    context_window: int = 2048
    applicable_attack_families: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            'model_id': self.model_id,
            'model_type': self.model_type,
            'architecture_family': self.architecture_family,
            'parameter_count': self.parameter_count,
            'is_fine_tune': self.is_fine_tune,
            'quantization': self.quantization,
            'has_system_prompt_support': self.has_system_prompt_support,
            'context_window': self.context_window,
            'applicable_attack_families': self.applicable_attack_families,
        }


class ModelFingerprinter:

    def build_profile(self, manifest) -> ThreatProfile:
        config = manifest.config_json or {}

        model_type = config.get('model_type', 'unknown')
        arch = self._detect_architecture(config)
        quantization = self._detect_quantization(manifest)

        is_chat = (
            'chat' in manifest.model_id.lower()
            or 'instruct' in manifest.model_id.lower()
            or manifest.tokenizer_config is not None
        )

        context = config.get('max_position_embeddings', 2048)

        attacks = ['system_extraction', 'prompt_injection']
        if is_chat:
            attacks.extend(['alignment_bypass', 'multi_turn'])
        attacks.append('memorization')

        return ThreatProfile(
            model_id=manifest.model_id,
            model_type=model_type,
            architecture_family=arch,
            parameter_count=self._estimate_params(config),
            is_fine_tune='adapter_config' in [f.name for f in manifest.files],
            quantization=quantization,
            has_system_prompt_support=is_chat,
            context_window=context,
            applicable_attack_families=attacks,
        )

    def _detect_architecture(self, config):
        model_type = config.get('model_type', '').lower()
        architectures = config.get('architectures', [])
        arch_str = ' '.join(architectures).lower() if architectures else ''
        combined = f"{model_type} {arch_str}"

        for family in KNOWN_ARCHITECTURE_SIGNATURES:
            if family in combined:
                return family
        return 'unknown'

    def _detect_quantization(self, manifest):
        all_names = ' '.join(f.name.lower() for f in manifest.files)
        model_id_lower = manifest.model_id.lower()
        combined = f"{all_names} {model_id_lower}"

        for method in ['gptq', 'awq', 'gguf', 'eetq']:
            if method in combined:
                return method.upper()
        return None

    def _estimate_params(self, config):
        h = config.get('hidden_size', 0)
        n_layers = config.get('num_hidden_layers', 0)
        if h and n_layers:
            return h * n_layers * 12  #rough estimate
        return None
