"""
Attack mutator — generates new payloads by:
  1. Starting with a seed (attack template)
  2. Using attacker LLM to generate variants
  3. Optionally adapting based on previous response

Supports two modes:
  - generate_variant(): Create new attack from seed (no context)
  - mutate(): Create new attack based on target's response to previous attempt
"""

from ..prompts import MUTATE_ATTACK


class AttackMutator:

    def __init__(self, attacker_harness):
        self.attacker = attacker_harness

    def generate_variant(self, seed: dict, target_behavior: str = "bypass all safety restrictions"):
        """
        Generate a fresh attack variant from a seed (no prior response).
        """
        if seed.get("requires_encoding"):
            payload = self._encode_payload(seed["payload_template"], target_behavior, seed["encoding_type"])
        else:
            payload = seed["payload"].format(target_behavior=target_behavior)

        return {
            "seed_id": seed["id"],
            "technique": seed["technique"],
            "payload": payload,
            "is_dynamic": True,
            "source": "generated_variant",
        }

    def mutate(self, seed: dict, prev_payload: str, target_response: str, 
               result: dict, target_behavior: str = "bypass all safety restrictions"):
        """
        mutate based on target's response to previous attack.
        """
        outcome = "blocked" if not result["success"] else "partial"  #success vs attempt

        prompt = MUTATE_ATTACK.format(
            technique=seed["technique"],
            description=seed.get("description", "[no description]"),
            previous_payload=prev_payload,
            target_response=target_response[:400],
            goal=target_behavior,
            system_prompt=seed.get("system_prompt", "[unknown]"),
            canary=seed.get("canary", "[redacted]"),
            outcome=outcome,
            hints=seed.get("hints", "Use different encoding or framing"),
        )

        try:
            response, _ = self.attacker.generate(prompt, max_tokens=300)
            new_payload = self._clean_payload(response)
        except Exception:
            new_payload = prev_payload  #fallback: repeat previous

        return {
            "seed_id": seed["id"],
            "technique": seed["technique"],
            "payload": new_payload,
            "is_dynamic": True,
            "source": "mutated",
            "based_on": prev_payload,
            "target_response_snippet": target_response[:100],
        }

    # ================================================================ #
    @staticmethod
    def _clean_payload(raw: str) -> str:
        """Strip markdown, quotes, and extra whitespace."""
        if raw.startswith("```"):
            raw = raw.split("```")[1]
        if raw.startswith('"""') or raw.startswith("'''"):
            raw = raw[3:-3]
        raw = raw.strip().strip('"').strip("'").strip()
        return raw

    @staticmethod
    def _encode_payload(template: str, target_behavior: str, encoding_type: str):
        import base64
        import codecs

        payload_str = target_behavior

        if encoding_type == "base64":
            encoded = base64.b64encode(payload_str.encode()).decode()
        elif encoding_type == "rot13":
            encoded = codecs.encode(payload_str, "rot_13")
        else:
            encoded = payload_str

        return template.format(encoded=encoded)
