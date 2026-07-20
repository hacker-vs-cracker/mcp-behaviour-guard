from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx

from .models import Contract


class OllamaAdvisor:
    def __init__(
        self,
        model: str = "llama3.1:8b",
        base_url: str = "http://127.0.0.1:11434",
        timeout_seconds: float = 120,
    ) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    async def suggest_tests(
        self,
        contract: Contract,
        discovered_tools: list[dict[str, Any]],
    ) -> dict[str, Any]:
        prompt = _build_prompt(contract, discovered_tools)
        payload = {
            "model": self.model,
            "stream": False,
            "format": "json",
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a security test-case assistant. Propose candidates only. "
                        "Never claim a vulnerability and never make pass/fail decisions."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "options": {"temperature": 0.2},
        }
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            response = await client.post(f"{self.base_url}/api/chat", json=payload)
            response.raise_for_status()
            raw = response.json()

        content = raw.get("message", {}).get("content", "{}")
        try:
            suggestions = json.loads(content)
        except json.JSONDecodeError:
            suggestions = {"raw": content}

        return {
            "trusted_for_pass_fail": False,
            "model": self.model,
            "suggestions": suggestions,
        }


def write_suggestions(payload: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _build_prompt(contract: Contract, discovered_tools: list[dict[str, Any]]) -> str:
    safe_contract = contract.model_dump(mode="json")
    for identity in safe_contract.get("identities", {}).values():
        identity["headers"] = {key: "<redacted>" for key in identity.get("headers", {})}

    return f"""
Review this MCP security contract and discovered tool metadata.
Return JSON with a top-level key named candidate_tests. Each candidate must contain:
id, tool, category, rationale, schema_valid_arguments, expected_security_property.
Focus on boundary values, confused-deputy behaviour, path boundaries, SSRF-shaped URLs,
replay/idempotency, approval binding and cross-tenant object identifiers.
Do not include shell payloads, exploit steps, credentials, or destructive production actions.

Contract:
{json.dumps(safe_contract, indent=2)}

Discovered tools:
{json.dumps(discovered_tools, indent=2)}
""".strip()
