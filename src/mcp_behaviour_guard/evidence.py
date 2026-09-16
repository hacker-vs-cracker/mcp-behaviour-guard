"""Small, conservative filters for artifacts that leave the test process."""

from __future__ import annotations

import re
from typing import Any

from .models import AuthorizationStatus, Contract

_SENSITIVE_KEY = re.compile(
    r"(?:authorization|password|secret|token|api.?key|cookie|credential)", re.I
)
_BEARER = re.compile(r"\bBearer\s+[^\s,;\"']+", re.I)
_URL_CREDENTIAL = re.compile(r"(?<=://)[^/@\s]+:[^/@\s]+@")
_QUERY_SECRET = re.compile(r"([?&](?:token|api_key|secret|password)=)[^&#\s]+", re.I)
_MAX_TEXT = 2048


def contract_secrets(contract: Contract) -> set[str]:
    values: set[str] = set()
    for identity in contract.identities.values():
        for name, value in {**identity.headers, **identity.environment}.items():
            if _SENSITIVE_KEY.search(name) and value:
                values.add(value)
                if value.lower().startswith("bearer "):
                    values.add(value[7:])
    for name, value in contract.server.environment.items():
        if _SENSITIVE_KEY.search(name) and value:
            values.add(value)
    return {value for value in values if len(value) >= 6}


def redact(value: Any, secrets: set[str] | None = None) -> Any:
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            label = str(key)
            if label in {
                "response",
                "reader_response",
                "prompt_payloads",
                "values",
                "forbidden_values_present",
            }:
                cleaned[label] = "[omitted from exported evidence]"
            elif label == "authorization":
                allowed = {status.value for status in AuthorizationStatus}
                cleaned[label] = item if isinstance(item, str) and item in allowed else "[redacted]"
            elif _SENSITIVE_KEY.search(label) and label not in {
                "credential_profile_fingerprint",
                "leaked_environment_variables",
                "leaked_environment_variable_names",
            }:
                cleaned[label] = "[redacted]"
            else:
                cleaned[label] = redact(item, secrets)
        return cleaned
    if isinstance(value, (list, tuple)):
        return [redact(item, secrets) for item in value]
    if isinstance(value, str):
        text = _BEARER.sub("Bearer [redacted]", value)
        text = _URL_CREDENTIAL.sub("[redacted]@", text)
        text = _QUERY_SECRET.sub(r"\1[redacted]", text)
        for secret in sorted(secrets or set(), key=len, reverse=True):
            text = text.replace(secret, "[redacted]")
        return text if len(text) <= _MAX_TEXT else "[long value omitted from exported evidence]"
    return value
