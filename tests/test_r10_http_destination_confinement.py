from __future__ import annotations

from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

import mcp_behaviour_guard.client as client_module
from mcp_behaviour_guard.client import McpClient
from mcp_behaviour_guard.config import ContractError, validate_target
from mcp_behaviour_guard.models import Contract, IdentitySpec, ServerSpec


def _payload(
    *,
    url: str = "https://mcp.example.test/mcp",
    allowed_origins: list[str] | None = None,
    allow_redirects: bool = False,
    allowed_hosts: list[str] | None = None,
    target_allowlist: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "version": 1,
        "server": {
            "name": "restricted-http",
            "transport": "streamable-http",
            "url": url,
            "allowed_hosts": allowed_hosts if allowed_hosts is not None else ["legacy.invalid"],
            "http_destination": {
                "allowed_origins": (
                    allowed_origins if allowed_origins is not None else ["https://mcp.example.test"]
                ),
                "allow_redirects": allow_redirects,
            },
        },
        "identities": {
            "reviewer": {
                "headers": {
                    "Authorization": "Bearer test-only",
                    "X-Identity": "reviewer",
                }
            }
        },
        "tools": {
            "read": {
                "permitted_identities": ["reviewer"],
                "read_only": True,
            }
        },
        "safety": {
            "target_allowlist": (
                target_allowlist if target_allowlist is not None else ["other-legacy.invalid"]
            )
        },
    }


def _contract(**kwargs: Any) -> Contract:
    return Contract.model_validate(_payload(**kwargs))


def test_http_destination_policy_is_additive_and_keeps_contract_v1() -> None:
    contract = _contract()
    assert contract.version == 1
    assert contract.server.http_destination is not None
    assert contract.server.http_destination.allowed_origins == ["https://mcp.example.test"]
    assert contract.server.http_destination.allow_redirects is False


def test_legacy_http_serialization_omits_absent_destination_policy() -> None:
    server = ServerSpec(
        name="legacy-http",
        transport="streamable-http",
        url="http://127.0.0.1:8000/mcp",
    )
    assert "http_destination" not in server.model_dump(mode="json")

    contract = Contract.model_validate(
        {
            "version": 1,
            "server": {
                "name": "legacy-http",
                "transport": "streamable-http",
                "url": "http://127.0.0.1:8000/mcp",
            },
            "identities": {"reviewer": {}},
            "tools": {
                "read": {
                    "permitted_identities": ["reviewer"],
                    "read_only": True,
                }
            },
        }
    )
    assert "http_destination" not in contract.model_dump(mode="json")["server"]


def test_http_destination_policy_is_rejected_for_stdio() -> None:
    with pytest.raises(
        ValidationError,
        match="http_destination.*streamable-http|streamable-http.*http_destination",
    ):
        ServerSpec.model_validate(
            {
                "name": "stdio",
                "transport": "stdio",
                "command": "python",
                "http_destination": {
                    "allowed_origins": ["https://mcp.example.test"],
                },
            }
        )


def test_restricted_http_requires_at_least_one_allowed_origin() -> None:
    contract = _contract(allowed_origins=[])
    with pytest.raises(ContractError, match="origin|destination|allow"):
        validate_target(contract, lab_mode=False)


@pytest.mark.parametrize(
    "origin",
    [
        "ftp://mcp.example.test",
        "file:///tmp/mcp",
        "mailto:user@example.test",
    ],
)
def test_restricted_http_rejects_non_http_origins(origin: str) -> None:
    contract = _contract(allowed_origins=[origin])
    with pytest.raises(ContractError, match="http|https|scheme|origin"):
        validate_target(contract, lab_mode=False)


@pytest.mark.parametrize(
    "origin",
    [
        "https://user:secret@mcp.example.test",
        "https://mcp.example.test/private",
        "https://mcp.example.test?tenant=a",
        "https://mcp.example.test#fragment",
    ],
)
def test_restricted_http_rejects_non_origin_allowlist_entries(origin: str) -> None:
    contract = _contract(allowed_origins=[origin])
    with pytest.raises(ContractError, match="origin|userinfo|path|query|fragment"):
        validate_target(contract, lab_mode=False)


def test_restricted_http_rejects_userinfo_in_configured_target_url() -> None:
    contract = _contract(url="https://user:secret@mcp.example.test/mcp")
    with pytest.raises(ContractError, match="userinfo|credential|url|origin"):
        validate_target(contract, lab_mode=False)


def test_restricted_http_initial_origin_must_be_approved() -> None:
    contract = _contract(
        url="https://unapproved.example.test/mcp",
        allowed_origins=["https://mcp.example.test"],
    )
    with pytest.raises(ContractError, match="origin|destination|allow"):
        validate_target(contract, lab_mode=False)


def test_restricted_http_normalizes_hostname_case_trailing_dot_and_default_port() -> None:
    contract = _contract(
        url="https://MCP.EXAMPLE.TEST.:443/mcp",
        allowed_origins=["https://mcp.example.test"],
    )
    validate_target(contract, lab_mode=False)


def test_restricted_http_non_default_port_is_part_of_destination_identity() -> None:
    contract = _contract(
        url="https://mcp.example.test:8443/mcp",
        allowed_origins=["https://mcp.example.test"],
    )
    with pytest.raises(ContractError, match="origin|destination|port|allow"):
        validate_target(contract, lab_mode=False)


def test_restricted_http_scheme_is_part_of_destination_identity() -> None:
    contract = _contract(
        url="http://mcp.example.test/mcp",
        allowed_origins=["https://mcp.example.test"],
    )
    with pytest.raises(ContractError, match="origin|destination|scheme|allow"):
        validate_target(contract, lab_mode=False)


def test_restricted_http_does_not_require_legacy_hostname_approval() -> None:
    contract = _contract(
        allowed_hosts=["not-approved-by-legacy.example"],
        target_allowlist=["also-not-approved-by-legacy.example"],
    )
    validate_target(contract, lab_mode=False)


class _DummyAsyncClient:
    captured_kwargs: dict[str, Any] = {}

    def __init__(self, **kwargs: Any) -> None:
        type(self).captured_kwargs = kwargs

    async def __aenter__(self) -> _DummyAsyncClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        del args


@asynccontextmanager
async def _fake_streamable_http_client(
    url: str,
    *,
    http_client: Any,
) -> Any:
    del url, http_client
    yield object(), object(), lambda: "session-id"


class _DummySession:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        del args, kwargs

    async def __aenter__(self) -> _DummySession:
        return self

    async def __aexit__(self, *args: Any) -> None:
        del args

    async def initialize(self) -> Any:
        return SimpleNamespace(protocolVersion="test")


async def _capture_restricted_client_kwargs(
    monkeypatch: pytest.MonkeyPatch,
    *,
    allow_redirects: bool,
) -> tuple[Contract, dict[str, Any]]:
    _DummyAsyncClient.captured_kwargs = {}
    monkeypatch.setattr(client_module.httpx, "AsyncClient", _DummyAsyncClient)
    monkeypatch.setattr(client_module, "streamable_http_client", _fake_streamable_http_client)
    monkeypatch.setattr(client_module, "ClientSession", _DummySession)

    contract = _contract(allow_redirects=allow_redirects)
    client = McpClient(contract.server, "reviewer", contract.identities["reviewer"])

    async with client._http_session(None):
        pass

    return contract, _DummyAsyncClient.captured_kwargs


@pytest.mark.asyncio
async def test_restricted_http_redirects_are_disabled_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, kwargs = await _capture_restricted_client_kwargs(monkeypatch, allow_redirects=False)
    assert kwargs["follow_redirects"] is False


@pytest.mark.asyncio
async def test_restricted_http_disables_ambient_httpx_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, kwargs = await _capture_restricted_client_kwargs(monkeypatch, allow_redirects=False)
    assert kwargs["trust_env"] is False


@pytest.mark.asyncio
async def test_restricted_http_runtime_request_hook_accepts_approved_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, kwargs = await _capture_restricted_client_kwargs(monkeypatch, allow_redirects=True)
    assert kwargs["follow_redirects"] is True
    hooks = kwargs["event_hooks"]["request"]
    assert len(hooks) >= 1

    request = httpx.Request("GET", "https://mcp.example.test/redirected/path")
    for hook in hooks:
        result = hook(request)
        if result is not None:
            await result


@pytest.mark.asyncio
async def test_restricted_http_runtime_request_hook_rejects_unapproved_redirect_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, kwargs = await _capture_restricted_client_kwargs(monkeypatch, allow_redirects=True)
    hooks = kwargs["event_hooks"]["request"]
    request = httpx.Request("GET", "https://evil.example.test/mcp")

    with pytest.raises(ContractError, match="origin|destination|allow"):
        for hook in hooks:
            result = hook(request)
            if result is not None:
                await result


@pytest.mark.asyncio
async def test_restricted_http_runtime_request_hook_rejects_unapproved_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, kwargs = await _capture_restricted_client_kwargs(monkeypatch, allow_redirects=True)
    hooks = kwargs["event_hooks"]["request"]
    request = httpx.Request("GET", "https://mcp.example.test:8443/mcp")

    with pytest.raises(ContractError, match="origin|destination|port|allow"):
        for hook in hooks:
            result = hook(request)
            if result is not None:
                await result


@pytest.mark.asyncio
async def test_restricted_http_runtime_request_hook_allows_explicit_second_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _DummyAsyncClient.captured_kwargs = {}
    monkeypatch.setattr(client_module.httpx, "AsyncClient", _DummyAsyncClient)
    monkeypatch.setattr(client_module, "streamable_http_client", _fake_streamable_http_client)
    monkeypatch.setattr(client_module, "ClientSession", _DummySession)

    contract = _contract(
        allow_redirects=True,
        allowed_origins=[
            "https://mcp.example.test",
            "https://redirect.example.test:8443",
        ],
    )
    client = McpClient(contract.server, "reviewer", contract.identities["reviewer"])

    async with client._http_session(None):
        pass

    hooks = _DummyAsyncClient.captured_kwargs["event_hooks"]["request"]
    request = httpx.Request("GET", "https://redirect.example.test:8443/mcp")
    for hook in hooks:
        result = hook(request)
        if result is not None:
            await result


@pytest.mark.asyncio
async def test_legacy_http_client_keeps_existing_redirect_and_environment_behavior(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _DummyAsyncClient.captured_kwargs = {}
    monkeypatch.setattr(client_module.httpx, "AsyncClient", _DummyAsyncClient)
    monkeypatch.setattr(client_module, "streamable_http_client", _fake_streamable_http_client)
    monkeypatch.setattr(client_module, "ClientSession", _DummySession)

    server = ServerSpec(
        name="legacy",
        transport="streamable-http",
        url="http://127.0.0.1:8000/mcp",
    )
    client = McpClient(server, "reviewer", IdentitySpec())

    async with client._http_session(None):
        pass

    kwargs = _DummyAsyncClient.captured_kwargs
    assert kwargs["follow_redirects"] is True
    assert "trust_env" not in kwargs
    assert "event_hooks" not in kwargs


def test_restricted_http_normalizes_ipv6_literal_and_default_port() -> None:
    contract = _contract(
        url="https://[0:0:0:0:0:0:0:1]:443/mcp",
        allowed_origins=["https://[::1]"],
    )
    validate_target(contract, lab_mode=False)


def test_restricted_http_rejects_invalid_allowlist_port() -> None:
    contract = _contract(allowed_origins=["https://mcp.example.test:70000"])
    with pytest.raises(ContractError, match="port|origin|destination"):
        validate_target(contract, lab_mode=False)


def test_restricted_http_rejects_invalid_target_port() -> None:
    contract = _contract(url="https://mcp.example.test:70000/mcp")
    with pytest.raises(ContractError, match="port|origin|destination"):
        validate_target(contract, lab_mode=False)


@pytest.mark.asyncio
async def test_restricted_http_actual_client_rejects_unapproved_initial_origin_without_preflight(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _DummyAsyncClient.captured_kwargs = {}
    monkeypatch.setattr(client_module.httpx, "AsyncClient", _DummyAsyncClient)
    monkeypatch.setattr(client_module, "streamable_http_client", _fake_streamable_http_client)
    monkeypatch.setattr(client_module, "ClientSession", _DummySession)

    contract = _contract(
        url="https://unapproved.example.test/mcp",
        allowed_origins=["https://mcp.example.test"],
    )
    client = McpClient(contract.server, "reviewer", contract.identities["reviewer"])

    with pytest.raises(ContractError, match="target origin.*not allowlisted"):
        async with client._http_session(None):
            pass

    assert _DummyAsyncClient.captured_kwargs == {}


@pytest.mark.asyncio
async def test_restricted_http_real_redirect_is_blocked_before_disallowed_transport_send(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent_urls: list[str] = []
    original_async_client = httpx.AsyncClient

    def transport_handler(request: httpx.Request) -> httpx.Response:
        sent_urls.append(str(request.url))
        if request.url.host == "mcp.example.test":
            return httpx.Response(
                302,
                headers={"Location": "https://evil.example.test/mcp"},
                request=request,
            )
        raise AssertionError("disallowed redirect reached the HTTP transport")

    def async_client_factory(**kwargs: Any) -> httpx.AsyncClient:
        return original_async_client(
            transport=httpx.MockTransport(transport_handler),
            **kwargs,
        )

    @asynccontextmanager
    async def redirecting_streamable_http_client(
        url: str,
        *,
        http_client: httpx.AsyncClient,
    ) -> Any:
        await http_client.get(url)
        yield object(), object(), lambda: "session-id"

    monkeypatch.setattr(client_module.httpx, "AsyncClient", async_client_factory)
    monkeypatch.setattr(
        client_module,
        "streamable_http_client",
        redirecting_streamable_http_client,
    )

    contract = _contract(allow_redirects=True)
    client = McpClient(contract.server, "reviewer", contract.identities["reviewer"])

    with pytest.raises(ContractError, match="request origin.*not allowlisted"):
        async with client._http_session(None):
            pass

    assert sent_urls == ["https://mcp.example.test/mcp"]
