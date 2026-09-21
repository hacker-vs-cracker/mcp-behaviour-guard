from __future__ import annotations

import asyncio
import json
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from time import perf_counter
from typing import Any

import httpx
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client

from .config import (
    resolve_restricted_http_destination,
    resolve_restricted_stdio_launch,
    validate_restricted_http_request_url,
)
from .models import (
    AuthorizationStatus,
    ExecutionStatus,
    IdentitySpec,
    InvocationRecord,
    ServerSpec,
    TemporalIntegritySpec,
)


class McpClient:
    def __init__(self, server: ServerSpec, identity_name: str, identity: IdentitySpec) -> None:
        self.server = server
        self.identity_name = identity_name
        self.identity = identity
        self.protocol_version: str | None = None

    @asynccontextmanager
    async def session(
        self,
        notification_sink: list[str] | None = None,
    ) -> AsyncIterator[tuple[ClientSession, str | None]]:
        if self.server.transport == "streamable-http":
            async with self._http_session(notification_sink) as current:
                yield current
            return

        async with self._stdio_session(notification_sink) as current:
            yield current

    @asynccontextmanager
    async def _http_session(
        self,
        notification_sink: list[str] | None,
    ) -> AsyncIterator[tuple[ClientSession, str | None]]:
        if not self.server.url:
            raise ValueError("streamable-http target is missing server.url")

        timeout = httpx.Timeout(self.server.timeout_seconds)
        if self.server.http_destination is not None:
            allowed_origins, allow_redirects = resolve_restricted_http_destination(self.server)

            async def enforce_destination(request: httpx.Request) -> None:
                validate_restricted_http_request_url(
                    str(request.url),
                    allowed_origins,
                )

            http_client = httpx.AsyncClient(
                headers=self.identity.headers,
                timeout=timeout,
                verify=self.server.verify_tls,
                follow_redirects=allow_redirects,
                trust_env=False,
                event_hooks={"request": [enforce_destination]},
            )
        else:
            http_client = httpx.AsyncClient(
                headers=self.identity.headers,
                timeout=timeout,
                verify=self.server.verify_tls,
                follow_redirects=True,
            )

        async with (
            http_client,
            streamable_http_client(
                self.server.url,
                http_client=http_client,
            ) as (read_stream, write_stream, get_session_id),
            ClientSession(
                read_stream,
                write_stream,
                message_handler=_notification_handler(notification_sink),
            ) as session,
        ):
            initialised = await session.initialize()
            self.protocol_version = str(getattr(initialised, "protocolVersion", "unknown"))
            yield session, get_session_id()

    @asynccontextmanager
    async def _stdio_session(
        self,
        notification_sink: list[str] | None,
    ) -> AsyncIterator[tuple[ClientSession, str | None]]:
        if not self.server.command:
            raise ValueError("stdio target is missing server.command")

        command = self.server.command or ""
        cwd = self.server.cwd
        launch = self.server.stdio_launch
        if launch is not None and launch.mode == "restricted":
            command, canonical_cwd = resolve_restricted_stdio_launch(self.server)
            cwd = canonical_cwd
            environment = {
                name: os.environ[name] for name in launch.inherit_environment if name in os.environ
            }
            restricted = True
        else:
            environment = dict(os.environ)
            restricted = False

        environment.update(self.server.environment)
        environment.update(self.identity.environment)

        if restricted:
            environment["MCP_GUARD_IDENTITY"] = self.identity_name
            if self.identity.tenant is None:
                environment.pop("MCP_GUARD_TENANT", None)
            else:
                environment["MCP_GUARD_TENANT"] = self.identity.tenant
            if self.identity.role is None:
                environment.pop("MCP_GUARD_ROLE", None)
            else:
                environment["MCP_GUARD_ROLE"] = self.identity.role
        else:
            environment.setdefault("MCP_GUARD_IDENTITY", self.identity_name)
            if self.identity.tenant is not None:
                environment.setdefault("MCP_GUARD_TENANT", self.identity.tenant)
            if self.identity.role is not None:
                environment.setdefault("MCP_GUARD_ROLE", self.identity.role)

        parameters = StdioServerParameters(
            command=command,
            args=self.server.args,
            env=environment,
            cwd=cwd,
        )
        async with (
            stdio_client(parameters) as (read_stream, write_stream),
            ClientSession(
                read_stream,
                write_stream,
                message_handler=_notification_handler(notification_sink),
            ) as session,
        ):
            initialised = await session.initialize()
            self.protocol_version = str(getattr(initialised, "protocolVersion", "unknown"))
            yield session, None

    async def list_tools(self) -> list[dict[str, Any]]:
        async with self.session() as (session, _):
            return await _list_tools(session)

    async def invoke(
        self,
        test_id: str,
        tool: str,
        arguments: dict[str, Any],
        denial_error_markers: list[str] | None = None,
        *,
        meta: dict[str, Any] | None = None,
    ) -> InvocationRecord:
        started = perf_counter()
        try:
            async with self.session() as (session, session_id):
                return await self.invoke_on_session(
                    session=session,
                    session_id=session_id,
                    test_id=test_id,
                    tool=tool,
                    arguments=arguments,
                    denial_error_markers=denial_error_markers,
                    meta=meta,
                )
        except Exception as exc:
            return InvocationRecord(
                test_id=test_id,
                tool=tool,
                identity=self.identity_name,
                arguments=arguments,
                allowed=None,
                authorization=AuthorizationStatus.UNKNOWN,
                execution=_exception_execution(exc),
                error=str(exc),
                duration_ms=(perf_counter() - started) * 1000,
                session_id=None,
                protocol_version=self.protocol_version,
                transport=self.server.transport,
            )

    async def invoke_on_session(
        self,
        session: ClientSession,
        session_id: str | None,
        test_id: str,
        tool: str,
        arguments: dict[str, Any],
        denial_error_markers: list[str] | None = None,
        *,
        meta: dict[str, Any] | None = None,
    ) -> InvocationRecord:
        started = perf_counter()
        try:
            if meta is None:
                tool_response = await session.call_tool(tool, arguments=arguments)
            else:
                tool_response = await session.call_tool(
                    tool,
                    arguments=arguments,
                    meta=meta,
                )
            response = _normalise_tool_result(tool_response)
            is_error = bool(getattr(tool_response, "isError", False))
            denied = is_error and _matches_denial_marker(response, denial_error_markers or [])
            return InvocationRecord(
                test_id=test_id,
                tool=tool,
                identity=self.identity_name,
                arguments=arguments,
                allowed=False if denied else None if is_error else True,
                authorization=(
                    AuthorizationStatus.DENY
                    if denied
                    else AuthorizationStatus.UNKNOWN
                    if is_error
                    else AuthorizationStatus.ALLOW
                ),
                execution=ExecutionStatus.REJECTED if is_error else ExecutionStatus.SUCCEEDED,
                response=response,
                error="tool returned isError=true" if is_error else None,
                duration_ms=(perf_counter() - started) * 1000,
                session_id=session_id,
                protocol_version=self.protocol_version,
                transport=self.server.transport,
            )
        except Exception as exc:
            return InvocationRecord(
                test_id=test_id,
                tool=tool,
                identity=self.identity_name,
                arguments=arguments,
                allowed=None,
                authorization=AuthorizationStatus.UNKNOWN,
                execution=_exception_execution(exc),
                error=str(exc),
                duration_ms=(perf_counter() - started) * 1000,
                session_id=session_id,
                protocol_version=self.protocol_version,
                transport=self.server.transport,
            )

    async def metadata_snapshot(
        self,
        session: ClientSession,
        temporal: TemporalIntegritySpec,
    ) -> dict[str, Any]:
        snapshot: dict[str, Any] = {
            "tools": {},
            "prompts": {},
            "prompt_payloads": {},
            "resources": {},
        }
        capabilities = session.get_server_capabilities()

        if temporal.monitor_tools:
            tools = await _list_tools(session)
            snapshot["tools"] = _index_metadata(tools, "name")

        prompts_supported = bool(capabilities and getattr(capabilities, "prompts", None))
        if temporal.monitor_prompts and prompts_supported:
            prompts = await _list_prompts(session)
            snapshot["prompts"] = _index_metadata(prompts, "name")

            prompt_probes = dict(temporal.prompt_probes)
            if temporal.probe_argumentless_prompts:
                for prompt in prompts:
                    prompt_name = prompt.get("name")
                    if not isinstance(prompt_name, str) or prompt_name in prompt_probes:
                        continue
                    if not _prompt_requires_arguments(prompt):
                        prompt_probes[prompt_name] = {}

            for prompt_name, prompt_arguments in prompt_probes.items():
                try:
                    prompt_response = await session.get_prompt(
                        prompt_name,
                        arguments=prompt_arguments,
                    )
                    snapshot["prompt_payloads"][prompt_name] = prompt_response.model_dump(
                        mode="json",
                        by_alias=True,
                        exclude_none=True,
                    )
                except Exception as exc:
                    snapshot["prompt_payloads"][prompt_name] = {
                        "error": str(exc),
                        "error_type": type(exc).__name__,
                    }

        resources_supported = bool(capabilities and getattr(capabilities, "resources", None))
        if temporal.monitor_resources and resources_supported:
            resources = await _list_resources(session)
            snapshot["resources"] = _index_metadata(resources, "uri")

        return snapshot


async def _list_tools(session: ClientSession) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    cursor: str | None = None
    while True:
        response = await session.list_tools(cursor) if cursor else await session.list_tools()
        items.extend(
            tool.model_dump(mode="json", by_alias=True, exclude_none=True)
            for tool in response.tools
        )
        cursor = getattr(response, "nextCursor", None)
        if not cursor:
            return items


async def _list_prompts(session: ClientSession) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    cursor: str | None = None
    while True:
        response = await session.list_prompts(cursor) if cursor else await session.list_prompts()
        items.extend(
            prompt.model_dump(mode="json", by_alias=True, exclude_none=True)
            for prompt in response.prompts
        )
        cursor = getattr(response, "nextCursor", None)
        if not cursor:
            return items


async def _list_resources(session: ClientSession) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    cursor: str | None = None
    while True:
        response = (
            await session.list_resources(cursor) if cursor else await session.list_resources()
        )
        items.extend(
            resource.model_dump(mode="json", by_alias=True, exclude_none=True)
            for resource in response.resources
        )
        cursor = getattr(response, "nextCursor", None)
        if not cursor:
            return items


def _notification_handler(notification_sink: list[str] | None):
    async def handle(message: Any) -> None:
        if notification_sink is None or isinstance(message, Exception):
            return
        root = getattr(message, "root", message)
        method = getattr(root, "method", None)
        if method:
            notification_sink.append(str(method))

    return handle


def _index_metadata(items: list[dict[str, Any]], key: str) -> dict[str, Any]:
    indexed: dict[str, Any] = {}
    for item in items:
        identifier = item.get(key)
        if identifier is None:
            continue
        indexed[str(identifier)] = item
    return {name: indexed[name] for name in sorted(indexed)}


def _normalise_tool_result(tool_response: Any) -> Any:
    structured = getattr(tool_response, "structuredContent", None)
    if structured is not None:
        return structured

    content = getattr(tool_response, "content", None)
    if not content:
        return (
            tool_response.model_dump(mode="json", by_alias=True)
            if hasattr(tool_response, "model_dump")
            else tool_response
        )

    values: list[Any] = []
    for item in content:
        text = getattr(item, "text", None)
        if text is None:
            values.append(
                item.model_dump(mode="json") if hasattr(item, "model_dump") else str(item)
            )
            continue
        try:
            values.append(json.loads(text))
        except json.JSONDecodeError:
            values.append(text)

    return values[0] if len(values) == 1 else values


def _prompt_requires_arguments(prompt: dict[str, Any]) -> bool:
    arguments = prompt.get("arguments", [])
    if not isinstance(arguments, list):
        return False
    return any(isinstance(item, dict) and item.get("required") is True for item in arguments)


def _matches_denial_marker(response: Any, markers: list[str]) -> bool:
    if not markers:
        return False
    text = json.dumps(response, sort_keys=True, default=str).casefold()
    return any(marker.strip() and marker.casefold() in text for marker in markers)


def _exception_execution(exc: Exception) -> ExecutionStatus:
    return (
        ExecutionStatus.TIMEOUT
        if isinstance(exc, (TimeoutError, asyncio.TimeoutError, httpx.TimeoutException))
        else ExecutionStatus.FAILED
    )
