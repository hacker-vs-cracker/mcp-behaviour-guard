from __future__ import annotations

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

from .models import IdentitySpec, InvocationRecord, ServerSpec


class McpClient:
    def __init__(self, server: ServerSpec, identity_name: str, identity: IdentitySpec) -> None:
        self.server = server
        self.identity_name = identity_name
        self.identity = identity

    @asynccontextmanager
    async def session(self) -> AsyncIterator[tuple[ClientSession, str | None]]:
        if self.server.transport == "streamable-http":
            async with self._http_session() as current:
                yield current
            return

        async with self._stdio_session() as current:
            yield current

    @asynccontextmanager
    async def _http_session(self) -> AsyncIterator[tuple[ClientSession, str | None]]:
        if not self.server.url:
            raise ValueError("streamable-http target is missing server.url")
        timeout = httpx.Timeout(self.server.timeout_seconds)
        async with (
            httpx.AsyncClient(
                headers=self.identity.headers,
                timeout=timeout,
                verify=self.server.verify_tls,
                follow_redirects=True,
            ) as http_client,
            streamable_http_client(
                self.server.url,
                http_client=http_client,
            ) as (read_stream, write_stream, get_session_id),
            ClientSession(read_stream, write_stream) as session,
        ):
            await session.initialize()
            yield session, get_session_id()

    @asynccontextmanager
    async def _stdio_session(self) -> AsyncIterator[tuple[ClientSession, str | None]]:
        if not self.server.command:
            raise ValueError("stdio target is missing server.command")
        environment = dict(os.environ)
        environment.update(self.server.environment)
        environment.update(self.identity.environment)
        environment.setdefault("MCP_GUARD_IDENTITY", self.identity_name)
        if self.identity.tenant is not None:
            environment.setdefault("MCP_GUARD_TENANT", self.identity.tenant)
        if self.identity.role is not None:
            environment.setdefault("MCP_GUARD_ROLE", self.identity.role)

        parameters = StdioServerParameters(
            command=self.server.command,
            args=self.server.args,
            env=environment,
            cwd=self.server.cwd,
        )
        async with (
            stdio_client(parameters) as (read_stream, write_stream),
            ClientSession(read_stream, write_stream) as session,
        ):
            await session.initialize()
            yield session, None

    async def list_tools(self) -> list[dict[str, Any]]:
        async with self.session() as (session, _):
            result = await session.list_tools()
            return [tool.model_dump(mode="json", by_alias=True) for tool in result.tools]

    async def invoke(
        self,
        test_id: str,
        tool: str,
        arguments: dict[str, Any],
    ) -> InvocationRecord:
        started = perf_counter()
        session_id: str | None = None
        try:
            async with self.session() as (session, current_session_id):
                session_id = current_session_id
                result = await session.call_tool(tool, arguments=arguments)
                response = _normalise_tool_result(result)
                is_error = bool(getattr(result, "isError", False))
                return InvocationRecord(
                    test_id=test_id,
                    tool=tool,
                    identity=self.identity_name,
                    arguments=arguments,
                    allowed=not is_error,
                    response=response,
                    error="tool returned isError=true" if is_error else None,
                    duration_ms=(perf_counter() - started) * 1000,
                    session_id=session_id,
                )
        except Exception as exc:
            return InvocationRecord(
                test_id=test_id,
                tool=tool,
                identity=self.identity_name,
                arguments=arguments,
                allowed=False,
                error=str(exc),
                duration_ms=(perf_counter() - started) * 1000,
                session_id=session_id,
            )


def _normalise_tool_result(result: Any) -> Any:
    structured = getattr(result, "structuredContent", None)
    if structured is not None:
        return structured

    content = getattr(result, "content", None)
    if not content:
        return (
            result.model_dump(mode="json", by_alias=True)
            if hasattr(result, "model_dump")
            else result
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
