from __future__ import annotations

import logging
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from typing import TextIO

import anyio
import anyio.lowlevel
import mcp.types as types
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
from anyio.streams.text import TextReceiveStream
from mcp import StdioServerParameters
from mcp.client.stdio import (
    PROCESS_TERMINATION_TIMEOUT,
    _create_platform_compatible_process,
    _get_executable_command,
    _terminate_process_tree,
)
from mcp.shared.message import SessionMessage

logger = logging.getLogger(__name__)


@asynccontextmanager
async def restricted_stdio_client(
    server: StdioServerParameters,
    errlog: TextIO = sys.stderr,
) -> AsyncIterator[
    tuple[
        MemoryObjectReceiveStream[SessionMessage | Exception],
        MemoryObjectSendStream[SessionMessage],
    ]
]:
    """Launch STDIO with exactly the environment selected by Behaviour Guard.

    MCP SDK 1.28.1's public stdio_client always merges a default parent
    environment into server.env. Restricted launch must not do that.

    The project pins MCP 1.28.1. Reuse that SDK's process creation and
    termination helpers so launcher, process-group/job-object, shutdown,
    cancellation, and failed-startup behaviour stay aligned with the pinned SDK.
    """
    if server.env is None:
        raise ValueError("restricted STDIO requires an explicit child environment")

    read_stream_writer, read_stream = anyio.create_memory_object_stream[SessionMessage | Exception](
        0
    )
    write_stream, write_stream_reader = anyio.create_memory_object_stream[SessionMessage](0)

    try:
        command = _get_executable_command(server.command)
        process = await _create_platform_compatible_process(
            command=command,
            args=server.args,
            env=dict(server.env),
            errlog=errlog,
            cwd=server.cwd,
        )
    except OSError:
        await read_stream.aclose()
        await write_stream.aclose()
        await read_stream_writer.aclose()
        await write_stream_reader.aclose()
        raise

    async def stdout_reader() -> None:
        assert process.stdout, "Opened process is missing stdout"

        try:
            async with read_stream_writer:
                buffer = ""
                async for chunk in TextReceiveStream(
                    process.stdout,
                    encoding=server.encoding,
                    errors=server.encoding_error_handler,
                ):
                    lines = (buffer + chunk).split("\n")
                    buffer = lines.pop()

                    for line in lines:
                        try:
                            message = types.JSONRPCMessage.model_validate_json(line)
                        except Exception as exc:
                            logger.exception("Failed to parse JSONRPC message from server")
                            await read_stream_writer.send(exc)
                            continue

                        await read_stream_writer.send(SessionMessage(message))
        except anyio.ClosedResourceError:
            await anyio.lowlevel.checkpoint()

    async def stdin_writer() -> None:
        assert process.stdin, "Opened process is missing stdin"

        try:
            async with write_stream_reader:
                async for session_message in write_stream_reader:
                    json_message = session_message.message.model_dump_json(
                        by_alias=True,
                        exclude_none=True,
                    )
                    await process.stdin.send(
                        (json_message + "\n").encode(
                            encoding=server.encoding,
                            errors=server.encoding_error_handler,
                        )
                    )
        except anyio.ClosedResourceError:
            await anyio.lowlevel.checkpoint()

    async with anyio.create_task_group() as task_group, process:
        task_group.start_soon(stdout_reader)
        task_group.start_soon(stdin_writer)
        try:
            yield read_stream, write_stream
        finally:
            if process.stdin:
                with suppress(Exception):
                    await process.stdin.aclose()

            try:
                with anyio.fail_after(PROCESS_TERMINATION_TIMEOUT):
                    await process.wait()
            except TimeoutError:
                await _terminate_process_tree(process)
            except ProcessLookupError:
                pass

            await read_stream.aclose()
            await write_stream.aclose()
            await read_stream_writer.aclose()
            await write_stream_reader.aclose()
