from pathlib import Path

import pytest

from mcp_behaviour_guard.models import FilesystemObserverSpec, SideEffectKind
from mcp_behaviour_guard.observers.filesystem import FilesystemObserver


@pytest.mark.asyncio
async def test_filesystem_observer_detects_new_file(tmp_path: Path) -> None:
    observer = FilesystemObserver(
        "workspace",
        FilesystemObserverSpec(type="filesystem", roots=[tmp_path]),
    )
    await observer.begin()
    (tmp_path / "evidence.txt").write_text("changed", encoding="utf-8")

    events = await observer.collect()

    assert len(events) == 1
    assert events[0].kind == SideEffectKind.FILESYSTEM_WRITE
