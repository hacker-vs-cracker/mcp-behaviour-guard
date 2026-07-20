from __future__ import annotations

from fnmatch import fnmatch

from ..models import FilesystemObserverSpec, SideEffectKind
from ..util import file_sha256
from .base import SideEffectEvent


class FilesystemObserver:
    def __init__(self, name: str, spec: FilesystemObserverSpec) -> None:
        self.name = name
        self.spec = spec
        self._before: dict[str, tuple[int, str]] = {}

    async def begin(self) -> None:
        self._before = self._snapshot()

    async def collect(self) -> list[SideEffectEvent]:
        after = self._snapshot()
        events: list[SideEffectEvent] = []

        for path, fingerprint in after.items():
            previous = self._before.get(path)
            if previous == fingerprint:
                continue
            events.append(
                SideEffectEvent(
                    observer=self.name,
                    kind=SideEffectKind.FILESYSTEM_WRITE,
                    details={
                        "path": path,
                        "operation": "created" if previous is None else "modified",
                    },
                )
            )
        return events

    def _snapshot(self) -> dict[str, tuple[int, str]]:
        snapshot: dict[str, tuple[int, str]] = {}
        for root in self.spec.roots:
            if not root.exists():
                continue
            for path in root.rglob("*"):
                if not path.is_file() or self._ignored(path.name):
                    continue
                relative = f"{root.name}/{path.relative_to(root).as_posix()}"
                stat = path.stat()
                snapshot[relative] = (stat.st_size, file_sha256(path))
        return snapshot

    def _ignored(self, name: str) -> bool:
        return any(fnmatch(name, pattern) for pattern in self.spec.ignore)
