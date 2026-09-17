from __future__ import annotations

from fnmatch import fnmatch
from pathlib import Path

from ..models import FilesystemObserverSpec, SideEffectKind
from ..util import file_sha256
from .base import SideEffectEvent

SnapshotKey = tuple[int, str]
SnapshotValue = tuple[str, int, str]


class FilesystemObserver:
    def __init__(self, name: str, spec: FilesystemObserverSpec) -> None:
        self.name = name
        self.spec = spec
        self.observes = set(spec.observes)
        self.complete_observes: set[SideEffectKind] = set()
        self._before: dict[SnapshotKey, SnapshotValue] = {}

    async def begin(self) -> None:
        self._before = self._snapshot()

    async def collect(self) -> list[SideEffectEvent]:
        after = self._snapshot()
        events: list[SideEffectEvent] = []

        for key, current in after.items():
            previous = self._before.get(key)
            if previous == current:
                continue
            display_path = current[0]
            events.append(
                SideEffectEvent(
                    observer=self.name,
                    kind=SideEffectKind.FILESYSTEM_WRITE,
                    details={
                        "path": display_path,
                        "operation": "created" if previous is None else "modified",
                    },
                )
            )

        for key in self._before.keys() - after.keys():
            display_path = self._before[key][0]
            events.append(
                SideEffectEvent(
                    observer=self.name,
                    kind=SideEffectKind.FILESYSTEM_WRITE,
                    details={"path": display_path, "operation": "deleted"},
                )
            )
        return events

    def _snapshot(self) -> dict[SnapshotKey, SnapshotValue]:
        snapshot: dict[SnapshotKey, SnapshotValue] = {}
        for root_index, root in enumerate(self.spec.roots):
            if not root.exists():
                raise FileNotFoundError(f"filesystem observation root is missing: {root}")
            if not root.is_dir():
                raise NotADirectoryError(f"filesystem observation root is not a directory: {root}")

            for path in root.rglob("*"):
                if not path.is_file() or self._ignored(path.name):
                    continue
                relative_path = path.relative_to(root).as_posix()
                root_label = self._root_label(root_index, root)
                display_path = f"{root_label}/{relative_path}"
                stat = path.stat()
                snapshot[(root_index, relative_path)] = (
                    display_path,
                    stat.st_size,
                    file_sha256(path),
                )
        return snapshot

    def _root_label(self, root_index: int, root: Path) -> str:
        base = root.name or "root"
        duplicates = sum(1 for candidate in self.spec.roots if (candidate.name or "root") == base)
        return f"{base}#{root_index + 1}" if duplicates > 1 else base

    def _ignored(self, name: str) -> bool:
        return any(fnmatch(name, pattern) for pattern in self.spec.ignore)
