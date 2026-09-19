from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from mcp_behaviour_guard import cli


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ((3, 10), False),
        ((3, 11), True),
        ((3, 12), True),
        ((3, 13), True),
        ((3, 14), True),
        ((3, 15), False),
    ],
)
def test_supported_python_runtime_range(
    version: tuple[int, int],
    expected: bool,
) -> None:
    assert cli._python_version_supported(version) is expected


def test_package_metadata_matches_supported_python_range() -> None:
    project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))["project"]

    assert project["requires-python"] == ">=3.11,<3.15"

    classifiers = set(project["classifiers"])
    for minor in ("3.11", "3.12", "3.13", "3.14"):
        assert f"Programming Language :: Python :: {minor}" in classifiers
