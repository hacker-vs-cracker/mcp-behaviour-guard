from __future__ import annotations

import json
from pathlib import Path

from mcp_behaviour_guard.host_config import (
    compare_host_config_snapshots,
    snapshot_host_config,
)


def _write_config(path: Path, payload: dict[str, object]) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_host_snapshot_redacts_credentials_and_keeps_env_references(tmp_path: Path) -> None:
    config = _write_config(
        tmp_path / "mcp.json",
        {
            "servers": {
                "local-tools": {
                    "type": "stdio",
                    "command": "python",
                    "args": ["-m", "local_tools"],
                    "env": {
                        "API_TOKEN": "actual-secret-value",
                        "MODE": "development",
                        "FROM_SHELL": "${LOCAL_MCP_TOKEN}",
                    },
                }
            }
        },
    )

    snapshot = snapshot_host_config(config, host_label="VS Code")
    server = snapshot["servers"]["local-tools"]

    assert server["environment"]["API_TOKEN"] == "<redacted>"
    assert server["environment"]["FROM_SHELL"] == "${LOCAL_MCP_TOKEN}"
    assert server["environment"]["MODE"].startswith("sha256:")
    assert "actual-secret-value" not in json.dumps(snapshot)


def test_host_config_diff_flags_added_removed_and_changed_servers(tmp_path: Path) -> None:
    approved_path = _write_config(
        tmp_path / "approved.json",
        {
            "mcpServers": {
                "local-tools": {"command": "python", "args": ["-m", "tools.v1"]},
                "retired": {"url": "https://old.example.test/mcp"},
            }
        },
    )
    current_path = _write_config(
        tmp_path / "current.json",
        {
            "mcpServers": {
                "local-tools": {"command": "python", "args": ["-m", "tools.v2"]},
                "new-remote": {"url": "https://new.example.test/mcp"},
            }
        },
    )

    approved = snapshot_host_config(approved_path, host_label="editor")
    current = snapshot_host_config(current_path, host_label="editor")
    diff = compare_host_config_snapshots(approved, current)

    assert diff["drift_detected"] is True
    assert diff["added_servers"] == ["new-remote"]
    assert diff["removed_servers"] == ["retired"]
    assert list(diff["changed_servers"]) == ["local-tools"]


def test_nested_mcp_servers_mapping_is_supported(tmp_path: Path) -> None:
    config = _write_config(
        tmp_path / "nested.json",
        {"mcp": {"servers": {"remote": {"url": "https://example.test/mcp"}}}},
    )

    snapshot = snapshot_host_config(config)

    assert snapshot["servers"]["remote"]["transport"] == "streamable-http"


def test_vscode_json_with_comments_is_supported(tmp_path: Path) -> None:
    config = tmp_path / "mcp.json"
    config.write_text(
        """{
          // Workspace MCP server used by the demo
          "servers": {
            "local-tools": {
              "type": "stdio",
              "command": "python",
              "args": ["-m", "tools"], /* keep the module explicit */
            },
          },
        }""",
        encoding="utf-8",
    )

    snapshot = snapshot_host_config(config, host_label="VS Code")

    assert snapshot["servers"]["local-tools"]["command"] == "python"


def test_host_snapshot_redacts_url_credentials_and_secret_args(tmp_path: Path) -> None:
    config = _write_config(
        tmp_path / "mcp.json",
        {
            "servers": {
                "remote": {
                    "url": "https://user:pass@example.test/mcp?token=abc&region=nz",
                    "command": "ignored",
                    "args": [
                        "--api-key=literal-secret",
                        "--token",
                        "other-secret",
                        "--mode",
                        "safe",
                    ],
                }
            }
        },
    )

    snapshot = snapshot_host_config(config)
    server = snapshot["servers"]["remote"]

    assert "user:pass" not in server["url"]
    assert "token=%3Credacted%3E" in server["url"]
    assert server["args"][:3] == ["--api-key=<redacted>", "--token", "<redacted>"]


def test_json5_style_nested_server_mapping_is_supported(tmp_path: Path) -> None:
    config = tmp_path / "host-config.json"
    config.write_text(
        """{
          mcp: {
            servers: {
              docs: {
                command: "npx",
                args: ["-y", "@modelcontextprotocol/server-memory",],
              },
            },
          },
        }""",
        encoding="utf-8",
    )

    snapshot = snapshot_host_config(config, host_label="JSON5 Host")

    assert snapshot["servers"]["docs"]["command"] == "npx"


def test_host_snapshot_tracks_vscode_security_controls_without_copying_values(
    tmp_path: Path,
) -> None:
    config = _write_config(
        tmp_path / "mcp.json",
        {
            "servers": {
                "local-tools": {
                    "type": "stdio",
                    "command": "python",
                    "envFile": "/private/project/.env",
                    "sandboxEnabled": True,
                    "dev": {"watch": "src/**/*.py"},
                }
            },
            "sandbox": {
                "filesystem": {"allowWrite": ["${workspaceFolder}"]},
                "network": {"allowedDomains": ["api.internal.example"]},
            },
        },
    )

    snapshot = snapshot_host_config(config, host_label="VS Code")
    encoded = json.dumps(snapshot)

    server = snapshot["servers"]["local-tools"]
    assert server["other"]["sandboxEnabled"] is True
    assert server["other"]["envFile"].startswith("sha256:")
    assert snapshot["host_controls"]["sandbox"]
    assert "/private/project/.env" not in encoded
    assert "api.internal.example" not in encoded


def test_host_diff_catches_filter_and_enablement_changes(tmp_path: Path) -> None:
    approved_path = _write_config(
        tmp_path / "approved.json",
        {
            "mcp": {
                "servers": {
                    "docs": {
                        "url": "https://example.test/mcp",
                        "transport": "streamable-http",
                        "enabled": True,
                        "toolFilter": {"include": ["search_*"]},
                    }
                }
            }
        },
    )
    current_path = _write_config(
        tmp_path / "current.json",
        {
            "mcp": {
                "servers": {
                    "docs": {
                        "url": "https://example.test/mcp",
                        "transport": "streamable-http",
                        "enabled": False,
                        "toolFilter": {"include": ["*"]},
                    }
                }
            }
        },
    )

    approved = snapshot_host_config(approved_path, host_label="JSON5 Host")
    current = snapshot_host_config(current_path, host_label="JSON5 Host")
    diff = compare_host_config_snapshots(approved, current)

    assert diff["drift_detected"] is True
    assert list(diff["changed_servers"]) == ["docs"]


def test_host_diff_catches_top_level_sandbox_change(tmp_path: Path) -> None:
    approved_path = _write_config(
        tmp_path / "approved.json",
        {
            "servers": {"local": {"command": "python"}},
            "sandbox": {"network": {"allowedDomains": ["api.example.test"]}},
        },
    )
    current_path = _write_config(
        tmp_path / "current.json",
        {
            "servers": {"local": {"command": "python"}},
            "sandbox": {"network": {"allowedDomains": ["*"]}},
        },
    )

    approved = snapshot_host_config(approved_path, host_label="VS Code")
    current = snapshot_host_config(current_path, host_label="VS Code")
    diff = compare_host_config_snapshots(approved, current)

    assert diff["drift_detected"] is True
    assert diff["host_controls_changed"] is True


def test_host_snapshot_redacts_hyphenated_api_key_query_parameter(tmp_path: Path) -> None:
    config = _write_config(
        tmp_path / "mcp.json",
        {"servers": {"remote": {"url": "https://example.test/mcp?api-key=do-not-store&region=nz"}}},
    )

    snapshot = snapshot_host_config(config)
    encoded = json.dumps(snapshot)

    assert "do-not-store" not in encoded
    assert "region=nz" not in encoded
    assert "api-key=%3Credacted%3E" in snapshot["servers"]["remote"]["url"]
