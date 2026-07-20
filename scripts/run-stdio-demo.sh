#!/usr/bin/env bash
set -euo pipefail

export DEMO_AGENT_TOKEN="${DEMO_AGENT_TOKEN:-local-demo-token}"
mcp-guard doctor contracts/stdio-demo.yaml
mcp-guard run contracts/stdio-demo.yaml --lab-mode --no-fail
