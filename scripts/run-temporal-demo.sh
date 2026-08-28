#!/usr/bin/env bash
set -euo pipefail

python -m mcp_behaviour_guard.cli doctor contracts/temporal-demo.yaml
python -m mcp_behaviour_guard.cli run contracts/temporal-demo.yaml --no-fail
