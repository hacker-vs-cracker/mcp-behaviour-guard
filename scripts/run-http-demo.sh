#!/usr/bin/env bash
set -euo pipefail

docker compose up --build -d
mcp-guard doctor contracts/http-demo.yaml
mcp-guard run contracts/http-demo.yaml --lab-mode --no-fail
