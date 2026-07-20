.PHONY: install lint format test demo-up demo-down demo-http demo-stdio run-demo clean

install:
	python -m pip install -e '.[dev]'

lint:
	ruff format --check .
	ruff check .
	mypy src/mcp_behaviour_guard

format:
	ruff format .
	ruff check --fix .

test:
	pytest

demo-up:
	docker compose up --build -d

demo-down:
	docker compose down -v

demo-http:
	mcp-guard run contracts/http-demo.yaml --lab-mode --no-fail

demo-stdio:
	DEMO_AGENT_TOKEN=local-demo-token mcp-guard run contracts/stdio-demo.yaml --lab-mode --no-fail

run-demo: demo-http

clean:
	rm -rf .guard reports reports-http reports-stdio baselines ai-suggestions.json baseline-diff.json
	find demo_runtime -type f ! -name .gitkeep -delete
