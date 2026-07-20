# Contributing

## Local checks

```bash
python -m pip install -e '.[dev]'
ruff format .
ruff check .
mypy src/mcp_behaviour_guard
pytest
```

Exercise the demonstrations when changing clients, observers or engine behaviour:

```bash
make demo-stdio
docker compose up --build -d
make demo-http
docker compose down -v
```

Keep pass/fail rules deterministic. AI-generated suggestions must remain outside the trusted decision path and require normal code review.

New checks should include:

- a contract field or explicit test input;
- an objective expected property;
- reproducible observed evidence;
- a unit test for pass and fail cases; and
- a safety note when the check can change state.

Do not submit real credentials, customer data or scan evidence from systems you are not authorized to test.
