FROM python:3.11.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY demo ./demo
RUN python -m pip install --upgrade pip && python -m pip install .

RUN useradd --create-home --uid 10001 guard && \
    mkdir -p /data /runtime && \
    chown -R guard:guard /app /data /runtime
USER guard

CMD ["uvicorn", "demo.server.app:app", "--host", "0.0.0.0", "--port", "8000"]
