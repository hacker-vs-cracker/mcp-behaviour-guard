# Phase 2B.1 defines fixture runtime contents only.
# Phase 2B.2 MUST supply a reviewed platform-specific immutable base image digest.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /fixture
COPY store.py app_service.py control_service.py ./

RUN useradd --create-home --uid 10001 fixture && \
    mkdir -p /state && \
    chown fixture:fixture /state

USER fixture
VOLUME ["/state"]
CMD ["python", "app_service.py", "--db", "/state/fixture.db", "--host", "0.0.0.0", "--port", "8001"]
