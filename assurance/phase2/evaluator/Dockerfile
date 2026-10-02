# Phase 2B.2 trusted evaluator. The caller MUST supply an immutable platform manifest digest.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /opt/evaluator
COPY requirements.lock /tmp/requirements.lock
COPY --from=wheelhouse / /wheelhouse/
RUN python -m pip install \
      --no-index \
      --find-links=/wheelhouse \
      --only-binary=:all: \
      --require-hashes \
      -r /tmp/requirements.lock && \
    python -m pip check && \
    rm -rf /wheelhouse /root/.cache/pip

RUN useradd --create-home --uid 10003 evaluator && \
    mkdir -p /work /trusted-output && \
    chown evaluator:evaluator /work /trusted-output

USER evaluator
WORKDIR /work
ENTRYPOINT ["mcp-guard"]
CMD ["--help"]
