# Synthetic MCP candidate for Phase 2B.3.
# BASE_IMAGE is the already-reviewed, exact local evaluator image.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

USER root
WORKDIR /candidate
COPY candidate_server.py /candidate/candidate_server.py
RUN useradd --create-home --uid 10002 candidate && \
    chown -R candidate:candidate /candidate

USER candidate
ENTRYPOINT ["python", "/candidate/candidate_server.py"]
