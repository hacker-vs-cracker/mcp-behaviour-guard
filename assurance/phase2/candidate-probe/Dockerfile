# Synthetic untrusted subject used only to prove the local isolation boundary.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /candidate
COPY probe.py /candidate/probe.py
RUN useradd --create-home --uid 10002 candidate && \
    chown -R candidate:candidate /candidate
USER candidate
ENTRYPOINT ["python", "/candidate/probe.py"]
CMD ["server", "--port", "7000"]
