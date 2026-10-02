# Trusted local gate image. BASE_IMAGE is selected by the operator/helper after exact image readback.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

WORKDIR /phase2-gate
COPY gate.py expected-checks.json gate-rules.json /phase2-gate/

USER evaluator
ENTRYPOINT ["python", "/phase2-gate/gate.py"]
