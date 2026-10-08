# agathon-sandbox — ephemeral probe runner for run_operator_tool / test-probe.
# Build:  docker build -t agathon-sandbox:latest docker/agathon-sandbox
# Env:    AGATHON_DOCKER_IMAGE=agathon-sandbox:latest (Railway / engine host)

FROM python:3.11-slim

RUN useradd --create-home --shell /usr/sbin/nologin sandbox \
    && mkdir -p /work \
    && chown sandbox:sandbox /work

WORKDIR /work
USER sandbox

# probe.py is bind-mounted read-only at /work/probe.py by the orchestrator.
CMD ["python3", "/work/probe.py"]
