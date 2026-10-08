# agathon-sandbox

Minimal Docker image for operator probe dry-runs (`POST /developer/test-probe`) and
Brain `run_operator_tool` executions.

## Build locally

```bash
docker build -t agathon-sandbox:latest docker/agathon-sandbox
```

## Engine configuration

Set on the Railway / engine host:

```
AGATHON_DOCKER_IMAGE=agathon-sandbox:latest
```

The orchestrator bind-mounts `probe.py` at `/work/probe.py` and runs:

```
docker run --rm ... agathon-sandbox:latest python3 /work/probe.py
```

## Railway notes

Railway containers typically **do not** expose a Docker daemon. Options:

1. **Sidecar with Docker socket** — deploy engine on a VM or Railway service with DinD.
2. **Remote builder** — build and push `agathon-sandbox:latest` to a registry the engine host can pull.
3. **Dev only** — sandbox test works on local engine; prod shows a clear Docker error until configured.

Probe contract: env vars `TARGET_URL`, `TARGET_MODEL`, `TARGET_API_KEY`; stdout JSON recommended.
