# pipe2025

This repository packages a small Go login API as a GitHub Actions self-healing CI demo. The application code stays fixed while the workflow diagnoses and repairs `Dockerfile`, `docker-compose.yml`, and GitHub Actions configuration.

## Try the autoheal in 3 minutes

1. Fork the repo.
2. In Settings → Secrets, add `AI_API_KEY` (any OpenAI-compatible provider).
3. Go to Actions → `github-actions-autoheal-showcase` → Run workflow.
4. Watch the diagnose job find issues, the autoheal job propose a fix, and a PR appear on your fork.

## Self-Healing Showcase flow

1. Build and start the demo stack with Docker Compose.
2. Capture machine-readable findings from Docker, Compose, workflow state, and runtime logs.
3. Generate a remediation plan from those findings with an OpenAI-compatible AI API.
4. Apply the proposed Docker and workflow edits.
5. Re-run verification and publish artifacts plus a step summary.
6. If verification passes, push the healed changes to an `autoheal/*` branch.

## Trigger the heal on a clean fork

Run `make demo-break`, commit the intentionally broken `Dockerfile`, push your branch, and then run the workflow from GitHub Actions. The demo break swaps in the stored bad Dockerfile so the diagnose job has a predictable failure to repair.

## Local dev with Ollama (no API key)

Install Ollama, pull `llama3.1`, copy `.env.example` to `.env`, set `AI_PROVIDER=ollama`, and run the helper scripts manually. `scripts/ai_client.py` will default to `http://localhost:11434/v1` with model `llama3.1` and a placeholder API key.

## About the demo app

API endpoint usage for `register`, `login`, `me`, and `users` now lives in [APP.md](APP.md).

## Local stack

Run `docker compose up --build` in the repository root to start the API on `localhost:8080` with Postgres. The Compose file waits for the database healthcheck before starting the app and keeps the app health probe at the HTTP layer.

## AI configuration

Copy `.env.example` to `.env` and set either the OpenAI-compatible values or the Ollama values. The scripts call an OpenAI-style `POST /chat/completions` API, with Ollama supported through its compatible local endpoint.
