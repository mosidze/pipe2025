# pipe2025

This repository packages a small Go login API as a GitHub Actions self-healing CI demo. The application code stays fixed while the workflow diagnoses and repairs `Dockerfile`, `docker-compose.yml`, and GitHub Actions configuration.

## Try the autoheal in 3 minutes

1. Fork the repo.
2. In Settings → Secrets, add `AI_API_KEY` (any OpenAI-compatible provider).
3. Run `make demo-break`, commit the broken `Dockerfile`, and push your branch.
4. Watch `devsecops` find issues, AI triage them, trigger `autoheal-showcase` with a security handoff, and open a PR on your fork.

## Self-Healing Showcase flow

1. Build and start the demo stack with Docker Compose.
2. Capture machine-readable findings from Docker, Compose, workflow state, and runtime logs.
3. Generate a remediation plan from those findings with an OpenAI-compatible AI API.
4. Apply the proposed Docker and workflow edits.
5. Re-run verification and publish artifacts plus a step summary.
6. If verification passes, push the healed changes to an `autoheal/*` branch and open a PR.

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

## DevSecOps pipeline

The repository includes a GitHub-native DevSecOps workflow in `.github/workflows/devsecops.yml`.

- SAST: `gosec` and `govulncheck` scan the Go codebase and upload SARIF to the GitHub Security tab.
- Secret detection: `gitleaks` scans the repository history and reports leaks as SARIF.
- SCA: Trivy scans both the repository filesystem and the built container image for HIGH and CRITICAL findings.
- DAST: ZAP baseline runs against the local stack with a hard `-T 3` minute timeout and the JSON report is converted to SARIF.
- AI triage: the SARIF outputs are aggregated, summarized, and gated into `allow`, `warn`, or `block`, with only docker-scoped auto-fixes eligible for the autoheal bridge.
- Bridge to autoheal: when AI triage marks a docker-scope finding as auto-fixable, the workflow dispatches `autoheal-showcase` with a `security_source_run_id` handoff.

The SAST layer on Go code is intentionally READ-ONLY for AI. It can surface Go findings in reports, but it never proposes patches to application code, `go.mod`, or `go.sum`.

### Required secrets on your fork

Set these four in Settings → Secrets and variables → Actions before the first push — the `ai-triage` job fails fast (by design) without a key, because AI is the centerpiece of this demo, not an optional extra.

- `AI_API_KEY` — any OpenAI-compatible key (e.g. Groq free tier).
- `AI_PROVIDER` — `openai-compatible` (or `ollama` for local).
- `AI_BASE_URL` — e.g. `https://api.groq.com/openai/v1`.
- `AI_MODEL` — e.g. `llama-3.3-70b-versatile` (Groq's active 70B model; `llama-3.1-70b-versatile` was decommissioned in October 2025).

Payload budget: `ai-triage` trims findings to the top 40 by severity before the model call, preferring docker-scoped findings. If the payload is still too large, it chunks the request into 20-item batches. On persistent rate limits, the job reports the findings without AI commentary and exits `0` because the six scanners are deterministic and the AI layer is additive.

## Operator controls

- Setting repo variable `AUTOHEAL_DISABLED=true` skips the autoheal job while `diagnose` still runs.
- Heal history lives in `artifacts/heal_history/` inside each autoheal PR diff.
- Token usage is recorded in `artifacts/ai_usage.jsonl`.

### Human-in-the-loop gate (one-time fork setup)

The `trigger-autoheal` job uses a dynamic environment based on the AI gate:

- `gate=allow` / `gate=warn` → environment `autoheal-auto` (auto-proceeds).
- `gate=block` → environment `autoheal-human` (waits for a reviewer click in the Actions UI: "Review deployments" → Approve).

Create both in Settings → Environments on your fork:

- `autoheal-auto` — no protection rules.
- `autoheal-human` — add yourself as a Required reviewer.

Until the environments exist the job will pause; add them once and the flow works for every run.

## Reviewing an autoheal PR

- [ ] Diff is small and targeted to findings listed in PR body.
- [ ] hadolint / actionlint / yamllint green in lint-and-test job.
- [ ] No widening of `permissions:` (look at workflow diff).
- [ ] No new `${{ secrets.* }}` references.
- [ ] Third-party actions pinned by SHA.
- [ ] Heal history JSON file present in the diff.
