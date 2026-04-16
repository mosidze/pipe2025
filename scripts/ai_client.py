"""AI client helpers for OpenAI-compatible gateways and local Ollama instances.

Set `AI_PROVIDER=openai-compatible` to use the standard `/chat/completions` API
with `AI_API_KEY`, `AI_BASE_URL`, and `AI_MODEL`. Set `AI_PROVIDER=ollama` to
default to `http://localhost:11434/v1` and `llama3.1` without requiring a real
API key.
"""

import json
import os
from pathlib import Path

import requests


ROOT_ENV_PATH = Path(".env")


def load_dotenv(path: Path = ROOT_ENV_PATH) -> None:
    if not path.exists():
        return

    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def get_ai_config() -> dict:
    load_dotenv()

    provider = os.getenv("AI_PROVIDER", "openai-compatible").strip() or "openai-compatible"

    if provider == "ollama":
        api_key = os.getenv("AI_API_KEY", "ollama").strip() or "ollama"
        base_url = os.getenv("AI_BASE_URL", "http://localhost:11434/v1").strip().rstrip("/")
        model = os.getenv("AI_MODEL", "llama3.1").strip() or "llama3.1"
    else:
        api_key = os.getenv("AI_API_KEY", "").strip()
        base_url = os.getenv("AI_BASE_URL", "https://api.openai.com/v1").strip().rstrip("/")
        model = os.getenv("AI_MODEL", "gpt-4o-mini").strip() or "gpt-4o-mini"

        if not api_key:
            raise RuntimeError("Missing AI_API_KEY. Set it in .env or GitHub Secrets.")

    return {
        "api_key": api_key,
        "base_url": base_url,
        "model": model,
        "provider": provider,
    }


def call_ai_json(system_prompt: str, user_prompt: str) -> dict:
    config = get_ai_config()
    headers = {
        "Authorization": f"Bearer {config['api_key']}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": config["model"],
        "temperature": 0.1,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    }

    response = requests.post(
        f"{config['base_url']}/chat/completions",
        headers=headers,
        json={**payload, "response_format": {"type": "json_object"}},
        timeout=120,
    )

    if response.status_code >= 400:
        fallback = requests.post(
            f"{config['base_url']}/chat/completions",
            headers=headers,
            json=payload,
            timeout=120,
        )
        fallback.raise_for_status()
        response = fallback
    else:
        response.raise_for_status()

    response_payload = response.json()
    content = response_payload["choices"][0]["message"]["content"]
    if isinstance(content, list):
        content = "".join(part.get("text", "") for part in content if isinstance(part, dict))
    return json.loads(content)
