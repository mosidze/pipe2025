import argparse
import json
from pathlib import Path

import yaml


ALLOWED_PATHS = {
    "Dockerfile",
    "docker-compose.yml",
    ".github/workflows/autoheal-showcase.yml",
}


def validate_dockerfile(content: str) -> None:
    if "FROM " not in content:
        raise RuntimeError("Dockerfile must contain at least one FROM instruction.")
    if "ENTRYPOINT" not in content and "CMD" not in content:
        raise RuntimeError("Dockerfile must define ENTRYPOINT or CMD.")


def validate_yaml(path: str, content: str) -> None:
    parsed = yaml.load(content, Loader=yaml.BaseLoader)
    if not isinstance(parsed, dict):
        raise RuntimeError(f"{path} must parse to a YAML mapping.")

    if path.endswith("autoheal-showcase.yml"):
        if "jobs" not in parsed:
            raise RuntimeError("Workflow file must define jobs.")
        if "on" not in parsed:
            raise RuntimeError("Workflow file must define triggers in 'on'.")

    if path == "docker-compose.yml":
        if "services" not in parsed:
            raise RuntimeError("docker-compose.yml must define services.")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", required=True)
    args = parser.parse_args()

    plan = json.loads(Path(args.plan).read_text())
    changes = plan.get("changes", [])
    if not isinstance(changes, list) or not changes:
        raise RuntimeError("Remediation plan must contain at least one file change.")

    for change in changes:
        path = change.get("path")
        content = change.get("content")

        if path not in ALLOWED_PATHS:
            raise RuntimeError(f"Unsupported remediation path: {path}")
        if not isinstance(content, str) or not content.strip():
            raise RuntimeError(f"Empty content for remediation path: {path}")

        if path == "Dockerfile":
            validate_dockerfile(content)
        else:
            validate_yaml(path, content)


if __name__ == "__main__":
    main()
