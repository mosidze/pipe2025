import argparse
import json
import os
from pathlib import Path


def add_issue(issues: list, issue_id: str, severity: str, file_path: str, title: str, evidence: str, recommendation: str) -> None:
    issues.append(
        {
            "id": issue_id,
            "severity": severity,
            "file": file_path,
            "title": title,
            "evidence": evidence,
            "recommendation": recommendation,
        }
    )


def inspect_dockerfile(issues: list, advisory_issues: list) -> None:
    dockerfile = Path("Dockerfile")
    if not dockerfile.exists():
        add_issue(
            issues,
            "missing_dockerfile",
            "high",
            "Dockerfile",
            "Dockerfile is missing",
            "The repository does not contain a Dockerfile.",
            "Create a buildable Dockerfile for the showcase pipeline.",
        )
        return

    content = dockerfile.read_text()
    lines = content.splitlines()

    if "golang:rc-stretch" in content:
        add_issue(
            advisory_issues,
            "legacy_base_image",
            "high",
            "Dockerfile",
            "Legacy Docker base image",
            "Dockerfile uses golang:rc-stretch, which is obsolete.",
            "Move to a stable, supported multi-stage build.",
        )

    if sum(1 for line in lines if line.strip().startswith("FROM ")) < 2:
        add_issue(
            advisory_issues,
            "single_stage_build",
            "medium",
            "Dockerfile",
            "Single-stage build",
            "Dockerfile builds and runs in one stage.",
            "Use multi-stage Docker builds to reduce runtime size and attack surface.",
        )

    if "USER " not in content:
        add_issue(
            advisory_issues,
            "root_runtime",
            "medium",
            "Dockerfile",
            "Container runs as root",
            "Dockerfile does not switch to a non-root user.",
            "Add a dedicated runtime user.",
        )

    if "HEALTHCHECK" not in content:
        add_issue(
            advisory_issues,
            "missing_healthcheck",
            "low",
            "Dockerfile",
            "No runtime healthcheck in Dockerfile",
            "Dockerfile does not expose a HEALTHCHECK instruction.",
            "Add a simple HTTP healthcheck or move it to Compose.",
        )


def inspect_compose(issues: list, advisory_issues: list) -> None:
    compose = Path("docker-compose.yml")
    if not compose.exists():
        return

    content = compose.read_text()

    if content.lstrip().startswith("version:"):
        add_issue(
            advisory_issues,
            "obsolete_compose_version",
            "low",
            "docker-compose.yml",
            "Obsolete compose version key",
            "Compose file still uses the top-level version field.",
            "Remove the version field for modern Docker Compose.",
        )

    if "healthcheck:" not in content:
        add_issue(
            advisory_issues,
            "missing_compose_healthcheck",
            "medium",
            "docker-compose.yml",
            "Missing compose healthcheck",
            "docker-compose.yml does not define a healthcheck for the app container.",
            "Add a simple healthcheck tied to the HTTP endpoint.",
        )


def inspect_workflow(issues: list, advisory_issues: list) -> None:
    workflow = Path(".github/workflows/autoheal-showcase.yml")
    if not workflow.exists():
        add_issue(
            issues,
            "missing_workflow",
            "high",
            ".github/workflows/autoheal-showcase.yml",
            "GitHub Actions showcase workflow is missing",
            "The self-healing workflow file is not present.",
            "Create a workflow that diagnoses, heals and verifies Docker/pipeline issues.",
        )
        return

    content = workflow.read_text()

    if "workflow_dispatch:" not in content:
        add_issue(
            advisory_issues,
            "manual_trigger_missing",
            "medium",
            ".github/workflows/autoheal-showcase.yml",
            "Manual trigger is missing",
            "The workflow cannot be triggered directly from GitHub Actions UI or gh CLI.",
            "Add workflow_dispatch to make the showcase easy to run.",
        )

    if "actions/upload-artifact" not in content:
        add_issue(
            advisory_issues,
            "artifact_publishing_missing",
            "medium",
            ".github/workflows/autoheal-showcase.yml",
            "Artifacts are not published",
            "The workflow does not persist diagnosis or remediation outputs.",
            "Upload findings, patches and reports as workflow artifacts.",
        )


def inspect_verification(issues: list, verification_path: Path, logs_path: Path) -> None:
    if verification_path.exists():
        verification = json.loads(verification_path.read_text())
        if not verification.get("success", False):
            add_issue(
                issues,
                "runtime_verification_failed",
                "high",
                str(verification_path),
                "Runtime verification failed",
                verification.get("summary", "Verification failed."),
                "Repair Docker or pipeline configuration so the service can build and answer HTTP checks.",
            )

    if logs_path.exists():
        logs = logs_path.read_text()
        if "permission denied" in logs.lower():
            add_issue(
                issues,
                "docker_permission_error",
                "medium",
                str(logs_path),
                "Docker permission issue detected",
                "Runtime logs mention a Docker permission problem.",
                "Ensure the workflow runs on a Docker-capable runner.",
            )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verification", required=True)
    parser.add_argument("--logs", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    issues = []
    advisory_issues = []
    inspect_dockerfile(issues, advisory_issues)
    inspect_compose(issues, advisory_issues)
    inspect_workflow(issues, advisory_issues)
    inspect_verification(issues, Path(args.verification), Path(args.logs))

    output = {
        "status": "blocking_issues_found" if issues else "clean",
        "issues_found": bool(issues),
        "issue_count": len(issues),
        "blocking_issue_count": len(issues),
        "advisory_issue_count": len(advisory_issues),
        "issues": issues,
        "advisory_issues": advisory_issues,
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(output, indent=2))

    github_output = os.getenv("GITHUB_OUTPUT")
    if github_output:
        with Path(github_output).open("a") as handle:
            handle.write(f"issues_found={'true' if issues else 'false'}\n")
            handle.write(f"blocking_issues_found={'true' if issues else 'false'}\n")

    print(f"blocking_issues_found={'true' if issues else 'false'}")


if __name__ == "__main__":
    main()
