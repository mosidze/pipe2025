import argparse
import json
from pathlib import Path


def load_json(path: str) -> dict:
    file_path = Path(path)
    if not file_path.exists():
        return {}
    return json.loads(file_path.read_text())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--findings", required=True)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--pre", required=True)
    parser.add_argument("--post", required=True)
    parser.add_argument("--state", required=False)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    findings = load_json(args.findings)
    plan = load_json(args.plan)
    pre = load_json(args.pre)
    post = load_json(args.post)
    state = load_json(args.state) if args.state else {}

    lines = [
        "# GitHub Actions Self-Healing Showcase",
        "",
        f"- Blocking findings detected: {findings.get('blocking_issue_count', 0)}",
        f"- Advisory findings detected: {findings.get('advisory_issue_count', 0)}",
        f"- Pre-heal verification: {'PASS' if pre.get('success') else 'FAIL'}",
        f"- Post-heal verification: {'PASS' if post.get('success') else 'FAIL'}",
        f"- Workflow file changed: {'YES' if state.get('workflow_touched') else 'NO'}",
        "",
        "## AI remediation summary",
        "",
        plan.get("summary", "No AI remediation plan was generated."),
        "",
        "## Blocking Findings",
        "",
    ]

    for issue in findings.get("issues", []):
        lines.append(f"- [{issue['severity']}] {issue['title']} ({issue['file']})")

    if findings.get("advisory_issues"):
        lines.extend(["", "## Advisory Findings", ""])
        for issue in findings.get("advisory_issues", []):
            lines.append(f"- [{issue['severity']}] {issue['title']} ({issue['file']})")

    if state.get("workflow_touched"):
        lines.extend(
            [
                "",
                "## Verification Note",
                "",
                "- Workflow changes were syntax-validated in this run, but GitHub Actions can only execute them on the next run.",
            ]
        )

    Path(args.output).write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
