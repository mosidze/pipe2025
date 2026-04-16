"""AI security triage for scanner findings.

Invariants:
- AI may recommend auto-fixes only for docker-scoped findings.
- Go-code and secret findings are always human-reviewed and never bridged to autoheal.
- The handoff contains only docker-scoped auto-fix findings.
- A blocking gate exits non-zero after writing outputs.
"""

import argparse
import json
import os
import sys
from pathlib import Path

try:
    from usage_tracker import call_tracked
except ImportError:  # pragma: no cover - package import path
    from .usage_tracker import call_tracked


SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def normalize_response(response: dict) -> dict:
    if not isinstance(response, dict):
        raise RuntimeError("AI triage response must be a JSON object.")

    triaged_findings = response.get("triaged_findings", [])
    if not isinstance(triaged_findings, list):
        raise RuntimeError("AI triage response must contain a triaged_findings list.")

    autoheal_handoff = response.get("autoheal_handoff", {})
    if not isinstance(autoheal_handoff, dict):
        raise RuntimeError("AI triage response must contain an autoheal_handoff object.")

    gate = str(response.get("gate", "warn")).lower()
    if gate not in {"allow", "warn", "block"}:
        raise RuntimeError(f"Unsupported gate value: {gate}")

    return {
        "gate": gate,
        "summary": str(response.get("summary", "")),
        "triaged_findings": triaged_findings,
        "autoheal_handoff": autoheal_handoff,
    }


def find_model_triage(model_findings: list[dict], scanner: str, rule_id: str) -> dict:
    for finding in model_findings:
        if str(finding.get("scanner", "")) == scanner and str(finding.get("rule_id", "")) == rule_id:
            return finding
    return {}


def build_triaged_findings(findings: list[dict], model_findings: list[dict]) -> list[dict]:
    triaged = []
    for finding in findings:
        model_finding = find_model_triage(model_findings, finding["scanner"], finding["rule_id"])
        triage = str(model_finding.get("triage", "needs_human"))
        triage_reason = str(model_finding.get("triage_reason", "No model triage provided."))
        explanation = str(model_finding.get("explanation", finding.get("message", "")))
        recommended_fix = str(model_finding.get("recommended_fix", ""))

        if triage == "auto_fix" and finding.get("path_scope") != "docker":
            triage = "needs_human"
            triage_reason = (
                f"{triage_reason} Auto-fix downgraded by policy because only docker-scoped findings "
                "may be auto-remediated."
            ).strip()

        triaged.append(
            {
                **finding,
                "triage": triage,
                "triage_reason": triage_reason,
                "explanation": explanation,
                "recommended_fix": recommended_fix,
            }
        )
    return triaged


def build_handoff(response: dict, triaged_findings: list[dict]) -> dict:
    eligible_findings = [
        finding
        for finding in triaged_findings
        if finding.get("triage") == "auto_fix" and finding.get("path_scope") == "docker"
    ]
    allowed = {(finding["scanner"], finding["rule_id"]) for finding in eligible_findings}

    requested = response.get("autoheal_handoff", {}).get("targeted_findings", [])
    filtered = []
    if isinstance(requested, list):
        for item in requested:
            if not isinstance(item, dict):
                continue
            scanner = str(item.get("scanner", ""))
            rule_id = str(item.get("rule_id", ""))
            if (scanner, rule_id) not in allowed:
                continue
            for finding in eligible_findings:
                if finding["scanner"] == scanner and finding["rule_id"] == rule_id:
                    filtered.append(finding)
                    break

    eligible = bool(response.get("autoheal_handoff", {}).get("eligible", False) and filtered)
    return {
        "eligible": eligible,
        "targeted_findings": filtered,
    }


def render_report(gate: str, summary: str, triaged_findings: list[dict]) -> str:
    lines = [f"AI gate: {gate}", "", summary or "No AI summary provided.", ""]
    for severity in SEVERITY_ORDER:
        lines.extend([f"## {severity}", "", "| rule_id | scanner | triage | explanation | recommended_fix |", "| --- | --- | --- | --- | --- |"])
        rows = [finding for finding in triaged_findings if finding.get("severity", "INFO") == severity]
        if rows:
            for finding in rows:
                explanation = str(finding.get("explanation", "")).replace("\n", " ")
                recommended_fix = str(finding.get("recommended_fix", "")).replace("\n", " ")
                lines.append(
                    f"| {finding.get('rule_id', '')} | {finding.get('scanner', '')} | "
                    f"{finding.get('triage', '')} | {explanation} | {recommended_fix} |"
                )
        else:
            lines.append("| - | - | - | No findings. | - |")
        lines.append("")
    return "\n".join(lines).strip() + "\n"


def write_outputs(eligible: bool) -> None:
    github_output = os.getenv("GITHUB_OUTPUT")
    if github_output:
        with Path(github_output).open("a") as handle:
            handle.write(f"autoheal_eligible={'true' if eligible else 'false'}\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--findings", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--handoff", required=True)
    args = parser.parse_args()

    findings_payload = json.loads(Path(args.findings).read_text())
    findings = findings_payload.get("findings", [])

    if findings:
        system_prompt = f"""
You are a GitHub-native DevSecOps triage agent.
{__doc__.strip()}
Return strict JSON with this schema:
{{
  "gate": "allow|warn|block",
  "summary": "one paragraph",
  "triaged_findings": [
    {{
      "scanner": "scanner name",
      "rule_id": "rule identifier",
      "triage": "auto_fix|needs_human|ignore",
      "triage_reason": "why this triage was chosen",
      "explanation": "plain English explanation",
      "recommended_fix": "plain English recommended fix"
    }}
  ],
  "autoheal_handoff": {{
    "eligible": true,
    "targeted_findings": [
      {{
        "scanner": "scanner name",
        "rule_id": "rule identifier"
      }}
    ]
  }}
}}
"""
        user_prompt = (
            "Findings JSON:\n"
            f"{json.dumps(findings_payload, indent=2)}\n\n"
            "Classify each finding for AI gating. Respect the invariants and keep auto-fix "
            "recommendations limited to Docker and Compose configuration."
        )
        response = normalize_response(call_tracked(system_prompt, user_prompt, step="security_triage"))
        triaged_findings = build_triaged_findings(findings, response["triaged_findings"])
        handoff = build_handoff(response, triaged_findings)
        gate = response["gate"]
        summary = response["summary"]
    else:
        triaged_findings = []
        handoff = {"eligible": False, "targeted_findings": []}
        gate = "allow"
        summary = "No security findings were available for AI triage."

    report = render_report(gate, summary, triaged_findings)
    Path(args.report).write_text(report)

    full_handoff = {
        "gate": gate,
        "summary": summary,
        "eligible": handoff["eligible"],
        "targeted_findings": handoff["targeted_findings"],
        "autoheal_handoff": handoff,
    }
    handoff_path = Path(args.handoff)
    if handoff["eligible"]:
        handoff_path.parent.mkdir(parents=True, exist_ok=True)
        handoff_path.write_text(json.dumps(full_handoff, indent=2) + "\n")
    elif handoff_path.exists():
        handoff_path.unlink()

    write_outputs(handoff["eligible"])
    print(f"gate={gate}")
    if gate == "block":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
