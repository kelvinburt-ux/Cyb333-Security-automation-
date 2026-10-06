"""Format and write sanitized reports for Secure Config Check audits."""

from collections.abc import Callable, Sequence
from datetime import datetime, timezone
import json
from pathlib import Path
import re

from secure_config_check.models import AuditReport, CheckResult, CheckStatus


PROJECT_NAME = "Secure Config Check"
TOOL_VERSION = "0.1.0"
TARGET_OS = "Ubuntu Linux 24.04 LTS"
BENCHMARK_NAME = "CIS Ubuntu Linux 24.04 LTS Benchmark"
BENCHMARK_VERSION = "2.0.0"
BENCHMARK_PROFILE = "Level 1 Server"

_CONTROL_METADATA = {
    "7.1.1": ("File permissions", "Access to passwd database"),
    "7.1.3": ("File permissions", "Access to group database"),
    "7.1.5": ("File permissions", "Access to shadow database"),
    "5.1.16": ("SSH", "SSH MaxAuthTries"),
    "5.1.19": ("SSH", "SSH PermitEmptyPasswords"),
    "5.1.20": ("SSH", "SSH PermitRootLogin"),
    "5.3.3.2.2": ("Password policy", "Minimum password length"),
    "5.4.1.1": ("Password policy", "Password expiration"),
    "5.4.1.3": ("Password policy", "Password expiration warning"),
    "4.1.1": ("Firewall", "UFW is installed"),
    "4.1.2": ("Firewall", "UFW service is configured"),
    "4.1.3": ("Firewall", "UFW incoming default policy"),
    "5.4.2.1": ("Account configuration", "Root is the only UID 0 account"),
    "7.2.1": ("Account configuration", "Accounts use shadowed passwords"),
    "7.2.2": ("Account configuration", "Shadow password fields are not empty"),
}
_CONTROL_ORDER = tuple(_CONTROL_METADATA)
_TOTAL_KEYS = (
    CheckStatus.PASS,
    CheckStatus.FAIL,
    CheckStatus.ERROR,
    CheckStatus.NOT_APPLICABLE,
)
_GENERIC_SUMMARY = "Details withheld; see the check status."
_STATIC_SUMMARIES = frozenset(
    {
        "Ownership and permissions meet the configured requirement.",
        "Ownership, file type, or permissions do not meet the requirement.",
        "Required file metadata could not be safely checked.",
        "Effective SSH setting meets the configured requirement.",
        "Effective SSH setting does not meet the configured requirement.",
        "Effective SSH setting could not be safely checked.",
        "Effective password length meets the requirement.",
        "Effective password length is below the requirement.",
        "The UFW package is installed.",
        "The UFW package is not installed.",
        "The UFW package state could not be safely checked.",
        "UFW service state could not be safely checked.",
        "UFW service is disabled or inactive.",
        "UFW service is enabled and active.",
        "UFW incoming default policy could not be safely checked.",
        "UFW incoming default policy is restrictive.",
        "UFW incoming default policy is not restrictive.",
        "Account data could not be safely evaluated.",
    }
)
_COUNT_SUMMARY_PATTERNS = (
    re.compile(r"UID 0 accounts: \d+; non-root UID 0 accounts: \d+\."),
    re.compile(r"Accounts: \d+; compliant: \d+; noncompliant: \d+\."),
    re.compile(r"Shadow accounts: \d+; empty password fields: \d+\."),
    re.compile(
        r"Default meets the requirement; \d+ applicable accounts checked; "
        r"\d+ noncompliant\."
    ),
    re.compile(
        r"Default or account values are noncompliant; \d+ applicable accounts "
        r"checked; \d+ noncompliant\."
    ),
)
_TimestampProvider = Callable[[], datetime]


def calculate_summary_totals(report: AuditReport) -> dict[str, int]:
    """Count each supported status and the total number of results."""
    totals = {status.value: 0 for status in _TOTAL_KEYS}
    for result in report.results:
        totals[result.status.value] += 1
    totals["total"] = len(report.results)
    return totals


def _ordered_results(report: AuditReport) -> list[CheckResult]:
    """Validate the known control set and return it in registry order."""
    results_by_id: dict[str, CheckResult] = {}
    for result in report.results:
        if result.control_id not in _CONTROL_METADATA:
            raise ValueError("report contains an unknown control")
        if result.control_id in results_by_id:
            raise ValueError("report contains a duplicate control")
        results_by_id[result.control_id] = result

    if set(results_by_id) != set(_CONTROL_ORDER):
        raise ValueError("report does not contain all registered controls")
    return [results_by_id[control_id] for control_id in _CONTROL_ORDER]


def _safe_summary(summary: str) -> str:
    """Allow fixed check messages and count-only summaries; replace other text."""
    if summary in _STATIC_SUMMARIES:
        return summary
    if any(pattern.fullmatch(summary) for pattern in _COUNT_SUMMARY_PATTERNS):
        return summary
    return _GENERIC_SUMMARY


def format_console_report(report: AuditReport) -> str:
    """Return a readable report with fixed metadata and sanitized result details."""
    lines = [
        PROJECT_NAME,
        f"Target: {TARGET_OS}",
        f"Benchmark: {BENCHMARK_NAME} v{BENCHMARK_VERSION}",
        f"Profile: {BENCHMARK_PROFILE}",
        "",
    ]
    for result in _ordered_results(report):
        category, title = _CONTROL_METADATA[result.control_id]
        lines.append(
            f"{result.control_id} | {category} | {title} | "
            f"{result.status.value} | {_safe_summary(result.summary)}"
        )

    totals = calculate_summary_totals(report)
    lines.extend(
        [
            "",
            "Summary:",
            f"PASS: {totals['PASS']}",
            f"FAIL: {totals['FAIL']}",
            f"ERROR: {totals['ERROR']}",
            f"NOT_APPLICABLE: {totals['NOT_APPLICABLE']}",
            f"Total: {totals['total']}",
        ]
    )
    return "\n".join(lines)


def _utc_timestamp(
    report: AuditReport, timestamp_provider: _TimestampProvider | None
) -> str:
    """Get an injected or report timestamp and normalize it to UTC ISO format."""
    timestamp = (
        timestamp_provider()
        if timestamp_provider is not None
        else datetime.fromisoformat(report.generated_at)
    )
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(timezone.utc).isoformat()


def build_json_payload(
    report: AuditReport,
    *,
    timestamp_provider: _TimestampProvider | None = None,
) -> dict[str, object]:
    """Build sanitized metadata, totals, and all 15 ordered result objects."""
    results = []
    for result in _ordered_results(report):
        category, title = _CONTROL_METADATA[result.control_id]
        results.append(
            {
                "control_id": result.control_id,
                "category": category,
                "title": title,
                "status": result.status.value,
                "summary": _safe_summary(result.summary),
            }
        )

    return {
        "project_name": PROJECT_NAME,
        "tool_version": TOOL_VERSION,
        "target_operating_system": TARGET_OS,
        "benchmark": {
            "name": BENCHMARK_NAME,
            "version": BENCHMARK_VERSION,
            "profile": BENCHMARK_PROFILE,
        },
        "generated_at": _utc_timestamp(report, timestamp_provider),
        "summary": calculate_summary_totals(report),
        "results": results,
    }


def write_json_report(
    report: AuditReport,
    destination: Path,
    *,
    timestamp_provider: _TimestampProvider | None = None,
) -> None:
    """Write an indented UTF-8 JSON report, creating parent directories as needed."""
    payload = build_json_payload(report, timestamp_provider=timestamp_provider)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(payload, indent=2) + "\n",
        encoding="utf-8",
    )