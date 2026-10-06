"""Tests for sanitized console and JSON audit reporting."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

from secure_config_check.auditor import _CONTROL_ORDER
from secure_config_check.models import AuditReport, CheckResult, CheckStatus
from secure_config_check.reporting import (
    BENCHMARK_NAME,
    BENCHMARK_PROFILE,
    BENCHMARK_VERSION,
    PROJECT_NAME,
    TARGET_OS,
    TOOL_VERSION,
    build_json_payload,
    calculate_summary_totals,
    format_console_report,
    write_json_report,
)


_MIXED_STATUSES = (
    CheckStatus.PASS,
    CheckStatus.FAIL,
    CheckStatus.ERROR,
    CheckStatus.NOT_APPLICABLE,
    CheckStatus.PASS,
    CheckStatus.FAIL,
    CheckStatus.ERROR,
    CheckStatus.NOT_APPLICABLE,
    CheckStatus.PASS,
    CheckStatus.FAIL,
    CheckStatus.ERROR,
    CheckStatus.NOT_APPLICABLE,
    CheckStatus.PASS,
    CheckStatus.PASS,
    CheckStatus.PASS,
)
_FIXED_TIMESTAMP = datetime(
    2026,
    10,
    6,
    12,
    34,
    56,
    tzinfo=timezone(timedelta(hours=2)),
)


def _report(
    statuses: tuple[CheckStatus, ...] = (CheckStatus.PASS,) * 15,
    *,
    summary: str = "Synthetic safe summary.",
) -> AuditReport:
    """Create a 15-result report with synthetic, non-system input values."""
    results = [
        CheckResult(
            control_id=control_id,
            title=f"untrusted title {index}",
            status=statuses[index],
            summary=summary,
        )
        for index, control_id in enumerate(_CONTROL_ORDER)
    ]
    return AuditReport(results=results)


def _fixed_clock() -> datetime:
    """Return a predictable timezone-aware test timestamp."""
    return _FIXED_TIMESTAMP


def test_summary_totals_count_mixed_statuses() -> None:
    """Count each status accurately and include the total number of results."""
    totals = calculate_summary_totals(_report(_MIXED_STATUSES))

    assert totals == {
        "PASS": 6,
        "FAIL": 3,
        "ERROR": 3,
        "NOT_APPLICABLE": 3,
        "total": 15,
    }


def test_summary_status_totals_add_up_to_fifteen() -> None:
    """Ensure the four status buckets sum to all 15 audit results."""
    totals = calculate_summary_totals(_report(_MIXED_STATUSES))

    assert sum(totals[key] for key in ("PASS", "FAIL", "ERROR", "NOT_APPLICABLE")) == 15
    assert totals["total"] == 15


def test_console_report_contains_all_control_ids() -> None:
    """Display every control ID in the auditor's registered order."""
    output = format_console_report(_report())

    control_lines = [line for line in output.splitlines() if " | " in line]
    displayed_ids = tuple(line.split(" | ", maxsplit=1)[0] for line in control_lines)
    assert displayed_ids == _CONTROL_ORDER


def test_console_report_contains_project_metadata_and_totals() -> None:
    """Show target metadata and all summary total categories in the console."""
    output = format_console_report(_report(_MIXED_STATUSES))

    assert PROJECT_NAME in output
    assert f"Target: {TARGET_OS}" in output
    assert f"Benchmark: {BENCHMARK_NAME} v{BENCHMARK_VERSION}" in output
    assert f"Profile: {BENCHMARK_PROFILE}" in output
    assert "PASS: 6" in output
    assert "FAIL: 3" in output
    assert "ERROR: 3" in output
    assert "NOT_APPLICABLE: 3" in output
    assert "Total: 15" in output


def test_json_payload_contains_required_metadata_and_utc_timestamp() -> None:
    """Include project, tool, target, benchmark, profile, and normalized UTC time."""
    payload = build_json_payload(_report(), timestamp_provider=_fixed_clock)

    assert payload["project_name"] == PROJECT_NAME
    assert payload["tool_version"] == TOOL_VERSION
    assert payload["target_operating_system"] == TARGET_OS
    assert payload["benchmark"] == {
        "name": BENCHMARK_NAME,
        "version": BENCHMARK_VERSION,
        "profile": BENCHMARK_PROFILE,
    }
    assert payload["generated_at"] == "2026-10-06T10:34:56+00:00"
    assert payload["summary"]["total"] == 15


def test_json_payload_contains_exactly_fifteen_ordered_results() -> None:
    """Serialize all results in the control order established by the auditor."""
    payload = build_json_payload(_report(), timestamp_provider=_fixed_clock)
    results = payload["results"]

    assert len(results) == 15
    assert tuple(result["control_id"] for result in results) == _CONTROL_ORDER


def test_writer_creates_parent_directories_and_writes_loadable_json(
    tmp_path: Path,
) -> None:
    """Create missing output directories and write formatted UTF-8 JSON."""
    destination = tmp_path / "nested" / "reports" / "audit.json"

    write_json_report(_report(), destination, timestamp_provider=_fixed_clock)

    assert destination.is_file()
    contents = destination.read_text(encoding="utf-8")
    assert "\n  \"project_name\"" in contents
    payload = json.loads(contents)
    assert payload["project_name"] == PROJECT_NAME
    assert len(payload["results"]) == 15


def test_sensitive_synthetic_strings_are_sanitized_from_console_and_json() -> None:
    """Never render untrusted titles or summaries containing sensitive values."""
    sensitive_summary = (
        "alice $6$synthetic-hash passwd-row shadow-row "
        "203.0.113.42 eth9 8443/tcp host.example "
        r"C:\Users\private-user\Documents\audit.json"
    )
    report = _report(summary=sensitive_summary)

    console_output = format_console_report(report)
    json_output = json.dumps(
        build_json_payload(report, timestamp_provider=_fixed_clock),
        ensure_ascii=False,
    )

    for sensitive_value in (
        "alice",
        "$6$synthetic-hash",
        "passwd-row",
        "shadow-row",
        "203.0.113.42",
        "eth9",
        "8443/tcp",
        "host.example",
        "private-user",
        "Documents",
    ):
        assert sensitive_value not in console_output
        assert sensitive_value not in json_output
    assert "Details withheld; see the check status." in console_output
    assert "Details withheld; see the check status." in json_output