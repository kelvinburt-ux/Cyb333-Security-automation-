"""Tests for CLI environment gating, reporting, and exit status behavior."""

from collections.abc import Callable
from pathlib import Path

import pytest

from secure_config_check import cli
from secure_config_check.auditor import _CONTROL_ORDER
from secure_config_check.models import AuditReport, CheckResult, CheckStatus
from secure_config_check.reporting import write_json_report


def _report(statuses: tuple[CheckStatus, ...] | None = None) -> AuditReport:
    """Create a synthetic 15-result report without reading the host system."""
    if statuses is None:
        statuses = (CheckStatus.PASS,) * 15
    return AuditReport(
        results=[
            CheckResult(
                control_id=control_id,
                title=f"Synthetic control {index}",
                status=statuses[index],
                summary="Synthetic test result.",
            )
            for index, control_id in enumerate(_CONTROL_ORDER)
        ]
    )


def _main(
    statuses: tuple[CheckStatus, ...] | None = None,
    *,
    output: list[str] | None = None,
    audit_runner: Callable[[], AuditReport] | None = None,
    json_writer: Callable[[AuditReport, Path], object] | None = None,
    argv: list[str] | None = None,
) -> int:
    """Invoke the CLI with injected dependencies and a supported host."""
    messages = output if output is not None else []
    report = _report(statuses)
    return cli.main(
        argv if argv is not None else [],
        audit_runner=audit_runner or (lambda: report),
        environment_checker=lambda: True,
        console_writer=messages.append,
        json_writer=json_writer or (lambda current_report, destination: None),
    )


def test_supported_ubuntu_24_04_environment_uses_os_release_reader() -> None:
    """Recognize Linux Ubuntu 24.04 from safely read os-release contents."""
    requested_paths: list[str] = []

    def read_text(path: str) -> str:
        requested_paths.append(path)
        return 'ID="ubuntu"\nVERSION_ID="24.04"\n'

    assert cli.is_supported_environment(platform_name="linux", read_text=read_text)
    assert requested_paths == ["/etc/os-release"]


def test_windows_environment_is_unsupported_without_file_read() -> None:
    """Reject Windows before attempting to read Linux os-release data."""
    def unexpected_read(path: str) -> str:
        raise AssertionError("os-release should not be read on Windows")

    assert not cli.is_supported_environment(
        platform_name="win32",
        read_text=unexpected_read,
    )


def test_unsupported_ubuntu_version_is_rejected() -> None:
    """Reject Ubuntu releases other than 24.04."""
    assert not cli.is_supported_environment(
        platform_name="linux",
        read_text=lambda path: "ID=ubuntu\nVERSION_ID=22.04\n",
    )


def test_unsupported_environment_does_not_run_audit() -> None:
    """Return code 2 without invoking the auditor on an unsupported host."""
    messages: list[str] = []
    audit_calls: list[str] = []

    def audit_runner() -> AuditReport:
        audit_calls.append("audit")
        return _report()

    exit_code = cli.main(
        [],
        audit_runner=audit_runner,
        environment_checker=lambda: False,
        console_writer=messages.append,
    )

    assert exit_code == 2
    assert audit_calls == []
    assert len(messages) == 1
    assert "Ubuntu Linux 24.04 LTS" in messages[0]


def test_exit_code_zero_for_pass_and_not_applicable() -> None:
    """Return 0 when results contain only PASS and NOT_APPLICABLE statuses."""
    statuses = (CheckStatus.NOT_APPLICABLE,) + (CheckStatus.PASS,) * 14

    assert _main(statuses) == 0


def test_exit_code_one_for_fail_without_error() -> None:
    """Return 1 for findings when no check produced an ERROR."""
    statuses = (CheckStatus.FAIL,) + (CheckStatus.PASS,) * 14

    assert _main(statuses) == 1


def test_exit_code_two_when_error_exists() -> None:
    """Return 2 when at least one result is an ERROR."""
    statuses = (CheckStatus.ERROR,) + (CheckStatus.PASS,) * 14

    assert _main(statuses) == 2


def test_error_exit_code_takes_priority_over_fail() -> None:
    """Return 2 rather than 1 when a report contains both FAIL and ERROR."""
    statuses = (CheckStatus.FAIL, CheckStatus.ERROR) + (CheckStatus.PASS,) * 13

    assert _main(statuses) == 2


def test_console_report_is_produced() -> None:
    """Send the formatted console report to the injected writer."""
    messages: list[str] = []

    exit_code = _main(output=messages)

    assert exit_code == 0
    assert len(messages) == 1
    assert "Secure Config Check" in messages[0]
    assert "7.1.1" in messages[0]
    assert "Total: 15" in messages[0]


def test_optional_json_report_uses_injected_writer(tmp_path: Path) -> None:
    """Call the injected JSON writer only when --json-output is supplied."""
    destination = tmp_path / "reports" / "audit-report.json"
    written: list[tuple[AuditReport, Path]] = []

    def json_writer(report: AuditReport, path: Path) -> None:
        written.append((report, path))

    exit_code = _main(
        argv=["--json-output", str(destination)],
        json_writer=json_writer,
    )

    assert exit_code == 0
    assert len(written) == 1
    assert written[0][1] == destination
    assert len(written[0][0].results) == 15


def test_json_output_directory_is_created_by_reporting_layer(tmp_path: Path) -> None:
    """Delegate output-directory creation to write_json_report."""
    destination = tmp_path / "nested" / "reports" / "audit-report.json"
    report = _report()

    exit_code = cli.main(
        ["--json-output", str(destination)],
        audit_runner=lambda: report,
        environment_checker=lambda: True,
        console_writer=lambda message: None,
        json_writer=write_json_report,
    )

    assert exit_code == 0
    assert destination.is_file()


def test_top_level_exception_is_generic_and_does_not_leak_details() -> None:
    """Hide exception text and local paths when an injected audit runner fails."""
    messages: list[str] = []

    def failing_audit() -> AuditReport:
        raise RuntimeError("private-user C:\\Users\\private-user\\shadow-hash")

    exit_code = cli.main(
        [],
        audit_runner=failing_audit,
        environment_checker=lambda: True,
        console_writer=messages.append,
    )

    assert exit_code == 2
    output = "\n".join(messages)
    assert "could not complete safely" in output
    assert "private-user" not in output
    assert "C:\\Users" not in output
    assert "shadow-hash" not in output


def test_json_writer_exception_returns_two_without_leaking_path(
    tmp_path: Path,
) -> None:
    """Return 2 and print generic text if writing JSON fails."""
    destination = tmp_path / "secret-user" / "private-report.json"
    messages: list[str] = []

    def failing_writer(report: AuditReport, path: Path) -> None:
        raise OSError(f"cannot write {path}")

    exit_code = cli.main(
        ["--json-output", str(destination)],
        audit_runner=_report,
        environment_checker=lambda: True,
        console_writer=messages.append,
        json_writer=failing_writer,
    )

    assert exit_code == 2
    output = "\n".join(messages)
    assert "secret-user" not in output
    assert "private-report.json" not in output
    assert "could not complete safely" in output


def test_help_option_works(capsys: pytest.CaptureFixture[str]) -> None:
    """Show argparse help and exit successfully without running an audit."""
    with pytest.raises(SystemExit) as exception:
        cli.main(["--help"])

    assert exception.value.code == 0
    help_output = capsys.readouterr().out
    assert "--json-output PATH" in help_output