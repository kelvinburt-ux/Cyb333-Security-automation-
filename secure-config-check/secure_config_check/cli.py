"""Command-line entry point for Secure Config Check."""

import argparse
from collections.abc import Callable, Sequence
from pathlib import Path
import sys

from secure_config_check.auditor import run_audit
from secure_config_check.helpers import read_text_file
from secure_config_check.models import AuditReport, CheckStatus
from secure_config_check.reporting import format_console_report, write_json_report


_OS_RELEASE_PATH = "/etc/os-release"
_UNSUPPORTED_MESSAGE = (
    "Unsupported operating system. Secure Config Check requires Ubuntu Linux 24.04 LTS."
)
_FAILURE_MESSAGE = "Secure Config Check could not complete safely."
_EnvironmentChecker = Callable[[], bool]
_AuditRunner = Callable[[], AuditReport]
_ConsoleWriter = Callable[[str], object]
_JsonWriter = Callable[[AuditReport, Path], object]
_TextReader = Callable[[str], str]


def is_supported_environment(
    *,
    platform_name: str | None = None,
    read_text: _TextReader = read_text_file,
) -> bool:
    """Return whether the host is Linux Ubuntu 24.04 using os-release metadata."""
    if (platform_name or sys.platform).lower() != "linux":
        return False

    try:
        contents = read_text(_OS_RELEASE_PATH)
    except Exception:
        return False

    values: dict[str, str] = {}
    for line in contents.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key.strip()] = value

    return values.get("ID", "").lower() == "ubuntu" and values.get(
        "VERSION_ID", ""
    ) == "24.04"


def _exit_code(report: AuditReport) -> int:
    """Return the CLI status code, with ERROR taking priority over FAIL."""
    statuses = {result.status for result in report.results}
    if CheckStatus.ERROR in statuses:
        return 2
    if CheckStatus.FAIL in statuses:
        return 1
    return 0


def _write_generic_failure(console_writer: _ConsoleWriter) -> None:
    """Try to print a safe failure message without exposing exception details."""
    try:
        console_writer(_FAILURE_MESSAGE)
    except Exception:
        return


def main(
    argv: Sequence[str] | None = None,
    *,
    audit_runner: _AuditRunner | None = None,
    environment_checker: _EnvironmentChecker | None = None,
    console_writer: _ConsoleWriter | None = None,
    json_writer: _JsonWriter | None = None,
) -> int:
    """Parse CLI options, verify the host, run the audit, and report its status."""
    parser = argparse.ArgumentParser(
        prog="secure-config-check",
        description="Read-only checks for the Ubuntu 24.04 Level 1 Server profile.",
    )
    parser.add_argument(
        "--json-output",
        type=Path,
        metavar="PATH",
        help="write a JSON report to PATH",
    )
    arguments = parser.parse_args(argv)

    run = audit_runner or run_audit
    check_environment = environment_checker or is_supported_environment
    write_console = console_writer or print
    write_json = json_writer or write_json_report

    try:
        if not check_environment():
            write_console(_UNSUPPORTED_MESSAGE)
            return 2

        report = run()
        write_console(format_console_report(report))
        if arguments.json_output is not None:
            write_json(report, arguments.json_output)
        return _exit_code(report)
    except Exception:
        _write_generic_failure(write_console)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())