"""Isolated tests for effective SSH configuration checks."""

from collections.abc import Sequence
import subprocess
from typing import NoReturn

import pytest

from secure_config_check.checks import ssh
from secure_config_check.helpers import CommandError, CommandTimeoutError, CommandUnavailableError
from secure_config_check.models import CheckResult, CheckStatus


def _install_command(
    monkeypatch: pytest.MonkeyPatch,
    output: str,
    *,
    returncode: int = 0,
) -> dict[str, object]:
    """Mock the safe command helper and record its arguments and timeout."""
    observed: dict[str, object] = {}

    def fake_run_command(
        arguments: Sequence[str], *, timeout_seconds: float
    ) -> subprocess.CompletedProcess[str]:
        observed["arguments"] = list(arguments)
        observed["timeout_seconds"] = timeout_seconds
        return subprocess.CompletedProcess(
            list(arguments), returncode, stdout=output
        )

    monkeypatch.setattr(ssh, "run_command", fake_run_command)
    return observed


def _results_by_id(results: list[CheckResult]) -> dict[str, CheckResult]:
    """Index returned results by control ID for clear assertions."""
    return {result.control_id: result for result in results}


def test_secure_settings_pass_and_command_is_scoped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Accept compliant values and invoke only sshd -T with a timeout."""
    output = (
        "MAXAUTHTRIES 4\n"
        "PermitEmptyPasswords NO\n"
        "permitrootlogin no\n"
        "allowusers hidden-user\n"
        "listenaddress 192.0.2.10\n"
    )
    observed = _install_command(monkeypatch, output)

    results = ssh.run_ssh_checks(timeout_seconds=3.0)

    assert [result.status for result in results] == [
        CheckStatus.PASS,
        CheckStatus.PASS,
        CheckStatus.PASS,
    ]
    assert observed == {"arguments": ["sshd", "-T"], "timeout_seconds": 3.0}
    assert all("hidden-user" not in result.summary for result in results)
    assert all("192.0.2.10" not in result.summary for result in results)


@pytest.mark.parametrize("attempts", [1, 2, 3, 4])
def test_maxauthtries_passes_for_values_one_through_four(
    monkeypatch: pytest.MonkeyPatch, attempts: int
) -> None:
    """Accept every integer in the required MaxAuthTries range."""
    output = (
        f"maxauthtries {attempts}\n"
        "permitemptypasswords no\n"
        "permitrootlogin no\n"
    )
    _install_command(monkeypatch, output)

    results = _results_by_id(ssh.run_ssh_checks())

    assert results["5.1.16"].status is CheckStatus.PASS


@pytest.mark.parametrize(
    ("key", "value", "control_id"),
    [
        ("maxauthtries", "5", "5.1.16"),
        ("permitemptypasswords", "yes", "5.1.19"),
        ("permitrootlogin", "yes", "5.1.20"),
        ("permitrootlogin", "prohibit-password", "5.1.20"),
        ("permitrootlogin", "without-password", "5.1.20"),
    ],
)
def test_valid_but_noncompliant_settings_fail(
    monkeypatch: pytest.MonkeyPatch,
    key: str,
    value: str,
    control_id: str,
) -> None:
    """Fail valid SSH values that do not satisfy the selected requirements."""
    settings = {
        "maxauthtries": "4",
        "permitemptypasswords": "no",
        "permitrootlogin": "no",
    }
    settings[key] = value
    output = "\n".join(f"{name} {setting}" for name, setting in settings.items())
    _install_command(monkeypatch, output)

    results = _results_by_id(ssh.run_ssh_checks())

    assert results[control_id].status is CheckStatus.FAIL


def test_missing_key_returns_error_for_affected_control(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Return ERROR for a missing required key without failing other keys."""
    _install_command(
        monkeypatch,
        "maxauthtries 4\npermitrootlogin no\n",
    )

    results = _results_by_id(ssh.run_ssh_checks())

    assert results["5.1.16"].status is CheckStatus.PASS
    assert results["5.1.19"].status is CheckStatus.ERROR
    assert results["5.1.20"].status is CheckStatus.PASS


@pytest.mark.parametrize(
    ("output", "expected_statuses"),
    [
        (
            "maxauthtries many\npermitemptypasswords no\npermitrootlogin no\n",
            [CheckStatus.ERROR, CheckStatus.PASS, CheckStatus.PASS],
        ),
        (
            "malformed\nmaxauthtries 4\npermitemptypasswords no\npermitrootlogin no\n",
            [CheckStatus.ERROR, CheckStatus.ERROR, CheckStatus.ERROR],
        ),
        (
            "maxauthtries 4 extra\npermitemptypasswords no\npermitrootlogin no\n",
            [CheckStatus.ERROR, CheckStatus.PASS, CheckStatus.PASS],
        ),
    ],
)
def test_malformed_output_returns_error(
    monkeypatch: pytest.MonkeyPatch,
    output: str,
    expected_statuses: list[CheckStatus],
) -> None:
    """Handle invalid target values and malformed lines without crashing."""
    _install_command(monkeypatch, output)

    results = ssh.run_ssh_checks()

    assert [result.status for result in results] == expected_statuses


def test_conflicting_duplicate_values_return_error_for_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject conflicting duplicate entries for a selected setting."""
    _install_command(
        monkeypatch,
        "maxauthtries 4\n"
        "MaxAuthTries 5\n"
        "permitemptypasswords no\n"
        "permitrootlogin no\n",
    )

    results = _results_by_id(ssh.run_ssh_checks())

    assert results["5.1.16"].status is CheckStatus.ERROR
    assert results["5.1.19"].status is CheckStatus.PASS
    assert results["5.1.20"].status is CheckStatus.PASS


@pytest.mark.parametrize(
    "error",
    [
        CommandUnavailableError("private command detail"),
        CommandTimeoutError("private timeout detail"),
        CommandError("private permission detail"),
    ],
)
def test_command_errors_return_generic_error_results(
    monkeypatch: pytest.MonkeyPatch, error: CommandError
) -> None:
    """Return generic ERROR results for unavailable, timed-out, or denied commands."""
    def fail_command(
        arguments: Sequence[str], *, timeout_seconds: float
    ) -> NoReturn:
        raise error

    monkeypatch.setattr(ssh, "run_command", fail_command)

    results = ssh.run_ssh_checks()

    assert len(results) == 3
    assert all(result.status is CheckStatus.ERROR for result in results)
    assert all("private" not in result.summary for result in results)


def test_nonzero_command_status_returns_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Return ERROR results when sshd cannot evaluate its configuration."""
    _install_command(
        monkeypatch,
        "maxauthtries 4\npermitemptypasswords no\npermitrootlogin no\n",
        returncode=1,
    )

    results = ssh.run_ssh_checks()

    assert all(result.status is CheckStatus.ERROR for result in results)