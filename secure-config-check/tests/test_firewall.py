"""Isolated tests for UFW package, service, and policy checks."""

from collections.abc import Sequence
import subprocess

import pytest

from secure_config_check.checks import firewall
from secure_config_check.helpers import (
    CommandError,
    CommandTimeoutError,
    CommandUnavailableError,
)
from secure_config_check.models import CheckResult, CheckStatus


_PACKAGE_COMMAND = ("dpkg-query", "-W", "-f=${Status}", "ufw")
_ENABLED_COMMAND = ("systemctl", "is-enabled", "ufw.service")
_ACTIVE_COMMAND = ("systemctl", "is-active", "ufw.service")
_UFW_COMMAND = ("ufw", "status", "verbose")
_COMMANDS = [_PACKAGE_COMMAND, _ENABLED_COMMAND, _ACTIVE_COMMAND, _UFW_COMMAND]


def _process(
    command: tuple[str, ...], output: str, returncode: int = 0
) -> subprocess.CompletedProcess[str]:
    """Create a command result for the mocked command runner."""
    return subprocess.CompletedProcess(command, returncode, stdout=output)


def _successful_responses() -> dict[
    tuple[str, ...], subprocess.CompletedProcess[str]
]:
    """Return safe default outputs representing a compliant UFW system."""
    return {
        _PACKAGE_COMMAND: _process(_PACKAGE_COMMAND, "install ok installed\n"),
        _ENABLED_COMMAND: _process(_ENABLED_COMMAND, "enabled\n"),
        _ACTIVE_COMMAND: _process(_ACTIVE_COMMAND, "active\n"),
        _UFW_COMMAND: _process(
            _UFW_COMMAND,
            "Status: active\n"
            "Default: deny (incoming), allow (outgoing), disabled (routed)\n"
            "To                         Action      From\n"
            "22/tcp                     ALLOW IN    192.0.2.10\n",
        ),
    }


def _install_runner(
    monkeypatch: pytest.MonkeyPatch,
    *,
    responses: dict[tuple[str, ...], subprocess.CompletedProcess[str]] | None = None,
    errors: dict[tuple[str, ...], CommandError] | None = None,
) -> list[tuple[str, ...]]:
    """Mock command execution and record every argument list."""
    command_responses = _successful_responses()
    if responses is not None:
        command_responses.update(responses)
    command_errors = errors or {}
    calls: list[tuple[str, ...]] = []

    def fake_run_command(
        arguments: Sequence[str], *, timeout_seconds: float
    ) -> subprocess.CompletedProcess[str]:
        command = tuple(arguments)
        calls.append(command)
        if command in command_errors:
            raise command_errors[command]
        return command_responses[command]

    monkeypatch.setattr(firewall, "run_command", fake_run_command)
    return calls


def _by_id(results: list[CheckResult]) -> dict[str, CheckResult]:
    """Index check results by control ID for readable assertions."""
    return {result.control_id: result for result in results}


def test_installed_enabled_active_and_deny_pass_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pass all controls and invoke every required command exactly once."""
    calls = _install_runner(monkeypatch)

    results = firewall.run_firewall_checks(timeout_seconds=3.0)

    assert [result.status for result in results] == [
        CheckStatus.PASS,
        CheckStatus.PASS,
        CheckStatus.PASS,
    ]
    assert calls == _COMMANDS
    assert all(calls.count(command) == 1 for command in _COMMANDS)


def test_known_not_installed_package_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Return FAIL when dpkg-query successfully confirms UFW is not installed."""
    calls = _install_runner(
        monkeypatch,
        responses={
            _PACKAGE_COMMAND: _process(
                _PACKAGE_COMMAND, "deinstall ok config-files\n"
            )
        },
    )

    results = _by_id(firewall.run_firewall_checks())

    assert results["4.1.1"].status is CheckStatus.FAIL
    assert len(calls) == 4


def test_disabled_service_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Return FAIL for a known disabled service state."""
    _install_runner(
        monkeypatch,
        responses={_ENABLED_COMMAND: _process(_ENABLED_COMMAND, "disabled\n", 1)},
    )

    results = _by_id(firewall.run_firewall_checks())

    assert results["4.1.2"].status is CheckStatus.FAIL


def test_inactive_service_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Return FAIL for a known inactive service state."""
    _install_runner(
        monkeypatch,
        responses={_ACTIVE_COMMAND: _process(_ACTIVE_COMMAND, "inactive\n", 3)},
    )

    results = _by_id(firewall.run_firewall_checks())

    assert results["4.1.2"].status is CheckStatus.FAIL


@pytest.mark.parametrize("policy", ["deny", "reject"])
def test_restrictive_incoming_policy_passes(
    monkeypatch: pytest.MonkeyPatch, policy: str
) -> None:
    """Pass for either accepted incoming default policy."""
    output = f"Status: active\nDefault: {policy} (incoming), allow (outgoing)\n"
    _install_runner(
        monkeypatch,
        responses={_UFW_COMMAND: _process(_UFW_COMMAND, output)},
    )

    results = _by_id(firewall.run_firewall_checks())

    assert results["4.1.3"].status is CheckStatus.PASS


@pytest.mark.parametrize("policy", ["allow", "limit", "skip"])
def test_nonrestrictive_incoming_policy_fails(
    monkeypatch: pytest.MonkeyPatch, policy: str
) -> None:
    """Fail for recognized incoming defaults that are not deny or reject."""
    output = f"Status: active\nDefault: {policy} (incoming), allow (outgoing)\n"
    _install_runner(
        monkeypatch,
        responses={_UFW_COMMAND: _process(_UFW_COMMAND, output)},
    )

    results = _by_id(firewall.run_firewall_checks())

    assert results["4.1.3"].status is CheckStatus.FAIL


@pytest.mark.parametrize(
    ("command", "error"),
    [
        (_PACKAGE_COMMAND, CommandUnavailableError("private command name")),
        (_ENABLED_COMMAND, CommandTimeoutError("private timeout detail")),
        (_UFW_COMMAND, CommandError("private permission detail")),
    ],
)
def test_command_failures_return_error(
    monkeypatch: pytest.MonkeyPatch,
    command: tuple[str, ...],
    error: CommandError,
) -> None:
    """Return generic ERROR for missing commands, timeouts, and permission errors."""
    _install_runner(monkeypatch, errors={command: error})

    results = firewall.run_firewall_checks()

    affected_control = {
        _PACKAGE_COMMAND: "4.1.1",
        _ENABLED_COMMAND: "4.1.2",
        _UFW_COMMAND: "4.1.2",
    }[command]
    assert _by_id(results)[affected_control].status is CheckStatus.ERROR
    assert all("private" not in result.summary for result in results)


@pytest.mark.parametrize(
    ("command", "output", "returncode", "control_id"),
    [
        (_PACKAGE_COMMAND, "package state unknown\n", 0, "4.1.1"),
        (_PACKAGE_COMMAND, "install ok installed\n", 1, "4.1.1"),
        (_ENABLED_COMMAND, "unexpected\n", 0, "4.1.2"),
        (_ACTIVE_COMMAND, "active\n", 1, "4.1.2"),
        (_UFW_COMMAND, "Status active\nDefault: deny (incoming)\n", 0, "4.1.2"),
        (_UFW_COMMAND, "Status: active\nDefault: mystery (incoming)\n", 0, "4.1.3"),
    ],
)
def test_malformed_or_unexpected_results_return_error(
    monkeypatch: pytest.MonkeyPatch,
    command: tuple[str, ...],
    output: str,
    returncode: int,
    control_id: str,
) -> None:
    """Return ERROR for malformed output or unexpected command exit status."""
    _install_runner(
        monkeypatch,
        responses={command: _process(command, output, returncode)},
    )

    results = _by_id(firewall.run_firewall_checks())

    assert results[control_id].status is CheckStatus.ERROR


def test_inactive_ufw_status_fails_service_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Return FAIL when UFW reports a known inactive firewall state."""
    _install_runner(
        monkeypatch,
        responses={
            _UFW_COMMAND: _process(
                _UFW_COMMAND,
                "Status: inactive\nDefault: allow (incoming), allow (outgoing)\n",
            )
        },
    )

    results = _by_id(firewall.run_firewall_checks())

    assert results["4.1.2"].status is CheckStatus.FAIL
    assert results["4.1.3"].status is CheckStatus.FAIL


def test_inactive_status_without_policy_is_fail_and_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep a known inactive state distinct from a missing incoming policy."""
    _install_runner(
        monkeypatch,
        responses={
            _UFW_COMMAND: _process(_UFW_COMMAND, "Status: inactive\n")
        },
    )

    results = _by_id(firewall.run_firewall_checks())

    assert results["4.1.2"].status is CheckStatus.FAIL
    assert results["4.1.3"].status is CheckStatus.ERROR


def test_reports_do_not_expose_firewall_rules_or_network_details(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep addresses, interfaces, ports, and rule output out of summaries."""
    sensitive_output = (
        "Status: active\n"
        "Default: deny (incoming), allow (outgoing)\n"
        "eth9 8443/tcp ALLOW IN 203.0.113.25\n"
    )
    _install_runner(
        monkeypatch,
        responses={_UFW_COMMAND: _process(_UFW_COMMAND, sensitive_output)},
    )

    results = firewall.run_firewall_checks()

    for result in results:
        assert "eth9" not in result.summary
        assert "8443" not in result.summary
        assert "203.0.113.25" not in result.summary