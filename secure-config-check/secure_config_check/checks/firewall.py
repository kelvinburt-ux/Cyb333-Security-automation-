"""Read-only checks for UFW package, service state, and incoming policy."""

from collections.abc import Callable, Sequence
import re
import subprocess

from secure_config_check.helpers import CommandError, run_command
from secure_config_check.models import CheckResult, CheckStatus


_TIMEOUT_SECONDS = 5.0
_ERROR_SUMMARY = "Firewall configuration could not be safely checked."
_PACKAGE_CONTROL = ("4.1.1", "UFW is installed")
_SERVICE_CONTROL = ("4.1.2", "UFW service is configured")
_POLICY_CONTROL = ("4.1.3", "UFW incoming default policy")
_PACKAGE_NOT_INSTALLED = frozenset(
    {
        "deinstall ok config-files",
        "purge ok not-installed",
        "unknown ok not-installed",
    }
)
_ENABLED_STATES = frozenset(
    {
        "enabled-runtime",
        "linked",
        "linked-runtime",
        "alias",
        "static",
        "indirect",
        "generated",
        "transient",
        "masked",
        "masked-runtime",
        "disabled",
    }
)
_INACTIVE_STATES = {
    "inactive": frozenset({3}),
    "failed": frozenset({3}),
    "activating": frozenset({0}),
    "deactivating": frozenset({0}),
    "reloading": frozenset({0}),
    "maintenance": frozenset({3}),
    "refreshing": frozenset({0}),
}
_INCOMING_POLICIES = frozenset({"deny", "reject", "allow", "limit", "skip"})
_INCOMING_POLICY_PATTERN = re.compile(
    r"^([a-z-]+)\s+\(incoming\)(?:,|$)", re.IGNORECASE
)
_CommandRunner = Callable[..., subprocess.CompletedProcess[str]]


def _run_once(
    runner: _CommandRunner, arguments: Sequence[str], timeout_seconds: float
) -> subprocess.CompletedProcess[str] | None:
    """Run one command through the safe helper and hide expected command errors."""
    try:
        return runner(arguments, timeout_seconds=timeout_seconds)
    except CommandError:
        return None


def _package_status(
    result: subprocess.CompletedProcess[str] | None,
) -> CheckStatus:
    """Classify dpkg-query output without retaining package command text."""
    if result is None or result.returncode != 0:
        return CheckStatus.ERROR

    output = result.stdout.strip().lower()
    if output == "install ok installed":
        return CheckStatus.PASS
    if output in _PACKAGE_NOT_INSTALLED:
        return CheckStatus.FAIL
    return CheckStatus.ERROR


def _systemctl_status(
    result: subprocess.CompletedProcess[str] | None, *, operation: str
) -> CheckStatus:
    """Classify one systemctl state, distinguishing known noncompliance from errors."""
    if result is None:
        return CheckStatus.ERROR

    lines = [line.strip().lower() for line in result.stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        return CheckStatus.ERROR
    state = lines[0]

    if operation == "enabled":
        if state == "enabled":
            return CheckStatus.PASS if result.returncode == 0 else CheckStatus.ERROR
        if state in {"disabled", "masked", "masked-runtime"}:
            return CheckStatus.FAIL if result.returncode == 1 else CheckStatus.ERROR
        if state in _ENABLED_STATES:
            return CheckStatus.FAIL if result.returncode == 0 else CheckStatus.ERROR
        return CheckStatus.ERROR

    if state == "active":
        return CheckStatus.PASS if result.returncode == 0 else CheckStatus.ERROR
    expected_codes = _INACTIVE_STATES.get(state)
    if expected_codes is None:
        return CheckStatus.ERROR
    return CheckStatus.FAIL if result.returncode in expected_codes else CheckStatus.ERROR


def _parse_ufw_status(output: str) -> tuple[str | None, str | None]:
    """Extract valid UFW state and policy independently from verbose output."""
    status_values: list[str] = []
    incoming_values: list[str] = []
    malformed_status = False
    malformed_policy = False

    for line in output.splitlines():
        stripped = line.strip()
        lowered = stripped.lower()
        if lowered.startswith("status"):
            key, separator, value = stripped.partition(":")
            if key.strip().lower() != "status" or not separator or not value.strip():
                malformed_status = True
            else:
                status_values.append(value.strip().lower())
        elif lowered.startswith("default"):
            key, separator, value = stripped.partition(":")
            if key.strip().lower() != "default" or not separator:
                malformed_policy = True
            else:
                match = _INCOMING_POLICY_PATTERN.match(value.strip())
                if match is None:
                    malformed_policy = True
                else:
                    incoming_values.append(match.group(1).lower())

    status = None
    if (
        status_values
        and len(set(status_values)) == 1
        and status_values[0] in {"active", "inactive"}
        and not malformed_status
    ):
        status = status_values[0]

    policy = None
    if (
        incoming_values
        and len(set(incoming_values)) == 1
        and incoming_values[0] in _INCOMING_POLICIES
        and not malformed_policy
    ):
        policy = incoming_values[0]
    return status, policy


def _ufw_status_values(
    result: subprocess.CompletedProcess[str] | None,
) -> tuple[str | None, str | None] | None:
    """Parse successful UFW output, converting command failures to unavailable values."""
    if result is None or result.returncode != 0:
        return None
    return _parse_ufw_status(result.stdout)


def _result(
    control: tuple[str, str], status: CheckStatus, summary: str
) -> CheckResult:
    """Create a result with only its fixed control label and safe summary."""
    return CheckResult(control[0], control[1], status, summary)


def run_firewall_checks(
    timeout_seconds: float = _TIMEOUT_SECONDS,
    command_runner: _CommandRunner | None = None,
) -> list[CheckResult]:
    """Run each required read-only command once and return three UFW results."""
    runner = command_runner or run_command
    package_result = _run_once(
        runner,
        ["dpkg-query", "-W", "-f=${Status}", "ufw"],
        timeout_seconds,
    )
    enabled_result = _run_once(
        runner, ["systemctl", "is-enabled", "ufw.service"], timeout_seconds
    )
    active_result = _run_once(
        runner, ["systemctl", "is-active", "ufw.service"], timeout_seconds
    )
    ufw_result = _run_once(runner, ["ufw", "status", "verbose"], timeout_seconds)

    package_status = _package_status(package_result)
    package_summary = {
        CheckStatus.PASS: "The UFW package is installed.",
        CheckStatus.FAIL: "The UFW package is not installed.",
        CheckStatus.ERROR: "The UFW package state could not be safely checked.",
    }[package_status]

    ufw_values = _ufw_status_values(ufw_result)
    enabled_status = _systemctl_status(enabled_result, operation="enabled")
    active_status = _systemctl_status(active_result, operation="active")
    ufw_status = None if ufw_values is None else ufw_values[0]
    ufw_active_status = (
        CheckStatus.ERROR
        if ufw_status is None
        else CheckStatus.PASS
        if ufw_status == "active"
        else CheckStatus.FAIL
    )
    service_states = (enabled_status, active_status, ufw_active_status)
    if CheckStatus.ERROR in service_states:
        service_status = CheckStatus.ERROR
        service_summary = "UFW service state could not be safely checked."
    elif CheckStatus.FAIL in service_states:
        service_status = CheckStatus.FAIL
        service_summary = "UFW service is disabled or inactive."
    else:
        service_status = CheckStatus.PASS
        service_summary = "UFW service is enabled and active."

    policy_status = CheckStatus.ERROR
    policy_summary = "UFW incoming default policy could not be safely checked."
    incoming_policy = None if ufw_values is None else ufw_values[1]
    if incoming_policy is not None:
        if incoming_policy in {"deny", "reject"}:
            policy_status = CheckStatus.PASS
            policy_summary = "UFW incoming default policy is restrictive."
        else:
            policy_status = CheckStatus.FAIL
            policy_summary = "UFW incoming default policy is not restrictive."

    return [
        _result(_PACKAGE_CONTROL, package_status, package_summary),
        _result(_SERVICE_CONTROL, service_status, service_summary),
        _result(_POLICY_CONTROL, policy_status, policy_summary),
    ]