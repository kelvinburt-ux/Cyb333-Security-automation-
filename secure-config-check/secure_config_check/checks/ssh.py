"""Read-only checks for selected effective OpenSSH server settings."""

from secure_config_check.helpers import CommandError, run_command
from secure_config_check.models import CheckResult, CheckStatus


_TIMEOUT_SECONDS = 5.0
_ERROR_SUMMARY = "Effective SSH setting could not be safely checked."
_PASS_SUMMARY = "Effective SSH setting meets the configured requirement."
_FAIL_SUMMARY = "Effective SSH setting does not meet the configured requirement."
_CONTROL_INFO = (
    ("maxauthtries", "5.1.16", "SSH MaxAuthTries"),
    ("permitemptypasswords", "5.1.19", "SSH PermitEmptyPasswords"),
    ("permitrootlogin", "5.1.20", "SSH PermitRootLogin"),
)
_ROOT_LOGIN_VALUES = frozenset(
    {"yes", "no", "prohibit-password", "without-password", "forced-commands-only"}
)


def _error_results() -> list[CheckResult]:
    """Create generic ERROR results for all selected SSH controls."""
    return [
        CheckResult(control_id, title, CheckStatus.ERROR, _ERROR_SUMMARY)
        for _, control_id, title in _CONTROL_INFO
    ]


def _parse_effective_settings(output: str) -> tuple[dict[str, str], set[str]]:
    """Keep only selected key/value pairs and flag malformed or conflicting keys."""
    if not output.strip():
        raise ValueError("effective SSH settings are empty")

    selected_keys = {key for key, _, _ in _CONTROL_INFO}
    settings: dict[str, str] = {}
    invalid_keys: set[str] = set()

    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 2:
            raise ValueError("effective SSH settings contain a malformed line")

        key = fields[0].lower()
        if key not in selected_keys:
            continue
        if len(fields) != 2:
            invalid_keys.add(key)
            continue

        value = fields[1].lower()
        previous_value = settings.get(key)
        if previous_value is not None and previous_value != value:
            invalid_keys.add(key)
        else:
            settings[key] = value

    return settings, invalid_keys


def _evaluate_setting(
    key: str, settings: dict[str, str], invalid_keys: set[str]
) -> CheckStatus:
    """Determine one selected setting's status without retaining raw output."""
    if key in invalid_keys or key not in settings:
        return CheckStatus.ERROR

    value = settings[key]
    if key == "maxauthtries":
        try:
            attempts = int(value)
        except ValueError:
            return CheckStatus.ERROR
        return CheckStatus.PASS if 1 <= attempts <= 4 else CheckStatus.FAIL

    if key == "permitemptypasswords":
        if value not in {"yes", "no"}:
            return CheckStatus.ERROR
        return CheckStatus.PASS if value == "no" else CheckStatus.FAIL

    if key == "permitrootlogin":
        if value not in _ROOT_LOGIN_VALUES:
            return CheckStatus.ERROR
        return CheckStatus.PASS if value == "no" else CheckStatus.FAIL

    return CheckStatus.ERROR


def run_ssh_checks(timeout_seconds: float = _TIMEOUT_SECONDS) -> list[CheckResult]:
    """Run ``sshd -T`` once and return results for the three selected controls."""
    try:
        command_result = run_command(["sshd", "-T"], timeout_seconds=timeout_seconds)
    except CommandError:
        return _error_results()

    if command_result.returncode != 0:
        return _error_results()

    try:
        settings, invalid_keys = _parse_effective_settings(command_result.stdout)
    except ValueError:
        return _error_results()

    results = []
    for key, control_id, title in _CONTROL_INFO:
        status = _evaluate_setting(key, settings, invalid_keys)
        summary = _PASS_SUMMARY if status is CheckStatus.PASS else (
            _FAIL_SUMMARY if status is CheckStatus.FAIL else _ERROR_SUMMARY
        )
        results.append(CheckResult(control_id, title, status, summary))
    return results