"""Orchestrate the fixed set of read-only security configuration checks."""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from secure_config_check.checks.accounts import run_account_checks
from secure_config_check.checks.firewall import run_firewall_checks
from secure_config_check.checks.passwords import run_password_checks
from secure_config_check.checks.permissions import run_permission_checks
from secure_config_check.checks.ssh import run_ssh_checks
from secure_config_check.models import AuditReport, CheckResult, CheckStatus


CategoryRunner = Callable[[], Sequence[CheckResult]]
CategoryControls = tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class _Category:
    """Describe one fixed category runner and its expected control results."""

    name: str
    runner: CategoryRunner
    controls: CategoryControls


_CATEGORY_REGISTRY = (
    _Category(
        "permissions",
        run_permission_checks,
        (
            ("7.1.1", "Access to /etc/passwd"),
            ("7.1.3", "Access to /etc/group"),
            ("7.1.5", "Access to /etc/shadow"),
        ),
    ),
    _Category(
        "ssh",
        run_ssh_checks,
        (
            ("5.1.16", "SSH MaxAuthTries"),
            ("5.1.19", "SSH PermitEmptyPasswords"),
            ("5.1.20", "SSH PermitRootLogin"),
        ),
    ),
    _Category(
        "passwords",
        run_password_checks,
        (
            ("5.3.3.2.2", "Minimum password length"),
            ("5.4.1.1", "Password expiration"),
            ("5.4.1.3", "Password expiration warning"),
        ),
    ),
    _Category(
        "firewall",
        run_firewall_checks,
        (
            ("4.1.1", "UFW is installed"),
            ("4.1.2", "UFW service is configured"),
            ("4.1.3", "UFW incoming default policy"),
        ),
    ),
    _Category(
        "accounts",
        run_account_checks,
        (
            ("5.4.2.1", "Root is the only UID 0 account"),
            ("7.2.1", "Accounts use shadowed passwords"),
            ("7.2.2", "Shadow password fields are not empty"),
        ),
    ),
)
_CONTROL_ORDER = tuple(
    control_id
    for category in _CATEGORY_REGISTRY
    for control_id, _ in category.controls
)
_GENERIC_ERROR_SUMMARY = "The check could not be safely completed."


def _category_error_results(category: _Category) -> list[CheckResult]:
    """Build generic errors for the expected controls in one failed category."""
    return [
        CheckResult(control_id, title, CheckStatus.ERROR, _GENERIC_ERROR_SUMMARY)
        for control_id, title in category.controls
    ]


def _validate_results(results: Sequence[CheckResult]) -> list[CheckResult]:
    """Require every registered control exactly once before report creation."""
    if any(not isinstance(result, CheckResult) for result in results):
        raise ValueError("category runners must return CheckResult values")

    control_ids = [result.control_id for result in results]
    if len(control_ids) != len(set(control_ids)):
        raise ValueError("duplicate control IDs were returned")

    expected_ids = set(_CONTROL_ORDER)
    returned_ids = set(control_ids)
    if returned_ids - expected_ids:
        raise ValueError("unexpected control IDs were returned")
    if expected_ids - returned_ids:
        raise ValueError("one or more registered control IDs are missing")
    if len(control_ids) != len(_CONTROL_ORDER):
        raise ValueError("the number of returned controls is invalid")

    results_by_id = {result.control_id: result for result in results}
    return [results_by_id[control_id] for control_id in _CONTROL_ORDER]


def run_audit(
    runners: Mapping[str, CategoryRunner] | None = None,
) -> AuditReport:
    """Run each category once and return a validated, ordered 15-control report.

    Optional runner overrides are keyed by the fixed category names and let
    tests supply results without reading the host system.
    """
    runner_overrides = runners or {}
    registered_names = {category.name for category in _CATEGORY_REGISTRY}
    if set(runner_overrides) - registered_names:
        raise ValueError("runner overrides contain an unknown category")

    collected_results: list[CheckResult] = []
    for category in _CATEGORY_REGISTRY:
        runner = runner_overrides.get(category.name, category.runner)
        try:
            category_results = list(runner())
        except Exception:
            category_results = _category_error_results(category)
        collected_results.extend(category_results)

    ordered_results = _validate_results(collected_results)
    return AuditReport(results=ordered_results)