"""Tests for fixed-order audit orchestration and failure isolation."""

from collections.abc import Callable

import pytest

from secure_config_check import auditor
from secure_config_check.models import AuditReport, CheckResult, CheckStatus


_CATEGORY_CONTROLS = {
    "permissions": ("7.1.1", "7.1.3", "7.1.5"),
    "ssh": ("5.1.16", "5.1.19", "5.1.20"),
    "passwords": ("5.3.3.2.2", "5.4.1.1", "5.4.1.3"),
    "firewall": ("4.1.1", "4.1.2", "4.1.3"),
    "accounts": ("5.4.2.1", "7.2.1", "7.2.2"),
}
_EXPECTED_CONTROL_ORDER = (
    "7.1.1",
    "7.1.3",
    "7.1.5",
    "5.1.16",
    "5.1.19",
    "5.1.20",
    "5.3.3.2.2",
    "5.4.1.1",
    "5.4.1.3",
    "4.1.1",
    "4.1.2",
    "4.1.3",
    "5.4.2.1",
    "7.2.1",
    "7.2.2",
)
_CONTROL_TITLES = {
    control_id: title
    for controls in (
        (
            ("7.1.1", "Access to /etc/passwd"),
            ("7.1.3", "Access to /etc/group"),
            ("7.1.5", "Access to /etc/shadow"),
        ),
        (
            ("5.1.16", "SSH MaxAuthTries"),
            ("5.1.19", "SSH PermitEmptyPasswords"),
            ("5.1.20", "SSH PermitRootLogin"),
        ),
        (
            ("5.3.3.2.2", "Minimum password length"),
            ("5.4.1.1", "Password expiration"),
            ("5.4.1.3", "Password expiration warning"),
        ),
        (
            ("4.1.1", "UFW is installed"),
            ("4.1.2", "UFW service is configured"),
            ("4.1.3", "UFW incoming default policy"),
        ),
        (
            ("5.4.2.1", "Root is the only UID 0 account"),
            ("7.2.1", "Accounts use shadowed passwords"),
            ("7.2.2", "Shadow password fields are not empty"),
        ),
    )
    for control_id, title in controls
}


def _results_for(control_ids: tuple[str, ...]) -> list[CheckResult]:
    """Create harmless PASS results for the requested control IDs."""
    return [
        CheckResult(
            control_id,
            _CONTROL_TITLES.get(control_id, "Unexpected synthetic check"),
            CheckStatus.PASS,
            "Synthetic test result.",
        )
        for control_id in control_ids
    ]


def _normal_runners(
    calls: list[str] | None = None,
) -> dict[str, Callable[[], list[CheckResult]]]:
    """Create injectable category runners that return the expected IDs."""
    runners: dict[str, Callable[[], list[CheckResult]]] = {}
    for category_name, control_ids in _CATEGORY_CONTROLS.items():
        def run_category(
            name: str = category_name,
            registered_ids: tuple[str, ...] = control_ids,
        ) -> list[CheckResult]:
            if calls is not None:
                calls.append(name)
            return _results_for(registered_ids)

        runners[category_name] = run_category
    return runners


def test_each_category_runner_is_called_exactly_once() -> None:
    """Call every injected category runner once in registry order."""
    calls: list[str] = []

    report = auditor.run_audit(_normal_runners(calls))

    assert calls == ["permissions", "ssh", "passwords", "firewall", "accounts"]
    assert len(report.results) == 15


def test_report_has_exact_control_order() -> None:
    """Return controls in the required order, regardless of runner result order."""
    runners = _normal_runners()
    for category_name, runner in runners.items():
        runners[category_name] = lambda current=runner: list(reversed(current()))

    report = auditor.run_audit(runners)

    assert tuple(result.control_id for result in report.results) == _EXPECTED_CONTROL_ORDER


def test_duplicate_control_id_is_rejected() -> None:
    """Reject duplicate IDs before constructing an audit report."""
    runners = _normal_runners()
    runners["permissions"] = lambda: _results_for(("7.1.1", "7.1.1", "7.1.5"))

    with pytest.raises(ValueError, match="duplicate control IDs"):
        auditor.run_audit(runners)


def test_missing_control_id_is_rejected() -> None:
    """Reject a report that omits one registered control."""
    runners = _normal_runners()
    runners["ssh"] = lambda: _results_for(("5.1.16", "5.1.19"))

    with pytest.raises(ValueError, match="missing"):
        auditor.run_audit(runners)


def test_unexpected_control_id_is_rejected() -> None:
    """Reject an unregistered ID instead of placing it in the report."""
    runners = _normal_runners()
    runners["accounts"] = lambda: _results_for(("5.4.2.1", "7.2.1", "9.9.9"))

    with pytest.raises(ValueError, match="unexpected"):
        auditor.run_audit(runners)


def test_category_exception_does_not_stop_later_runners() -> None:
    """Replace one failed category with errors and continue remaining categories."""
    calls: list[str] = []
    runners = _normal_runners(calls)

    def fail_permissions() -> list[CheckResult]:
        calls.append("permissions")
        raise RuntimeError("private username /etc/shadow contents")

    runners["permissions"] = fail_permissions

    report = auditor.run_audit(runners)

    assert calls == ["permissions", "ssh", "passwords", "firewall", "accounts"]
    failed_results = report.results[:3]
    assert all(result.status is CheckStatus.ERROR for result in failed_results)
    assert all(
        "private username" not in result.summary
        and "/etc/shadow contents" not in result.summary
        for result in failed_results
    )
    assert all(result.status is CheckStatus.PASS for result in report.results[3:])


def test_report_contains_exactly_fifteen_unique_results() -> None:
    """Return an AuditReport with all 15 registered controls exactly once."""
    report = auditor.run_audit(_normal_runners())

    assert isinstance(report, AuditReport)
    assert len(report.results) == 15
    assert len({result.control_id for result in report.results}) == 15