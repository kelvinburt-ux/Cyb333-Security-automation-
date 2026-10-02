"""Tests for the three account-file permission checks."""

from types import SimpleNamespace
from typing import Callable

import pytest

from secure_config_check.checks import permissions
from secure_config_check.models import CheckResult, CheckStatus


@pytest.mark.parametrize(
    ("check", "mode", "group_id", "group_name"),
    [
        (permissions.check_passwd, 0o600, 0, "root"),
        (permissions.check_group, 0o644, 0, "root"),
        (permissions.check_shadow, 0o400, 42, "shadow"),
    ],
)
def test_secure_metadata_passes(
    monkeypatch: pytest.MonkeyPatch,
    check: Callable[[], CheckResult],
    mode: int,
    group_id: int,
    group_name: str,
) -> None:
    """Accept secure ownership and modes, including stricter modes."""
    observed: list[tuple[str, bool]] = []

    def fake_stat(path: str, *, follow_symlinks: bool) -> SimpleNamespace:
        observed.append((path, follow_symlinks))
        return SimpleNamespace(
            st_mode=permissions.stat.S_IFREG | mode,
            st_uid=0,
            st_gid=group_id,
        )

    monkeypatch.setattr(permissions.os, "stat", fake_stat)
    monkeypatch.setattr(permissions, "_user_name", lambda uid: "root")
    monkeypatch.setattr(permissions, "_group_name", lambda gid: group_name)

    result = check()

    assert result.status is CheckStatus.PASS
    assert observed == [(result.title.removeprefix("Access to "), False)]


@pytest.mark.parametrize(
    ("check", "mode", "group_id", "group_name"),
    [
        (permissions.check_passwd, 0o664, 0, "root"),
        (permissions.check_group, 0o646, 0, "root"),
        (permissions.check_shadow, 0o644, 42, "shadow"),
    ],
)
def test_excessive_permissions_fail(
    monkeypatch: pytest.MonkeyPatch,
    check: Callable[[], CheckResult],
    mode: int,
    group_id: int,
    group_name: str,
) -> None:
    """Reject modes with any permission bits beyond the verified maximum."""
    monkeypatch.setattr(
        permissions.os,
        "stat",
        lambda path, *, follow_symlinks: SimpleNamespace(
            st_mode=permissions.stat.S_IFREG | mode,
            st_uid=0,
            st_gid=group_id,
        ),
    )
    monkeypatch.setattr(permissions, "_user_name", lambda uid: "root")
    monkeypatch.setattr(permissions, "_group_name", lambda gid: group_name)

    assert check().status is CheckStatus.FAIL


@pytest.mark.parametrize(
    ("check", "uid", "user_name", "gid", "group_name"),
    [
        (permissions.check_passwd, 1, "root", 0, "root"),
        (permissions.check_group, 0, "service-user", 0, "root"),
        (permissions.check_passwd, 0, "root", 1, "root"),
        (permissions.check_shadow, 0, "root", 42, "users"),
    ],
)
def test_ownership_mismatches_fail_without_disclosing_names(
    monkeypatch: pytest.MonkeyPatch,
    check: Callable[[], CheckResult],
    uid: int,
    user_name: str,
    gid: int,
    group_name: str,
) -> None:
    """Reject owner/group mismatches without placing names in the result."""
    monkeypatch.setattr(
        permissions.os,
        "stat",
        lambda path, *, follow_symlinks: SimpleNamespace(
            st_mode=permissions.stat.S_IFREG | 0o600,
            st_uid=uid,
            st_gid=gid,
        ),
    )
    monkeypatch.setattr(permissions, "_user_name", lambda found_uid: user_name)
    monkeypatch.setattr(permissions, "_group_name", lambda found_gid: group_name)

    result = check()

    assert result.status is CheckStatus.FAIL
    assert "service-user" not in result.summary
    assert "users" not in result.summary


def test_missing_file_returns_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Return ERROR when the requested configuration file is missing."""
    def missing_file(path: str, *, follow_symlinks: bool) -> None:
        raise FileNotFoundError("private file detail")

    monkeypatch.setattr(permissions.os, "stat", missing_file)

    result = permissions.check_shadow()

    assert result.status is CheckStatus.ERROR
    assert "private file detail" not in result.summary


def test_permission_error_returns_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Return ERROR when metadata cannot be read due to permissions."""
    def denied_file(path: str, *, follow_symlinks: bool) -> None:
        raise PermissionError("private permission detail")

    monkeypatch.setattr(permissions.os, "stat", denied_file)

    result = permissions.check_passwd()

    assert result.status is CheckStatus.ERROR
    assert "private permission detail" not in result.summary


def test_unresolved_owner_returns_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Return ERROR when a numeric root ID cannot be resolved safely."""
    monkeypatch.setattr(
        permissions.os,
        "stat",
        lambda path, *, follow_symlinks: SimpleNamespace(
            st_mode=permissions.stat.S_IFREG | 0o644,
            st_uid=0,
            st_gid=0,
        ),
    )
    monkeypatch.setattr(permissions, "_user_name", lambda uid: None)

    assert permissions.check_passwd().status is CheckStatus.ERROR


def test_runner_returns_exactly_the_three_controls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Return all three permission results in the requested control order."""
    monkeypatch.setattr(
        permissions.os,
        "stat",
        lambda path, *, follow_symlinks: SimpleNamespace(
            st_mode=permissions.stat.S_IFREG | 0o600,
            st_uid=0,
            st_gid=0,
        ),
    )
    monkeypatch.setattr(permissions, "_user_name", lambda uid: "root")
    monkeypatch.setattr(permissions, "_group_name", lambda gid: "root")

    results = permissions.run_permission_checks()

    assert [result.control_id for result in results] == ["7.1.1", "7.1.3", "7.1.5"]
    assert all(result.status is CheckStatus.PASS for result in results)