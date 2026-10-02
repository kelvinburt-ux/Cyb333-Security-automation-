"""Read-only ownership and permission checks for critical account files."""

import os
import stat

from secure_config_check.models import CheckResult, CheckStatus


_PASS_SUMMARY = "Ownership and permissions meet the configured requirement."
_FAIL_SUMMARY = "Ownership, file type, or permissions do not meet the requirement."
_ERROR_SUMMARY = "Required file metadata could not be safely checked."


def _user_name(uid: int) -> str | None:
    """Resolve a numeric user ID without exposing lookup errors."""
    try:
        import pwd

        return pwd.getpwuid(uid).pw_name
    except (ImportError, KeyError, OSError):
        return None


def _group_name(gid: int) -> str | None:
    """Resolve a numeric group ID without exposing lookup errors."""
    try:
        import grp

        return grp.getgrgid(gid).gr_name
    except (ImportError, KeyError, OSError):
        return None


def _check_file(
    *,
    control_id: str,
    title: str,
    path: str,
    maximum_mode: int,
    allowed_group_ids: frozenset[int] | None,
    allowed_group_names: frozenset[str],
) -> CheckResult:
    """Compare file metadata to a control without reading file contents."""
    try:
        metadata = os.stat(path, follow_symlinks=False)
    except (OSError, ValueError):
        return CheckResult(control_id, title, CheckStatus.ERROR, _ERROR_SUMMARY)

    if not stat.S_ISREG(metadata.st_mode):
        return CheckResult(control_id, title, CheckStatus.FAIL, _FAIL_SUMMARY)

    mode = stat.S_IMODE(metadata.st_mode)
    if mode & ~maximum_mode:
        return CheckResult(control_id, title, CheckStatus.FAIL, _FAIL_SUMMARY)

    if metadata.st_uid != 0:
        return CheckResult(control_id, title, CheckStatus.FAIL, _FAIL_SUMMARY)
    owner_name = _user_name(metadata.st_uid)
    if owner_name is None:
        return CheckResult(control_id, title, CheckStatus.ERROR, _ERROR_SUMMARY)
    if owner_name != "root":
        return CheckResult(control_id, title, CheckStatus.FAIL, _FAIL_SUMMARY)

    if allowed_group_ids is not None and metadata.st_gid not in allowed_group_ids:
        return CheckResult(control_id, title, CheckStatus.FAIL, _FAIL_SUMMARY)

    group_name = _group_name(metadata.st_gid)
    if group_name is None:
        return CheckResult(control_id, title, CheckStatus.ERROR, _ERROR_SUMMARY)
    if group_name not in allowed_group_names:
        return CheckResult(control_id, title, CheckStatus.FAIL, _FAIL_SUMMARY)

    return CheckResult(control_id, title, CheckStatus.PASS, _PASS_SUMMARY)


def check_passwd() -> CheckResult:
    """Check root ownership and maximum mode 0644 for /etc/passwd."""
    return _check_file(
        control_id="7.1.1",
        title="Access to /etc/passwd",
        path="/etc/passwd",
        maximum_mode=0o644,
        allowed_group_ids=frozenset({0}),
        allowed_group_names=frozenset({"root"}),
    )


def check_group() -> CheckResult:
    """Check root ownership and maximum mode 0644 for /etc/group."""
    return _check_file(
        control_id="7.1.3",
        title="Access to /etc/group",
        path="/etc/group",
        maximum_mode=0o644,
        allowed_group_ids=frozenset({0}),
        allowed_group_names=frozenset({"root"}),
    )


def check_shadow() -> CheckResult:
    """Check root ownership and maximum mode 0640 for /etc/shadow."""
    return _check_file(
        control_id="7.1.5",
        title="Access to /etc/shadow",
        path="/etc/shadow",
        maximum_mode=0o640,
        allowed_group_ids=None,
        allowed_group_names=frozenset({"root", "shadow"}),
    )


def run_permission_checks() -> list[CheckResult]:
    """Run and return the three file-permission checks in control order."""
    return [check_passwd(), check_group(), check_shadow()]