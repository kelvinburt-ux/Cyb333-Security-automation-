"""Read-only checks for local account identifiers and password fields."""

from collections.abc import Callable

from secure_config_check.helpers import CheckInputError, read_text_file
from secure_config_check.models import CheckResult, CheckStatus


_PASSWD_FILE = "/etc/passwd"
_SHADOW_FILE = "/etc/shadow"
_ERROR_SUMMARY = "Account data could not be safely evaluated."
_TextReader = Callable[[str], str]


def _numeric_id(value: str) -> int:
    """Parse an ASCII decimal account ID or reject malformed data."""
    if not value or not value.isascii() or not value.isdigit():
        raise ValueError("account ID is malformed")
    return int(value)


def _passwd_results(contents: str) -> tuple[CheckResult, CheckResult]:
    """Evaluate UID 0 uniqueness and password markers from validated passwd rows."""
    total_accounts = 0
    root_entries = 0
    root_uid: int | None = None
    root_uid_zero_count = 0
    other_uid_zero_count = 0
    compliant_password_count = 0

    for line in contents.splitlines():
        if not line.strip():
            continue

        fields = line.split(":")
        if len(fields) != 7 or not fields[0]:
            raise ValueError("passwd entry has an invalid field structure")

        uid = _numeric_id(fields[2])
        _numeric_id(fields[3])
        total_accounts += 1

        if fields[0] == "root":
            root_entries += 1
            root_uid = uid
            if uid == 0:
                root_uid_zero_count += 1
        elif uid == 0:
            other_uid_zero_count += 1

        if fields[1] == "x":
            compliant_password_count += 1

    if total_accounts == 0:
        raise ValueError("passwd data contains no account records")
    if root_entries == 0 or root_entries > 1:
        raise ValueError("root account data is missing or ambiguous")

    uid_zero_status = (
        CheckStatus.PASS
        if root_uid == 0 and root_uid_zero_count == 1 and other_uid_zero_count == 0
        else CheckStatus.FAIL
    )
    uid_zero_summary = (
        f"UID 0 accounts: {root_uid_zero_count + other_uid_zero_count}; "
        f"non-root UID 0 accounts: {other_uid_zero_count}."
    )
    uid_zero_result = CheckResult(
        "5.4.2.1", "Root is the only UID 0 account", uid_zero_status, uid_zero_summary
    )

    noncompliant_password_count = total_accounts - compliant_password_count
    password_status = (
        CheckStatus.PASS
        if noncompliant_password_count == 0
        else CheckStatus.FAIL
    )
    password_summary = (
        f"Accounts: {total_accounts}; compliant: {compliant_password_count}; "
        f"noncompliant: {noncompliant_password_count}."
    )
    password_result = CheckResult(
        "7.2.1",
        "Accounts use shadowed passwords",
        password_status,
        password_summary,
    )
    return uid_zero_result, password_result


def _shadow_empty_result(contents: str) -> CheckResult:
    """Count empty shadow password fields after validating each record."""
    total_accounts = 0
    empty_password_count = 0

    for line in contents.splitlines():
        if not line.strip():
            continue

        fields = line.split(":")
        if len(fields) != 9 or not fields[0]:
            raise ValueError("shadow entry has an invalid field structure")
        total_accounts += 1
        if fields[1] == "":
            empty_password_count += 1

    if total_accounts == 0:
        raise ValueError("shadow data contains no account records")

    status = CheckStatus.PASS if empty_password_count == 0 else CheckStatus.FAIL
    summary = (
        f"Shadow accounts: {total_accounts}; empty password fields: "
        f"{empty_password_count}."
    )
    return CheckResult(
        "7.2.2", "Shadow password fields are not empty", status, summary
    )


def _passwd_error_results() -> tuple[CheckResult, CheckResult]:
    """Return generic errors for checks that depend on passwd data."""
    return (
        CheckResult(
            "5.4.2.1",
            "Root is the only UID 0 account",
            CheckStatus.ERROR,
            _ERROR_SUMMARY,
        ),
        CheckResult(
            "7.2.1",
            "Accounts use shadowed passwords",
            CheckStatus.ERROR,
            _ERROR_SUMMARY,
        ),
    )


def check_root_uid(read_text: _TextReader = read_text_file) -> CheckResult:
    """Check that root is the only account with UID 0 and report counts only."""
    try:
        return _passwd_results(read_text(_PASSWD_FILE))[0]
    except (CheckInputError, OSError, UnicodeError, ValueError):
        return _passwd_error_results()[0]


def check_shadowed_passwords(read_text: _TextReader = read_text_file) -> CheckResult:
    """Check that every passwd account has exactly x in its password field."""
    try:
        return _passwd_results(read_text(_PASSWD_FILE))[1]
    except (CheckInputError, OSError, UnicodeError, ValueError):
        return _passwd_error_results()[1]


def check_nonempty_shadow_passwords(
    read_text: _TextReader = read_text_file,
) -> CheckResult:
    """Check that no shadow account has an empty password field."""
    try:
        return _shadow_empty_result(read_text(_SHADOW_FILE))
    except (CheckInputError, OSError, UnicodeError, ValueError):
        return CheckResult(
            "7.2.2",
            "Shadow password fields are not empty",
            CheckStatus.ERROR,
            _ERROR_SUMMARY,
        )


def run_account_checks(read_text: _TextReader = read_text_file) -> list[CheckResult]:
    """Run all three account checks while reading each source file once."""
    try:
        passwd_results = _passwd_results(read_text(_PASSWD_FILE))
    except (CheckInputError, OSError, UnicodeError, ValueError):
        passwd_results = _passwd_error_results()

    try:
        shadow_result = _shadow_empty_result(read_text(_SHADOW_FILE))
    except (CheckInputError, OSError, UnicodeError, ValueError):
        shadow_result = CheckResult(
            "7.2.2",
            "Shadow password fields are not empty",
            CheckStatus.ERROR,
            _ERROR_SUMMARY,
        )

    return [passwd_results[0], passwd_results[1], shadow_result]