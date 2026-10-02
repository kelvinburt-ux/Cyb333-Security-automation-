"""Isolated tests for password quality and password-aging checks."""

from collections.abc import Callable, Sequence

import pytest

from secure_config_check.checks import passwords
from secure_config_check.models import CheckResult, CheckStatus


def _shadow_entry(
    username: str,
    password_field: str,
    maximum_age: str,
    warning_age: str,
) -> str:
    """Build a shadow-format test row with the requested aging values."""
    return (
        f"{username}:{password_field}:20000:0:{maximum_age}:{warning_age}:7::"
    )


def _reader(
    contents: dict[str, str],
    *,
    denied_paths: Sequence[str] = (),
    calls: list[str] | None = None,
) -> Callable[[str], str]:
    """Create an injectable reader with optional access failures and call tracking."""
    def read_text(path: str) -> str:
        if calls is not None:
            calls.append(path)
        if path in denied_paths:
            raise PermissionError("private file access detail")
        if path not in contents:
            raise FileNotFoundError("private missing-file detail")
        return contents[path]

    return read_text


def _base_files(
    *,
    pam: str = "",
    quality: str = "",
    login_defs: str = "PASS_MAX_DAYS 365\nPASS_WARN_AGE 7\n",
    shadow: str | None = None,
) -> dict[str, str]:
    """Return a test-only set of policy files with one compliant account."""
    if shadow is None:
        shadow = _shadow_entry("private-user", "$6$private-hash", "365", "7")
    return {
        passwords._PAM_PASSWORD_FILE: pam,
        passwords._PWQUALITY_FILE: quality,
        passwords._LOGIN_DEFS_FILE: login_defs,
        passwords._SHADOW_FILE: shadow,
    }


def _by_id(results: list[CheckResult]) -> dict[str, CheckResult]:
    """Index results by control ID for readable assertions."""
    return {result.control_id: result for result in results}


def test_all_secure_password_settings_pass() -> None:
    """Pass all three checks when effective settings and account values comply."""
    files = _base_files(pam="password requisite pam_pwquality.so minlen=14\n")

    results = passwords.run_password_checks(
        _reader(files), lambda directory: []
    )

    assert [result.control_id for result in results] == [
        "5.3.3.2.2",
        "5.4.1.1",
        "5.4.1.3",
    ]
    assert all(result.status is CheckStatus.PASS for result in results)


@pytest.mark.parametrize(
    ("minlen", "expected"),
    [(13, CheckStatus.FAIL), (14, CheckStatus.PASS), (20, CheckStatus.PASS)],
)
def test_minimum_password_length_boundary(minlen: int, expected: CheckStatus) -> None:
    """Apply the minimum password-length boundary to the effective PAM value."""
    files = _base_files(pam=f"password requisite pam_pwquality.so minlen={minlen}\n")

    result = passwords.check_minimum_password_length(
        _reader(files), lambda directory: []
    )

    assert result.status is expected


def test_pam_minlen_overrides_main_file_and_dropins() -> None:
    """Use a PAM argument before lower-precedence configuration values."""
    files = _base_files(
        pam="password requisite pam_pwquality.so minlen=14\n",
        quality="minlen = 8\n",
    )
    files["/dropins/99-late.conf"] = "minlen = 9\n"
    calls: list[str] = []

    result = passwords.check_minimum_password_length(
        _reader(files, calls=calls), lambda directory: ["/dropins/99-late.conf"]
    )

    assert result.status is CheckStatus.PASS
    assert calls == [passwords._PAM_PASSWORD_FILE]


def test_main_pwquality_file_overrides_dropins() -> None:
    """Use pwquality.conf when it defines minlen, regardless of drop-ins."""
    files = _base_files(quality="minlen = 14\n")
    files["/dropins/10-early.conf"] = "minlen = 8\n"
    calls: list[str] = []

    result = passwords.check_minimum_password_length(
        _reader(files, calls=calls),
        lambda directory: ["/dropins/10-early.conf"],
    )

    assert result.status is CheckStatus.PASS
    assert calls == [passwords._PAM_PASSWORD_FILE, passwords._PWQUALITY_FILE]


def test_last_canonical_dropin_value_takes_precedence() -> None:
    """Sort drop-ins by filename and use the final applicable minlen value."""
    files = _base_files()
    files["/dropins/10-first.conf"] = "minlen = 14\n"
    files["/dropins/20-last.conf"] = "minlen = 12\n"
    calls: list[str] = []

    result = passwords.check_minimum_password_length(
        _reader(files, calls=calls),
        lambda directory: ["/dropins/20-last.conf", "/dropins/10-first.conf"],
    )

    assert result.status is CheckStatus.FAIL
    assert calls[-2:] == ["/dropins/10-first.conf", "/dropins/20-last.conf"]


@pytest.mark.parametrize(
    "quality",
    ["", "retry = 3\n", "minlen = fourteen\n", "minlen =\n"],
)
def test_missing_or_malformed_minlen_returns_error(quality: str) -> None:
    """Return ERROR when no effective minlen exists or its value is malformed."""
    files = _base_files(quality=quality)

    result = passwords.check_minimum_password_length(
        _reader(files), lambda directory: []
    )

    assert result.status is CheckStatus.ERROR


def test_conflicting_pam_minlen_arguments_return_error() -> None:
    """Reject conflicting minlen arguments in the effective PAM configuration."""
    files = _base_files(
        pam="password requisite pam_pwquality.so minlen=14 minlen=12\n",
        quality="minlen = 16\n",
    )

    result = passwords.check_minimum_password_length(
        _reader(files), lambda directory: []
    )

    assert result.status is CheckStatus.ERROR


@pytest.mark.parametrize(
    ("default_age", "account_age", "expected"),
    [
        ("1", "1", CheckStatus.PASS),
        ("365", "365", CheckStatus.PASS),
        ("0", "365", CheckStatus.FAIL),
        ("366", "365", CheckStatus.FAIL),
        ("365", "0", CheckStatus.FAIL),
        ("365", "366", CheckStatus.FAIL),
    ],
)
def test_password_expiration_boundaries(
    default_age: str, account_age: str, expected: CheckStatus
) -> None:
    """Require defaults and applicable account maximum ages from 1 through 365."""
    files = _base_files(
        login_defs=f"PASS_MAX_DAYS {default_age}\nPASS_WARN_AGE 7\n",
        shadow=_shadow_entry("private-user", "$6$private-hash", account_age, "7"),
    )

    result = passwords.check_password_expiration(_reader(files))

    assert result.status is expected


@pytest.mark.parametrize(
    ("default_warning", "account_warning", "expected"),
    [
        ("7", "7", CheckStatus.PASS),
        ("10", "9", CheckStatus.PASS),
        ("6", "7", CheckStatus.FAIL),
        ("7", "6", CheckStatus.FAIL),
    ],
)
def test_password_warning_boundaries(
    default_warning: str, account_warning: str, expected: CheckStatus
) -> None:
    """Require both default and applicable account warning values to be at least 7."""
    files = _base_files(
        login_defs=f"PASS_MAX_DAYS 365\nPASS_WARN_AGE {default_warning}\n",
        shadow=_shadow_entry("private-user", "$6$private-hash", "365", account_warning),
    )

    result = passwords.check_password_expiration_warning(_reader(files))

    assert result.status is expected


@pytest.mark.parametrize(
    ("control", "login_defs", "shadow"),
    [
        ("maximum", "PASS_WARN_AGE 7\n", _shadow_entry("u", "hash", "365", "7")),
        ("maximum", "PASS_MAX_DAYS many\n", _shadow_entry("u", "hash", "365", "7")),
        ("maximum", "PASS_MAX_DAYS 365\n", "malformed-shadow-row"),
        ("maximum", "PASS_MAX_DAYS 365\n", _shadow_entry("u", "hash", "many", "7")),
        ("warning", "PASS_MAX_DAYS 365\n", _shadow_entry("u", "hash", "365", "many")),
        ("warning", "PASS_MAX_DAYS 365\nPASS_WARN_AGE many\n", _shadow_entry("u", "hash", "365", "7")),
    ],
)
def test_missing_or_malformed_aging_data_returns_error(
    control: str, login_defs: str, shadow: str
) -> None:
    """Return ERROR when the required default or applicable account value is invalid."""
    files = _base_files(login_defs=login_defs, shadow=shadow)

    result = (
        passwords.check_password_expiration(_reader(files))
        if control == "maximum"
        else passwords.check_password_expiration_warning(_reader(files))
    )

    assert result.status is CheckStatus.ERROR


@pytest.mark.parametrize(
    "denied_path",
    [
        passwords._PAM_PASSWORD_FILE,
        passwords._LOGIN_DEFS_FILE,
        passwords._SHADOW_FILE,
    ],
)
def test_permission_denied_files_return_error(denied_path: str) -> None:
    """Handle inaccessible policy files without revealing underlying details."""
    files = _base_files(pam="password requisite pam_pwquality.so minlen=14\n")
    reader = _reader(files, denied_paths=[denied_path])

    if denied_path == passwords._PAM_PASSWORD_FILE:
        result = passwords.check_minimum_password_length(reader, lambda directory: [])
    else:
        result = passwords.check_password_expiration(reader)

    assert result.status is CheckStatus.ERROR
    assert "private file access detail" not in result.summary


def test_expiration_summaries_include_only_sanitized_counts() -> None:
    """Report aggregate account counts without exposing names or password fields."""
    first_name = "distinct-private-user"
    first_hash = "$6$distinct-private-hash"
    shadow = "\n".join(
        [
            _shadow_entry(first_name, first_hash, "365", "7"),
            _shadow_entry("locked-private-user", "!locked-private-hash", "1", "1"),
            _shadow_entry("second-private-user", "$6$second-private-hash", "400", "7"),
        ]
    )
    files = _base_files(shadow=shadow)

    result = passwords.check_password_expiration(_reader(files))

    assert result.status is CheckStatus.FAIL
    assert "2 applicable accounts checked" in result.summary
    assert "1 noncompliant" in result.summary
    for sensitive_value in (
        first_name,
        first_hash,
        "locked-private-user",
        "locked-private-hash",
        "second-private-user",
        "second-private-hash",
    ):
        assert sensitive_value not in result.summary