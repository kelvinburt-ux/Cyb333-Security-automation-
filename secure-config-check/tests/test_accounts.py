"""Isolated tests for local account configuration checks."""

from collections.abc import Callable

import pytest

from secure_config_check.checks import accounts
from secure_config_check.models import CheckResult, CheckStatus


def _passwd_entry(
    username: str,
    password_field: str,
    uid: str,
    gid: str = "1000",
) -> str:
    """Create one synthetic seven-field passwd record."""
    return f"{username}:{password_field}:{uid}:{gid}:Private:/home/private:/bin/false"


def _shadow_entry(username: str, password_field: str) -> str:
    """Create one synthetic nine-field shadow record."""
    return f"{username}:{password_field}:20000:0:365:7:14::"


def _reader(
    contents: dict[str, str],
    *,
    errors: dict[str, Exception] | None = None,
    calls: list[str] | None = None,
) -> Callable[[str], str]:
    """Create an injectable reader with optional failures and call tracking."""
    read_errors = errors or {}

    def read_text(path: str) -> str:
        if calls is not None:
            calls.append(path)
        if path in read_errors:
            raise read_errors[path]
        if path not in contents:
            raise FileNotFoundError("synthetic missing file")
        return contents[path]

    return read_text


def _files(
    *,
    passwd: str | None = None,
    shadow: str | None = None,
) -> dict[str, str]:
    """Return valid synthetic passwd and shadow content by default."""
    if passwd is None:
        passwd = "\n".join(
            [
                _passwd_entry("root", "x", "0", "0"),
                _passwd_entry("synthetic-user", "x", "1000"),
            ]
        )
    if shadow is None:
        shadow = "\n".join(
            [
                _shadow_entry("root", "$6$synthetic-root-hash"),
                _shadow_entry("synthetic-user", "!synthetic-locked-marker"),
            ]
        )
    return {accounts._PASSWD_FILE: passwd, accounts._SHADOW_FILE: shadow}


def _by_id(results: list[CheckResult]) -> dict[str, CheckResult]:
    """Index results by control ID for readable assertions."""
    return {result.control_id: result for result in results}


def test_secure_account_records_pass() -> None:
    """Pass all checks for valid account records that meet the requirements."""
    results = accounts.run_account_checks(_reader(_files()))

    assert [result.control_id for result in results] == [
        "5.4.2.1",
        "7.2.1",
        "7.2.2",
    ]
    assert all(result.status is CheckStatus.PASS for result in results)


@pytest.mark.parametrize(
    ("passwd", "expected"),
    [
        (
            "\n".join(
                [
                    _passwd_entry("root", "x", "0", "0"),
                    _passwd_entry("other", "x", "1000"),
                ]
            ),
            CheckStatus.PASS,
        ),
        (
            "\n".join(
                [
                    _passwd_entry("root", "x", "0", "0"),
                    _passwd_entry("uid-zero-private", "x", "0"),
                ]
            ),
            CheckStatus.FAIL,
        ),
        (
            "\n".join(
                [
                    _passwd_entry("root", "x", "1000", "0"),
                    _passwd_entry("other", "x", "1001"),
                ]
            ),
            CheckStatus.FAIL,
        ),
    ],
)
def test_root_uid_control_boundaries(passwd: str, expected: CheckStatus) -> None:
    """Require root UID 0 and reject any other UID 0 account."""
    result = accounts.check_root_uid(_reader(_files(passwd=passwd)))

    assert result.status is expected


def test_missing_root_record_returns_error() -> None:
    """Treat absent root account data as unevaluable rather than compliant."""
    passwd = _passwd_entry("ordinary", "x", "1000")

    result = accounts.check_root_uid(_reader(_files(passwd=passwd)))

    assert result.status is CheckStatus.ERROR


@pytest.mark.parametrize(
    ("password_field", "expected"),
    [
        ("x", CheckStatus.PASS),
        ("", CheckStatus.FAIL),
        ("!locked", CheckStatus.FAIL),
        ("$6$synthetic-hash", CheckStatus.FAIL),
    ],
)
def test_passwd_password_field_values(
    password_field: str, expected: CheckStatus
) -> None:
    """Require exactly x in every passwd password field."""
    passwd = "\n".join(
        [
            _passwd_entry("root", "x", "0", "0"),
            _passwd_entry("synthetic-user", password_field, "1000"),
        ]
    )

    result = accounts.check_shadowed_passwords(_reader(_files(passwd=passwd)))

    assert result.status is expected
    if expected is CheckStatus.FAIL:
        assert "Accounts: 2; compliant: 1; noncompliant: 1." == result.summary


@pytest.mark.parametrize(
    ("password_field", "expected"),
    [
        ("$6$synthetic-hash", CheckStatus.PASS),
        ("!synthetic-locked-marker", CheckStatus.PASS),
        ("", CheckStatus.FAIL),
    ],
)
def test_shadow_empty_password_field_boundary(
    password_field: str, expected: CheckStatus
) -> None:
    """Fail only when a valid shadow entry has an empty password field."""
    shadow = "\n".join(
        [
            _shadow_entry("root", "$6$synthetic-root-hash"),
            _shadow_entry("synthetic-user", password_field),
        ]
    )

    result = accounts.check_nonempty_shadow_passwords(_reader(_files(shadow=shadow)))

    assert result.status is expected
    if expected is CheckStatus.FAIL:
        assert result.summary == "Shadow accounts: 2; empty password fields: 1."


@pytest.mark.parametrize(
    ("passwd", "shadow"),
    [
        ("root:x:0:0:comment:/root", _shadow_entry("root", "hash")),
        (_passwd_entry("root", "x", "invalid", "0"), _shadow_entry("root", "hash")),
        (_passwd_entry("root", "x", "0", "0"), "root:hash:1:0:365:7"),
        (_passwd_entry("root", "x", "0", "0"), ":hash:1:0:365:7:14::"),
    ],
)
def test_malformed_records_return_errors(passwd: str, shadow: str) -> None:
    """Return ERROR for malformed colon-delimited records or numeric IDs."""
    results = _by_id(accounts.run_account_checks(_reader(_files(passwd=passwd, shadow=shadow))))

    if passwd != _passwd_entry("root", "x", "0", "0"):
        assert results["5.4.2.1"].status is CheckStatus.ERROR
        assert results["7.2.1"].status is CheckStatus.ERROR
    else:
        assert results["7.2.2"].status is CheckStatus.ERROR


@pytest.mark.parametrize("path", [accounts._PASSWD_FILE, accounts._SHADOW_FILE])
def test_missing_files_return_error(path: str) -> None:
    """Return ERROR if either required account database is missing."""
    files = _files()
    del files[path]

    results = _by_id(accounts.run_account_checks(_reader(files)))

    if path == accounts._PASSWD_FILE:
        assert results["5.4.2.1"].status is CheckStatus.ERROR
        assert results["7.2.1"].status is CheckStatus.ERROR
    else:
        assert results["7.2.2"].status is CheckStatus.ERROR


@pytest.mark.parametrize("path", [accounts._PASSWD_FILE, accounts._SHADOW_FILE])
def test_permission_denied_files_return_error(path: str) -> None:
    """Return ERROR for inaccessible files without exposing the OS error."""
    reader = _reader(
        _files(), errors={path: PermissionError("synthetic private access detail")}
    )

    results = _by_id(accounts.run_account_checks(reader))

    affected_ids = (
        ("5.4.2.1", "7.2.1")
        if path == accounts._PASSWD_FILE
        else ("7.2.2",)
    )
    for control_id in affected_ids:
        assert results[control_id].status is CheckStatus.ERROR
        assert "synthetic private access detail" not in results[control_id].summary


def test_result_summaries_never_include_synthetic_names_or_passwords() -> None:
    """Keep synthetic account names, hashes, and lock markers out of summaries."""
    passwd = "\n".join(
        [
            _passwd_entry("synthetic-root-name", "x", "0", "0"),
            _passwd_entry("synthetic-user-name", "$6$synthetic-passwd-hash", "0"),
        ]
    )
    shadow = "\n".join(
        [
            _shadow_entry("synthetic-shadow-user", "$6$synthetic-shadow-hash"),
            _shadow_entry("synthetic-locked-user", "!synthetic-lock-marker"),
            _shadow_entry("synthetic-empty-user", ""),
        ]
    )

    results = accounts.run_account_checks(_reader(_files(passwd=passwd, shadow=shadow)))
    sensitive_values = (
        "synthetic-root-name",
        "synthetic-user-name",
        "$6$synthetic-passwd-hash",
        "synthetic-shadow-user",
        "$6$synthetic-shadow-hash",
        "synthetic-locked-user",
        "!synthetic-lock-marker",
        "synthetic-empty-user",
    )

    for result in results:
        for sensitive_value in sensitive_values:
            assert sensitive_value not in result.summary


def test_runner_reads_each_file_only_once() -> None:
    """Read each account database once when producing the complete category."""
    calls: list[str] = []

    accounts.run_account_checks(_reader(_files(), calls=calls))

    assert calls == [accounts._PASSWD_FILE, accounts._SHADOW_FILE]