"""Read-only password-quality and password-aging configuration checks."""

from collections.abc import Callable, Sequence
from pathlib import Path
import re

from secure_config_check.helpers import CheckInputError, read_text_file
from secure_config_check.models import CheckResult, CheckStatus


_PAM_PASSWORD_FILE = "/etc/pam.d/common-password"
_PWQUALITY_FILE = "/etc/security/pwquality.conf"
_PWQUALITY_DROPIN_DIRECTORY = "/etc/security/pwquality.conf.d"
_LOGIN_DEFS_FILE = "/etc/login.defs"
_SHADOW_FILE = "/etc/shadow"
_INTEGER_PATTERN = re.compile(r"[+-]?\d+")
_ERROR_SUMMARY = "Password policy could not be safely evaluated."
_TextReader = Callable[[str], str]
_FileLister = Callable[[str], Sequence[str]]


def _list_dropin_files(directory: str) -> list[str]:
    """List pwquality .conf files in canonical filename order."""
    try:
        paths = [
            path
            for path in Path(directory).iterdir()
            if path.suffix == ".conf" and path.is_file()
        ]
    except FileNotFoundError:
        return []
    return [str(path) for path in sorted(paths, key=lambda item: item.name)]


def _integer_value(value: str | None) -> int:
    """Parse a signed decimal integer or reject malformed policy data."""
    if value is None or _INTEGER_PATTERN.fullmatch(value) is None:
        raise ValueError("policy value is not an integer")
    return int(value)


def _pam_minlen(contents: str) -> tuple[bool, str | None]:
    """Find PAM minlen arguments and reject malformed or conflicting values."""
    values: list[str] = []
    malformed = False

    for line in contents.splitlines():
        fields = line.split("#", 1)[0].split()
        module_index = next(
            (
                index
                for index, field in enumerate(fields)
                if field.endswith("pam_pwquality.so")
            ),
            None,
        )
        if module_index is None:
            continue

        for argument in fields[module_index + 1 :]:
            key, separator, value = argument.partition("=")
            if key.lower() != "minlen":
                continue
            if not separator or not value:
                malformed = True
            else:
                values.append(value)

    if malformed or len(set(values)) > 1:
        raise ValueError("PAM minlen is malformed or conflicting")
    return bool(values), values[0] if values else None


def _last_config_minlen(contents: str) -> tuple[bool, str | None]:
    """Return the final minlen assignment in one pwquality configuration file."""
    found = False
    value: str | None = None

    for line in contents.splitlines():
        setting = line.split("#", 1)[0].strip()
        if not setting:
            continue

        if "=" in setting:
            key, raw_value = setting.split("=", 1)
            if key.strip().lower() != "minlen":
                continue
            fields = raw_value.split()
        else:
            fields = setting.split()
            if fields[0].lower() != "minlen":
                continue
            fields = fields[1:]

        found = True
        value = fields[0] if len(fields) == 1 else None

    return found, value


def _effective_minlen(read_text: _TextReader, list_files: _FileLister) -> int:
    """Resolve minlen according to PAM, main-file, and ordered drop-in precedence."""
    pam_contents = read_text(_PAM_PASSWORD_FILE)
    has_pam_value, pam_value = _pam_minlen(pam_contents)
    if has_pam_value:
        return _integer_value(pam_value)

    main_contents = read_text(_PWQUALITY_FILE)
    has_main_value, main_value = _last_config_minlen(main_contents)
    if has_main_value:
        return _integer_value(main_value)

    effective_value: str | None = None
    has_dropin_value = False
    dropin_files = sorted(list_files(_PWQUALITY_DROPIN_DIRECTORY), key=lambda item: Path(item).name)
    for path in dropin_files:
        contents = read_text(path)
        found, value = _last_config_minlen(contents)
        if found:
            effective_value = value
            has_dropin_value = True

    if not has_dropin_value:
        raise ValueError("effective minlen is missing")
    return _integer_value(effective_value)


def check_minimum_password_length(
    read_text: _TextReader = read_text_file,
    list_files: _FileLister = _list_dropin_files,
) -> CheckResult:
    """Check that effective minlen is at least 14 without changing configuration."""
    try:
        minlen = _effective_minlen(read_text, list_files)
    except (CheckInputError, OSError, UnicodeError, ValueError):
        return CheckResult(
            "5.3.3.2.2",
            "Minimum password length",
            CheckStatus.ERROR,
            _ERROR_SUMMARY,
        )

    status = CheckStatus.PASS if minlen >= 14 else CheckStatus.FAIL
    summary = (
        "Effective password length meets the requirement."
        if status is CheckStatus.PASS
        else "Effective password length is below the requirement."
    )
    return CheckResult("5.3.3.2.2", "Minimum password length", status, summary)


def _last_login_setting(contents: str, name: str) -> int:
    """Parse the final numeric assignment for one login.defs setting."""
    value: str | None = None
    found = False

    for line in contents.splitlines():
        fields = line.split("#", 1)[0].split()
        if not fields or fields[0].upper() != name:
            continue
        found = True
        value = fields[1] if len(fields) == 2 else None

    if not found:
        raise ValueError("required login.defs setting is missing")
    return _integer_value(value)


def _account_aging_counts(
    contents: str, field_index: int, is_compliant: Callable[[int], bool]
) -> tuple[int, int]:
    """Count applicable password accounts and noncompliant aging values only."""
    entries_seen = 0
    applicable_count = 0
    noncompliant_count = 0

    for line in contents.splitlines():
        if not line:
            continue
        entries_seen += 1
        fields = line.split(":")
        if len(fields) < 7:
            raise ValueError("shadow entry cannot be evaluated safely")

        password_field = fields[1]
        if not password_field or password_field.startswith(("!", "*")):
            continue

        value = _integer_value(fields[field_index])
        applicable_count += 1
        if not is_compliant(value):
            noncompliant_count += 1

    if entries_seen == 0:
        raise ValueError("shadow data is empty")
    return applicable_count, noncompliant_count


def _aging_result(
    *,
    control_id: str,
    title: str,
    default_name: str,
    field_index: int,
    is_compliant: Callable[[int], bool],
    login_defs: str,
    shadow: str,
) -> CheckResult:
    """Evaluate the default and all applicable account aging values."""
    try:
        default_value = _last_login_setting(login_defs, default_name)
        applicable_count, noncompliant_count = _account_aging_counts(
            shadow, field_index, is_compliant
        )
    except ValueError:
        return CheckResult(control_id, title, CheckStatus.ERROR, _ERROR_SUMMARY)

    default_compliant = is_compliant(default_value)
    status = (
        CheckStatus.PASS
        if default_compliant and noncompliant_count == 0
        else CheckStatus.FAIL
    )
    summary = (
        f"Default meets the requirement; {applicable_count} applicable accounts "
        f"checked; {noncompliant_count} noncompliant."
        if status is CheckStatus.PASS
        else f"Default or account values are noncompliant; {applicable_count} "
        f"applicable accounts checked; {noncompliant_count} noncompliant."
    )
    return CheckResult(control_id, title, status, summary)


def _load_aging_files(read_text: _TextReader) -> tuple[str, str]:
    """Read login defaults and shadow data without retaining account identifiers."""
    return read_text(_LOGIN_DEFS_FILE), read_text(_SHADOW_FILE)


def _aging_error_results() -> tuple[CheckResult, CheckResult]:
    """Create generic errors for both password-aging checks."""
    return (
        CheckResult(
            "5.4.1.1",
            "Password expiration",
            CheckStatus.ERROR,
            _ERROR_SUMMARY,
        ),
        CheckResult(
            "5.4.1.3",
            "Password expiration warning",
            CheckStatus.ERROR,
            _ERROR_SUMMARY,
        ),
    )


def check_password_expiration(read_text: _TextReader = read_text_file) -> CheckResult:
    """Check default and account maximum password ages are from 1 through 365."""
    try:
        login_defs, shadow = _load_aging_files(read_text)
    except (CheckInputError, OSError, UnicodeError):
        return _aging_error_results()[0]
    return _aging_result(
        control_id="5.4.1.1",
        title="Password expiration",
        default_name="PASS_MAX_DAYS",
        field_index=4,
        is_compliant=lambda value: 1 <= value <= 365,
        login_defs=login_defs,
        shadow=shadow,
    )


def check_password_expiration_warning(
    read_text: _TextReader = read_text_file,
) -> CheckResult:
    """Check default and account password expiration warnings are at least 7."""
    try:
        login_defs, shadow = _load_aging_files(read_text)
    except (CheckInputError, OSError, UnicodeError):
        return _aging_error_results()[1]
    return _aging_result(
        control_id="5.4.1.3",
        title="Password expiration warning",
        default_name="PASS_WARN_AGE",
        field_index=5,
        is_compliant=lambda value: value >= 7,
        login_defs=login_defs,
        shadow=shadow,
    )


def run_password_checks(
    read_text: _TextReader = read_text_file,
    list_files: _FileLister = _list_dropin_files,
) -> list[CheckResult]:
    """Run the three selected password-policy checks and return their results."""
    minimum_length = check_minimum_password_length(read_text, list_files)
    try:
        login_defs, shadow = _load_aging_files(read_text)
    except (CheckInputError, OSError, UnicodeError):
        expiration, warning = _aging_error_results()
        return [minimum_length, expiration, warning]

    expiration = _aging_result(
        control_id="5.4.1.1",
        title="Password expiration",
        default_name="PASS_MAX_DAYS",
        field_index=4,
        is_compliant=lambda value: 1 <= value <= 365,
        login_defs=login_defs,
        shadow=shadow,
    )
    warning = _aging_result(
        control_id="5.4.1.3",
        title="Password expiration warning",
        default_name="PASS_WARN_AGE",
        field_index=5,
        is_compliant=lambda value: value >= 7,
        login_defs=login_defs,
        shadow=shadow,
    )
    return [minimum_length, expiration, warning]