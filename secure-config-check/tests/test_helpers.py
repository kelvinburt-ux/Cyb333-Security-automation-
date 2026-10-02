"""Tests for safe configuration-file and command helpers."""

from pathlib import Path
import subprocess

import pytest

from secure_config_check.helpers import (
    CommandTimeoutError,
    CommandUnavailableError,
    MissingInputError,
    UnreadableInputError,
    read_text_file,
    run_command,
)


def test_read_text_file_reads_utf8(tmp_path: Path) -> None:
    """Read an ordinary UTF-8 file without changing its contents."""
    config_file = tmp_path / "sample.conf"
    config_file.write_text("setting = enabled\n", encoding="utf-8")

    assert read_text_file(config_file) == "setting = enabled\n"


def test_read_text_file_reports_missing_file_without_path(tmp_path: Path) -> None:
    """Report a missing file without disclosing its path."""
    missing_file = tmp_path / "missing.conf"

    with pytest.raises(MissingInputError) as error:
        read_text_file(missing_file)

    assert str(missing_file) not in str(error.value)


def test_read_text_file_reports_permission_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Convert a file permission problem into a generic safe error."""
    config_file = tmp_path / "restricted.conf"
    config_file.touch()

    def deny_read(path: Path, *, encoding: str) -> str:
        raise PermissionError("private operating-system detail")

    monkeypatch.setattr(Path, "read_text", deny_read)

    with pytest.raises(UnreadableInputError) as error:
        read_text_file(config_file)

    assert "private operating-system detail" not in str(error.value)


def test_read_text_file_reports_invalid_utf8(tmp_path: Path) -> None:
    """Convert invalid UTF-8 bytes into a generic safe error."""
    config_file = tmp_path / "invalid.conf"
    config_file.write_bytes(b"setting = \xff\n")

    with pytest.raises(UnreadableInputError):
        read_text_file(config_file)


def test_run_command_uses_arguments_and_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Run commands as argument lists with shell use disabled."""
    observed: dict[str, object] = {}

    def fake_run(
        arguments: list[str], **options: object
    ) -> subprocess.CompletedProcess[str]:
        observed["arguments"] = arguments
        observed.update(options)
        return subprocess.CompletedProcess(arguments, 0, stdout="enabled\n")

    monkeypatch.setattr("secure_config_check.helpers.subprocess.run", fake_run)

    result = run_command(["safe-tool", "--show-setting"], timeout_seconds=2.0)

    assert result.stdout == "enabled\n"
    assert observed["arguments"] == ["safe-tool", "--show-setting"]
    assert observed["timeout"] == 2.0
    assert observed["shell"] is False
    assert observed["check"] is False


def test_run_command_handles_missing_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Handle an unavailable command without exposing its name."""
    def missing_command(*args: object, **kwargs: object) -> None:
        raise FileNotFoundError("private command path")

    monkeypatch.setattr("secure_config_check.helpers.subprocess.run", missing_command)

    with pytest.raises(CommandUnavailableError) as error:
        run_command(["private-command"])

    assert "private command path" not in str(error.value)


def test_run_command_handles_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """Convert a command timeout into a generic timeout error."""
    def timed_out(*args: object, **kwargs: object) -> None:
        raise subprocess.TimeoutExpired("private-command", timeout=5.0)

    monkeypatch.setattr("secure_config_check.helpers.subprocess.run", timed_out)

    with pytest.raises(CommandTimeoutError) as error:
        run_command(["private-command"])

    assert "private-command" not in str(error.value)