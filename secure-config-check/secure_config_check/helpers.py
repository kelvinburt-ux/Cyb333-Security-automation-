"""Safe, read-only helpers for configuration files and system commands."""

from collections.abc import Sequence
from pathlib import Path
import subprocess


class CheckInputError(Exception):
    """Base error for unavailable or unreadable check inputs."""


class MissingInputError(CheckInputError):
    """Raised when a required configuration file is missing."""


class UnreadableInputError(CheckInputError):
    """Raised when a configuration file cannot be read as UTF-8 text."""


class CommandError(Exception):
    """Base error for a command that could not be run successfully."""


class CommandUnavailableError(CommandError):
    """Raised when a required command is not installed or accessible."""


class CommandTimeoutError(CommandError):
    """Raised when a command exceeds its allowed run time."""


def read_text_file(path: str | Path) -> str:
    """Read a UTF-8 configuration file without exposing its path in errors."""
    try:
        return Path(path).read_text(encoding="utf-8")
    except FileNotFoundError as error:
        raise MissingInputError("required configuration file is missing") from error
    except (PermissionError, UnicodeDecodeError, OSError) as error:
        raise UnreadableInputError("configuration file cannot be read") from error


def run_command(
    arguments: Sequence[str], *, timeout_seconds: float = 5.0
) -> subprocess.CompletedProcess[str]:
    """Run a read-only command without a shell and with a strict timeout.

    Callers should inspect stdout only for the specific setting being checked.
    They must not include raw command output in console or JSON reports.
    """
    if not arguments or any(not isinstance(argument, str) for argument in arguments):
        raise ValueError("arguments must be a non-empty sequence of strings")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")

    try:
        return subprocess.run(
            list(arguments),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=timeout_seconds,
            check=False,
            shell=False,
        )
    except FileNotFoundError as error:
        raise CommandUnavailableError("required command is unavailable") from error
    except subprocess.TimeoutExpired as error:
        raise CommandTimeoutError("command exceeded its time limit") from error
    except UnicodeDecodeError as error:
        raise CommandError("command returned invalid text") from error
    except (PermissionError, OSError) as error:
        raise CommandError("command could not be run") from error