"""Data models shared by the Secure Config Check audit modules."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import json


class CheckStatus(str, Enum):
    """The possible outcomes for one configuration check."""

    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass(frozen=True)
class CheckResult:
    """Store a check's identifier, short title, outcome, and safe summary."""

    control_id: str
    title: str
    status: CheckStatus
    summary: str

    def __post_init__(self) -> None:
        """Reject missing labels and statuses outside the supported set."""
        if not self.control_id.strip():
            raise ValueError("control_id must not be empty")
        if not self.title.strip():
            raise ValueError("title must not be empty")
        if not self.summary.strip():
            raise ValueError("summary must not be empty")
        if not isinstance(self.status, CheckStatus):
            raise ValueError("status must be a CheckStatus value")

    def to_dict(self) -> dict[str, str]:
        """Convert this result to JSON-safe fields without raw system data."""
        return {
            "control_id": self.control_id,
            "title": self.title,
            "status": self.status.value,
            "summary": self.summary,
        }


@dataclass
class AuditReport:
    """Store and serialize the results from one complete 15-control audit."""

    results: list[CheckResult]
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def __post_init__(self) -> None:
        """Require exactly 15 results with no repeated control identifiers."""
        if len(self.results) != 15:
            raise ValueError("an audit report must contain exactly 15 results")
        control_ids = [result.control_id for result in self.results]
        if len(set(control_ids)) != len(control_ids):
            raise ValueError("control identifiers must be unique")

    def to_dict(self) -> dict[str, str | list[dict[str, str]]]:
        """Convert the report to a JSON-safe dictionary."""
        return {
            "generated_at": self.generated_at,
            "results": [result.to_dict() for result in self.results],
        }

    def to_json(self, *, indent: int = 2) -> str:
        """Return the report as formatted JSON text."""
        return json.dumps(self.to_dict(), indent=indent)