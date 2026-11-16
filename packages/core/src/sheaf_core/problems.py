"""What a check reports: every problem it finds, rather than the first."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Problem:
    code: str
    path: str
    detail: str
