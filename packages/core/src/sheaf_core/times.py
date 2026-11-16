"""Times as the standard writes them: RFC 3339 in UTC, with Z (sections 4 and 5.1)."""

import re
from datetime import UTC, date, datetime, timedelta

_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z")
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")


def parse_timestamp(value: str) -> datetime:
    """Parse a UTC timestamp written with Z. Digits past microseconds are dropped."""
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        raise ValueError(f"{value!r} is not an RFC 3339 UTC timestamp written with Z")
    return datetime.fromisoformat(value)


def parse_date(value: str) -> date:
    if not isinstance(value, str) or not _DATE.fullmatch(value):
        raise ValueError(f"{value!r} is not an RFC 3339 full-date")
    return date.fromisoformat(value)


def format_timestamp(moment: datetime) -> str:
    """Write an aware datetime as UTC with milliseconds, the precision of `committed_at`."""
    utc = require_aware(moment).astimezone(UTC)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"


def require_aware(moment: datetime) -> datetime:
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError(f"{moment!r} is not timezone-aware")
    return moment


_PERIOD = re.compile(r"P(?=[0-9])(?:([0-9]+)Y)?(?:([0-9]+)M)?(?:([0-9]+)D)?")


def add_period(day: date, period: str) -> date:
    """`day` plus an ISO 8601 period of whole years, months and days, as the mandate's retention
    classes give them. A day past the end of the month comes back as its last day."""
    match = _PERIOD.fullmatch(period)
    if match is None:
        raise ValueError(f"{period!r} is not a period of years, months and days")
    years, months, days = (int(part or 0) for part in match.groups())
    month = day.month - 1 + months
    year, month = day.year + years + month // 12, month % 12 + 1
    following = date(year + month // 12, month % 12 + 1, 1)
    last = (following - timedelta(days=1)).day
    return date(year, month, min(day.day, last)) + timedelta(days=days)
