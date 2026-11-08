"""Times as the drafter stores them: UTC, ISO 8601, ending in Z."""

from __future__ import annotations

import datetime as dt
import re

UTC = dt.UTC

# Feeds give anything from whole seconds to nanoseconds, with Z, +00:00 or
# nothing at all (NVD, Ubuntu). Fractions past microseconds are cut.
_TIME = re.compile(
    r"^(\d{4}-\d{2}-\d{2})(?:[T ](\d{2}:\d{2}(?::\d{2})?)(?:\.(\d+))?)?(Z|[+-]\d{2}:?\d{2})?$"
)


class TimeError(ValueError):
    """A feed gave a time the drafter can't read."""


def parse(text: str) -> dt.datetime:
    """Read a feed's time. A time without a zone is taken as UTC."""
    if not isinstance(text, str):
        raise TimeError("time is not text")
    match = _TIME.match(text.strip())
    if not match:
        raise TimeError("unreadable time")
    date, clock, fraction, zone = match.groups()
    clock = clock or "00:00:00"
    if len(clock) == 5:
        clock += ":00"
    fraction = (fraction or "")[:6].ljust(6, "0")
    if zone in (None, "Z"):
        zone = "+00:00"
    elif ":" not in zone:
        zone = zone[:3] + ":" + zone[3:]
    try:
        value = dt.datetime.fromisoformat(f"{date}T{clock}.{fraction}{zone}")
        return value.astimezone(UTC)
    except (ValueError, OverflowError) as exc:  # 9999-12-31T23:59-23:59 overflows
        raise TimeError("unreadable time") from exc


def fmt(value: dt.datetime) -> str:
    """The stored form, 2026-11-07T15:04:05.000000Z. The fraction is always there,
    so stored times sort correctly as text."""
    value = value.astimezone(UTC)
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond:06d}Z"


def norm(text: str) -> str:
    """A feed's time in the stored form, so stored times compare as text."""
    return fmt(parse(text))


def now() -> dt.datetime:
    return dt.datetime.now(UTC)
