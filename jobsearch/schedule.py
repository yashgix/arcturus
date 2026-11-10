"""Pure due-slot calculation for a future caller. This module runs no timers."""

from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo

from .store import SLOT, stamp


@dataclass(frozen=True)
class Cadence:
    name: str
    timezone: str
    anchor: date
    local_time: time
    interval_days: int

    def due_slot(self, now: datetime):
        """Return the latest due local calendar slot, including after wake."""
        stamp(now)
        if (
            not SLOT.fullmatch(self.name)
            or len(self.name) > 80
            or type(self.interval_days) is not int
            or self.interval_days < 1
            or self.local_time.tzinfo is not None
        ):
            raise ValueError("invalid cadence")
        local = now.astimezone(ZoneInfo(self.timezone))
        day = local.date()
        # Use the first occurrence on a fall-back day. Spring gaps shift by
        # the offset change. Compare UTC instants so a slot cannot go backwards.
        scheduled = datetime.combine(day, self.local_time, local.tzinfo).replace(fold=0)
        if now.astimezone(timezone.utc) < scheduled.astimezone(timezone.utc):
            day -= timedelta(days=1)
        elapsed = (day - self.anchor).days
        if elapsed < 0:
            return None
        due = day - timedelta(days=elapsed % self.interval_days)
        return f"{self.name}:{due.isoformat()}"
