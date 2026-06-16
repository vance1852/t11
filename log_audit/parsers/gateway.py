import re
from datetime import datetime, timezone, timedelta
from typing import List

from log_audit.config import TARGET_TIMEZONE
from log_audit.models import LogRecord
from log_audit.parsers.base import BaseParser


_GATEWAY_PATTERN = re.compile(
    r'^(\S+) \[(.+?)\] "(\S+) (\S+) \S+" (\d{3}) (\d+) ([\d.]+) "(.*)"$'
)

_MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _parse_gateway_timestamp(ts_str: str) -> datetime:
    match = re.match(
        r'(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})', ts_str
    )
    if not match:
        raise ValueError(f"Cannot parse gateway timestamp: {ts_str}")
    day, mon_str, year, hour, minute, sec, tz_str = match.groups()
    month = _MONTH_MAP.get(mon_str, 1)
    tz_sign = 1 if tz_str[0] == '+' else -1
    tz_hours = int(tz_str[1:3])
    tz_minutes = int(tz_str[3:5])
    tz_offset = timedelta(hours=tz_sign * tz_hours, minutes=tz_sign * tz_minutes)
    tz = timezone(tz_offset)
    dt = datetime(int(year), month, int(day), int(hour), int(minute), int(sec), tzinfo=tz)
    return dt.astimezone(TARGET_TIMEZONE)


class GatewayParser(BaseParser):

    @property
    def source_type(self) -> str:
        return "gateway"

    def can_parse(self, file_path: str) -> bool:
        fname = file_path.lower()
        return "gateway" in fname or "access" in fname

    def parse(self, file_path: str) -> List[LogRecord]:
        records: List[LogRecord] = []
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n\r")
                if not line:
                    continue
                m = _GATEWAY_PATTERN.match(line)
                if not m:
                    continue
                client_ip, ts_str, method, path, status_str, bytes_str, dur_str, ua = m.groups()
                try:
                    ts = _parse_gateway_timestamp(ts_str)
                except ValueError:
                    continue
                records.append(LogRecord(
                    timestamp=ts,
                    source_type=self.source_type,
                    raw_data={
                        "client_ip": client_ip,
                        "method": method,
                        "path": path,
                        "status_code": int(status_str),
                        "response_bytes": int(bytes_str),
                        "duration": float(dur_str),
                        "user_agent": ua,
                    },
                ))
        return records
