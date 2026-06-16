import re
from datetime import datetime, timezone, timedelta
from typing import List

from log_audit.config import TARGET_TIMEZONE
from log_audit.models import LogRecord
from log_audit.parsers.base import BaseParser


_LOGIN_PATTERN = re.compile(
    r'^(\S+)\s+LOGIN\s+user=(\S+)\s+src_ip=(\S+)\s+status=(\S+)(?:\s+reason=(.+))?$'
)


def _parse_login_timestamp(ts_str: str) -> datetime:
    dt = datetime.fromisoformat(ts_str)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=TARGET_TIMEZONE)
    return dt.astimezone(TARGET_TIMEZONE)


class LoginParser(BaseParser):

    @property
    def source_type(self) -> str:
        return "login"

    def can_parse(self, file_path: str) -> bool:
        fname = file_path.lower()
        return "login" in fname or "audit" in fname

    def parse(self, file_path: str) -> List[LogRecord]:
        records: List[LogRecord] = []
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n\r")
                if not line:
                    continue
                m = _LOGIN_PATTERN.match(line)
                if not m:
                    continue
                ts_str, user, src_ip, status, reason = m.groups()
                try:
                    ts = _parse_login_timestamp(ts_str)
                except ValueError:
                    continue
                records.append(LogRecord(
                    timestamp=ts,
                    source_type=self.source_type,
                    raw_data={
                        "user": user,
                        "src_ip": src_ip,
                        "status": status,
                        "reason": reason or "",
                    },
                ))
        return records
