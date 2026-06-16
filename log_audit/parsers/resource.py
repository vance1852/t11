import re
from datetime import datetime, timezone, timedelta
from typing import List

from log_audit.config import TARGET_TIMEZONE
from log_audit.models import LogRecord
from log_audit.parsers.base import BaseParser


_RESOURCE_PATTERN = re.compile(
    r'^(\S+)\s+cpu=([\d.]+)\s+mem=([\d.]+)\s+disk=([\d.]+)$'
)


def _parse_resource_timestamp(ts_str: str) -> datetime:
    dt = datetime.fromisoformat(ts_str)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=TARGET_TIMEZONE)
    return dt.astimezone(TARGET_TIMEZONE)


class ResourceParser(BaseParser):

    @property
    def source_type(self) -> str:
        return "resource"

    def can_parse(self, file_path: str) -> bool:
        fname = file_path.lower()
        return "resource" in fname or "metrics" in fname or "machine" in fname

    def parse(self, file_path: str) -> List[LogRecord]:
        records: List[LogRecord] = []
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n\r")
                if not line:
                    continue
                m = _RESOURCE_PATTERN.match(line)
                if not m:
                    continue
                ts_str, cpu_str, mem_str, disk_str = m.groups()
                try:
                    ts = _parse_resource_timestamp(ts_str)
                except ValueError:
                    continue
                records.append(LogRecord(
                    timestamp=ts,
                    source_type=self.source_type,
                    raw_data={
                        "cpu": float(cpu_str),
                        "mem": float(mem_str),
                        "disk": float(disk_str),
                    },
                ))
        return records
