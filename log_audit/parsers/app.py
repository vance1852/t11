import re
from datetime import datetime, timezone, timedelta
from typing import List, Tuple

from log_audit.config import TARGET_TIMEZONE
from log_audit.models import LogRecord
from log_audit.parsers.base import BaseParser


_APP_HEADER_PATTERN = re.compile(
    r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})\s+([+-]\d{4})\s+(\w+)\s+\[(\S+)\]\s+(.*)$'
)


def _parse_app_timestamp(ts_str: str, tz_str: str) -> datetime:
    dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S,%f")
    tz_sign = 1 if tz_str[0] == '+' else -1
    tz_hours = int(tz_str[1:3])
    tz_minutes = int(tz_str[3:5])
    tz_offset = timedelta(hours=tz_sign * tz_hours, minutes=tz_sign * tz_minutes)
    tz = timezone(tz_offset)
    dt = dt.replace(tzinfo=tz)
    return dt.astimezone(TARGET_TIMEZONE)


def _merge_multiline(lines: List[str]) -> List[Tuple[str, str, str, str, str]]:
    entries: List[Tuple[str, str, str, str, str]] = []
    current_ts = ""
    current_tz = ""
    current_level = ""
    current_module = ""
    current_message_lines: List[str] = []

    for line in lines:
        m = _APP_HEADER_PATTERN.match(line)
        if m:
            if current_ts:
                stack_trace = "\n".join(current_message_lines[1:]) if len(current_message_lines) > 1 else ""
                entries.append((
                    current_ts, current_tz, current_level,
                    current_module, current_message_lines[0],
                ))
                if stack_trace:
                    entries[-1] = (
                        entries[-1][0], entries[-1][1], entries[-1][2],
                        entries[-1][3], entries[-1][4] + "\n" + stack_trace,
                    )
            current_ts, current_tz, current_level, current_module, msg = m.groups()
            current_message_lines = [msg]
        else:
            if current_ts:
                current_message_lines.append(line)

    if current_ts:
        stack_trace = "\n".join(current_message_lines[1:]) if len(current_message_lines) > 1 else ""
        entries.append((
            current_ts, current_tz, current_level,
            current_module, current_message_lines[0],
        ))
        if stack_trace:
            entries[-1] = (
                entries[-1][0], entries[-1][1], entries[-1][2],
                entries[-1][3], entries[-1][4] + "\n" + stack_trace,
            )

    return entries


class AppParser(BaseParser):

    @property
    def source_type(self) -> str:
        return "app"

    def can_parse(self, file_path: str) -> bool:
        fname = file_path.lower()
        return "app" in fname or "application" in fname

    def parse(self, file_path: str) -> List[LogRecord]:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            lines = [line.rstrip("\n\r") for line in f if line.strip()]

        entries = _merge_multiline(lines)
        records: List[LogRecord] = []

        for ts_str, tz_str, level, module, message in entries:
            try:
                ts = _parse_app_timestamp(ts_str, tz_str)
            except ValueError:
                continue

            msg_parts = message.split("\n", 1)
            main_msg = msg_parts[0]
            stack_trace = msg_parts[1] if len(msg_parts) > 1 else ""

            records.append(LogRecord(
                timestamp=ts,
                source_type=self.source_type,
                raw_data={
                    "level": level,
                    "module": module,
                    "message": main_msg,
                    "stack_trace": stack_trace,
                },
            ))

        return records
