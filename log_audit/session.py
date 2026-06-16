import hashlib
from collections import defaultdict
from typing import List, Dict

from log_audit.config import SESSION_GAP_SECONDS
from log_audit.models import LogRecord, Session


def _make_session_id(client_ip: str, start_time) -> str:
    raw = f"{client_ip}-{start_time.isoformat()}"
    return hashlib.md5(raw.encode()).hexdigest()[:12]


def build_sessions(
    gateway_records: List[LogRecord],
    gap_seconds: int = SESSION_GAP_SECONDS,
) -> List[Session]:
    by_ip: Dict[str, List[LogRecord]] = defaultdict(list)
    for rec in gateway_records:
        by_ip[rec.raw_data["client_ip"]].append(rec)

    sessions: List[Session] = []
    for client_ip, records in by_ip.items():
        records.sort(key=lambda r: r.timestamp)
        if not records:
            continue

        current_group: List[LogRecord] = [records[0]]
        for rec in records[1:]:
            gap = (rec.timestamp - current_group[-1].timestamp).total_seconds()
            if gap > gap_seconds:
                sessions.append(_finalize_session(client_ip, current_group))
                current_group = [rec]
            else:
                current_group.append(rec)

        if current_group:
            sessions.append(_finalize_session(client_ip, current_group))

    sessions.sort(key=lambda s: s.start_time)
    return sessions


def _finalize_session(client_ip: str, requests: List[LogRecord]) -> Session:
    start_time = requests[0].timestamp
    end_time = requests[-1].timestamp
    duration = (end_time - start_time).total_seconds()
    status_dist: Dict[int, int] = defaultdict(int)
    has_error = False
    for req in requests:
        code = req.raw_data["status_code"]
        status_dist[code] += 1
        if code >= 500:
            has_error = True

    return Session(
        session_id=_make_session_id(client_ip, start_time),
        client_ip=client_ip,
        start_time=start_time,
        end_time=end_time,
        request_count=len(requests),
        duration_seconds=duration,
        status_distribution=dict(status_dist),
        has_error=has_error,
        requests=requests,
    )
