from collections import defaultdict
from typing import List, Dict, Tuple

from log_audit.config import ANOMALY_WINDOW_SECONDS
from log_audit.models import LogRecord, CorrelatedGroup


def _window_key(ts, window_seconds: int) -> Tuple[int, int]:
    epoch = ts.timestamp()
    window_idx = int(epoch // window_seconds)
    return window_idx


def correlate(
    records: List[LogRecord],
    window_seconds: int = ANOMALY_WINDOW_SECONDS,
) -> List[CorrelatedGroup]:
    buckets: Dict[int, Dict[str, List[LogRecord]]] = defaultdict(
        lambda: {"gateway": [], "app": [], "login": [], "resource": []}
    )

    for rec in records:
        wk = _window_key(rec.timestamp, window_seconds)
        buckets[wk][rec.source_type].append(rec)

    groups: List[CorrelatedGroup] = []
    for wk in sorted(buckets.keys()):
        bucket = buckets[wk]
        window_start_ts = wk * window_seconds
        from datetime import datetime, timezone
        window_start = datetime.fromtimestamp(window_start_ts, tz=timezone.utc)
        window_end = datetime.fromtimestamp(window_start_ts + window_seconds, tz=timezone.utc)

        has_multi = sum(1 for v in bucket.values() if v) >= 2
        if has_multi:
            groups.append(CorrelatedGroup(
                window_start=window_start,
                window_end=window_end,
                gateway_records=bucket["gateway"],
                app_records=bucket["app"],
                login_records=bucket["login"],
                resource_records=bucket["resource"],
            ))

    return groups


def get_time_windows(
    records: List[LogRecord],
    window_seconds: int = ANOMALY_WINDOW_SECONDS,
) -> Dict[int, Dict[str, List[LogRecord]]]:
    buckets: Dict[int, Dict[str, List[LogRecord]]] = defaultdict(
        lambda: {"gateway": [], "app": [], "login": [], "resource": []}
    )
    for rec in records:
        wk = _window_key(rec.timestamp, window_seconds)
        buckets[wk][rec.source_type].append(rec)
    return buckets
