from collections import defaultdict
from datetime import datetime, timezone
from typing import List, Dict, Tuple, Optional

import numpy as np

from log_audit.config import (
    ANOMALY_WINDOW_SECONDS,
    BASELINE_WINDOW_COUNT,
    ERROR_SPIKE_SIGMA,
    SLOW_REQUEST_P95_FACTOR,
    LOGIN_FAILURE_THRESHOLD,
    SCAN_404_THRESHOLD,
)
from log_audit.models import LogRecord, AnomalyEvent
from log_audit.correlator import get_time_windows


def _window_start_ts(window_key: int, window_seconds: int) -> datetime:
    return datetime.fromtimestamp(window_key * window_seconds, tz=timezone.utc)


def _window_end_ts(window_key: int, window_seconds: int) -> datetime:
    return datetime.fromtimestamp((window_key + 1) * window_seconds, tz=timezone.utc)


def _severity_error_spike(sigma_above: float, error_count: int) -> str:
    if sigma_above >= 5 or error_count >= 50:
        return "critical"
    if sigma_above >= 3 or error_count >= 20:
        return "high"
    return "medium"


def _severity_slow_request(ratio: float, count: int) -> str:
    if ratio >= 5 or count >= 20:
        return "critical"
    if ratio >= 3 or count >= 10:
        return "high"
    return "medium"


def _severity_login_failure(count: int) -> str:
    if count >= 20:
        return "critical"
    if count >= 10:
        return "high"
    return "medium"


def _severity_scan_404(unique_paths: int) -> str:
    if unique_paths >= 50:
        return "critical"
    if unique_paths >= 20:
        return "high"
    return "medium"


def detect_error_spikes(
    windows: Dict[int, Dict[str, List[LogRecord]]],
    window_seconds: int = ANOMALY_WINDOW_SECONDS,
    baseline_count: int = BASELINE_WINDOW_COUNT,
    sigma: float = ERROR_SPIKE_SIGMA,
) -> List[AnomalyEvent]:
    anomalies: List[AnomalyEvent] = []
    sorted_keys = sorted(windows.keys())

    error_rates: Dict[int, Tuple[float, int, int]] = {}
    for wk in sorted_keys:
        gw = windows[wk].get("gateway", [])
        app = windows[wk].get("app", [])
        gw_5xx = sum(1 for r in gw if r.raw_data.get("status_code", 0) >= 500)
        gw_total = len(gw)
        app_error = sum(1 for r in app if r.raw_data.get("level", "") == "ERROR")
        app_total = len(app)

        combined_errors = gw_5xx + app_error
        combined_total = gw_total + app_total
        rate = combined_errors / combined_total if combined_total > 0 else 0.0
        error_rates[wk] = (rate, combined_errors, combined_total)

    for i, wk in enumerate(sorted_keys):
        rate, err_count, total_count = error_rates[wk]
        if total_count < 5:
            continue
        if err_count < 2:
            continue

        baseline_keys = sorted_keys[max(0, i - baseline_count):i]
        if not baseline_keys:
            continue

        baseline_rates = [error_rates[bk][0] for bk in baseline_keys if error_rates[bk][1] >= 0]
        if not baseline_rates:
            continue

        baseline_arr = np.array(baseline_rates)
        bl_mean = float(np.mean(baseline_arr))
        bl_std = float(np.std(baseline_arr))

        if bl_std < 1e-9:
            threshold = bl_mean + 0.05
        else:
            threshold = bl_mean + sigma * bl_std

        if rate > threshold:
            sigma_above = (rate - bl_mean) / bl_std if bl_std > 1e-9 else float("inf")
            severity = _severity_error_spike(sigma_above, err_count)

            gw_5xx_ips = set()
            app_error_modules = set()
            gw = windows[wk].get("gateway", [])
            app = windows[wk].get("app", [])
            for r in gw:
                if r.raw_data.get("status_code", 0) >= 500:
                    gw_5xx_ips.add(r.raw_data.get("client_ip", ""))
            for r in app:
                if r.raw_data.get("level", "") == "ERROR":
                    app_error_modules.add(r.raw_data.get("module", ""))

            anomalies.append(AnomalyEvent(
                anomaly_type="error_spike",
                time_window_start=_window_start_ts(wk, window_seconds),
                time_window_end=_window_end_ts(wk, window_seconds),
                severity=severity,
                evidence={
                    "error_rate": round(rate, 4),
                    "error_count": err_count,
                    "total_count": total_count,
                    "baseline_mean": round(bl_mean, 4),
                    "baseline_std": round(bl_std, 4),
                    "sigma_above_baseline": round(sigma_above, 2),
                    "gateway_5xx_ips": sorted(gw_5xx_ips),
                    "app_error_modules": sorted(app_error_modules),
                },
                description=(
                    f"Error spike: rate={rate:.2%} (baseline={bl_mean:.2%}±{bl_std:.2%}), "
                    f"{err_count} errors in {total_count} events, "
                    f"sigma_above={sigma_above:.1f}"
                ),
            ))

    return anomalies


def detect_slow_requests(
    windows: Dict[int, Dict[str, List[LogRecord]]],
    window_seconds: int = ANOMALY_WINDOW_SECONDS,
    p95_factor: float = SLOW_REQUEST_P95_FACTOR,
) -> List[AnomalyEvent]:
    anomalies: List[AnomalyEvent] = []

    all_durations = []
    for wk in windows:
        for r in windows[wk].get("gateway", []):
            dur = r.raw_data.get("duration")
            if dur is not None:
                all_durations.append(dur)

    if not all_durations:
        return anomalies

    overall_p95 = float(np.percentile(all_durations, 95))
    threshold = overall_p95 * p95_factor

    for wk in sorted(windows.keys()):
        gw = windows[wk].get("gateway", [])
        durations = [r.raw_data["duration"] for r in gw if "duration" in r.raw_data]
        if len(durations) < 3:
            continue

        window_p95 = float(np.percentile(durations, 95))
        if window_p95 > threshold:
            slow_paths = defaultdict(int)
            for r in gw:
                if r.raw_data.get("duration", 0) > threshold:
                    slow_paths[r.raw_data.get("path", "")] += 1

            ratio = window_p95 / overall_p95 if overall_p95 > 0 else float("inf")
            slow_count = sum(slow_paths.values())
            severity = _severity_slow_request(ratio, slow_count)

            anomalies.append(AnomalyEvent(
                anomaly_type="slow_request",
                time_window_start=_window_start_ts(wk, window_seconds),
                time_window_end=_window_end_ts(wk, window_seconds),
                severity=severity,
                evidence={
                    "window_p95": round(window_p95, 3),
                    "overall_p95": round(overall_p95, 3),
                    "ratio": round(ratio, 2),
                    "slow_count": slow_count,
                    "slow_paths": dict(slow_paths),
                },
                description=(
                    f"Slow requests: p95={window_p95:.3f}s "
                    f"(overall_p95={overall_p95:.3f}s, ratio={ratio:.1f}x), "
                    f"{slow_count} slow requests"
                ),
            ))

    return anomalies


def detect_login_failures(
    windows: Dict[int, Dict[str, List[LogRecord]]],
    window_seconds: int = ANOMALY_WINDOW_SECONDS,
    threshold: int = LOGIN_FAILURE_THRESHOLD,
) -> List[AnomalyEvent]:
    anomalies: List[AnomalyEvent] = []

    for wk in sorted(windows.keys()):
        login_recs = windows[wk].get("login", [])
        failures_by_ip: Dict[str, List[LogRecord]] = defaultdict(list)
        for r in login_recs:
            if r.raw_data.get("status") == "failure":
                failures_by_ip[r.raw_data.get("src_ip", "")].append(r)

        for ip, failures in failures_by_ip.items():
            if len(failures) >= threshold:
                users = list(set(r.raw_data.get("user", "") for r in failures))
                severity = _severity_login_failure(len(failures))

                anomalies.append(AnomalyEvent(
                    anomaly_type="login_failure_burst",
                    time_window_start=_window_start_ts(wk, window_seconds),
                    time_window_end=_window_end_ts(wk, window_seconds),
                    severity=severity,
                    evidence={
                        "src_ip": ip,
                        "failure_count": len(failures),
                        "targeted_users": sorted(users),
                    },
                    description=(
                        f"Login failure burst: {len(failures)} failures from {ip}, "
                        f"targeting users: {', '.join(sorted(users))}"
                    ),
                ))

    return anomalies


def detect_scan_404(
    windows: Dict[int, Dict[str, List[LogRecord]]],
    window_seconds: int = ANOMALY_WINDOW_SECONDS,
    threshold: int = SCAN_404_THRESHOLD,
) -> List[AnomalyEvent]:
    anomalies: List[AnomalyEvent] = []

    for wk in sorted(windows.keys()):
        gw = windows[wk].get("gateway", [])
        not_found_by_ip: Dict[str, List[LogRecord]] = defaultdict(list)
        for r in gw:
            if r.raw_data.get("status_code") == 404:
                not_found_by_ip[r.raw_data.get("client_ip", "")].append(r)

        for ip, recs in not_found_by_ip.items():
            unique_paths = list(set(r.raw_data.get("path", "") for r in recs))
            if len(unique_paths) >= threshold:
                severity = _severity_scan_404(len(unique_paths))

                anomalies.append(AnomalyEvent(
                    anomaly_type="scan_404",
                    time_window_start=_window_start_ts(wk, window_seconds),
                    time_window_end=_window_end_ts(wk, window_seconds),
                    severity=severity,
                    evidence={
                        "src_ip": ip,
                        "unique_404_paths": len(unique_paths),
                        "total_404_requests": len(recs),
                        "sample_paths": sorted(unique_paths)[:10],
                    },
                    description=(
                        f"404 scan: {len(unique_paths)} unique 404 paths from {ip}, "
                        f"total {len(recs)} requests"
                    ),
                ))

    return anomalies


def run_all_detectors(
    records: List[LogRecord],
    window_seconds: int = ANOMALY_WINDOW_SECONDS,
) -> List[AnomalyEvent]:
    windows = get_time_windows(records, window_seconds)
    anomalies: List[AnomalyEvent] = []

    anomalies.extend(detect_error_spikes(windows, window_seconds))
    anomalies.extend(detect_slow_requests(windows, window_seconds))
    anomalies.extend(detect_login_failures(windows, window_seconds))
    anomalies.extend(detect_scan_404(windows, window_seconds))

    anomalies.sort(key=lambda a: (a.time_window_start, a.severity))
    return anomalies
