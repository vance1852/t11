import csv
import json
import os
from collections import defaultdict
from datetime import datetime, timezone
from typing import List, Dict, Any

import numpy as np

from log_audit.models import LogRecord, Session, AnomalyEvent, AuditReport


def _fmt_ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def _fmt_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = seconds / 60
    if minutes < 60:
        return f"{minutes:.1f}m"
    hours = minutes / 60
    return f"{hours:.1f}h"


def _col_widths(headers: List[str], rows: List[List[str]]) -> List[int]:
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(widths):
                widths[i] = max(widths[i], len(str(cell)))
    return widths


def _print_table(title: str, headers: List[str], rows: List[List[str]]) -> None:
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print(f"{'=' * 70}")
    widths = _col_widths(headers, rows)
    header_line = " | ".join(h.ljust(w) for h, w in zip(headers, widths))
    sep_line = "-+-".join("-" * w for w in widths)
    print(header_line)
    print(sep_line)
    for row in rows:
        cells = [str(c).ljust(w) for c, w in zip(row, widths)]
        print(" | ".join(cells))


def compute_overview(
    records: List[LogRecord],
    sessions: List[Session],
) -> Dict[str, Any]:
    gateway = [r for r in records if r.source_type == "gateway"]
    app = [r for r in records if r.source_type == "app"]
    login = [r for r in records if r.source_type == "login"]
    resource = [r for r in records if r.source_type == "resource"]

    total_requests = len(gateway)
    errors_5xx = sum(1 for r in gateway if r.raw_data.get("status_code", 0) >= 500)
    errors_4xx = sum(1 for r in gateway if 400 <= r.raw_data.get("status_code", 0) < 500)
    error_rate = errors_5xx / total_requests if total_requests > 0 else 0.0

    durations = [r.raw_data["duration"] for r in gateway if "duration" in r.raw_data]
    if durations:
        p50 = float(np.percentile(durations, 50))
        p95 = float(np.percentile(durations, 95))
        p99 = float(np.percentile(durations, 99))
    else:
        p50 = p95 = p99 = 0.0

    path_counts: Dict[str, int] = defaultdict(int)
    ip_counts: Dict[str, int] = defaultdict(int)
    for r in gateway:
        path_counts[r.raw_data.get("path", "")] += 1
        ip_counts[r.raw_data.get("client_ip", "")] += 1

    top_paths = sorted(path_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    app_errors = sum(1 for r in app if r.raw_data.get("level") == "ERROR")
    app_warnings = sum(1 for r in app if r.raw_data.get("level") == "WARN")
    login_failures = sum(1 for r in login if r.raw_data.get("status") == "failure")
    login_successes = sum(1 for r in login if r.raw_data.get("status") == "success")

    return {
        "total_gateway_requests": total_requests,
        "total_app_records": len(app),
        "total_login_records": len(login),
        "total_resource_records": len(resource),
        "5xx_count": errors_5xx,
        "4xx_count": errors_4xx,
        "error_rate": round(error_rate, 4),
        "p50_latency": round(p50, 3),
        "p95_latency": round(p95, 3),
        "p99_latency": round(p99, 3),
        "top_paths": [{"path": p, "count": c} for p, c in top_paths],
        "top_ips": [{"ip": ip, "count": c} for ip, c in top_ips],
        "app_errors": app_errors,
        "app_warnings": app_warnings,
        "login_failures": login_failures,
        "login_successes": login_successes,
        "total_sessions": len(sessions),
        "sessions_with_errors": sum(1 for s in sessions if s.has_error),
    }


def print_overview(overview: Dict[str, Any]) -> None:
    _print_table(
        "总览 / Overview",
        ["Metric", "Value"],
        [
            ["Total Gateway Requests", str(overview["total_gateway_requests"])],
            ["5xx Errors", str(overview["5xx_count"])],
            ["4xx Errors", str(overview["4xx_count"])],
            ["Error Rate (5xx)", f"{overview['error_rate']:.2%}"],
            ["P50 Latency", f"{overview['p50_latency']:.3f}s"],
            ["P95 Latency", f"{overview['p95_latency']:.3f}s"],
            ["P99 Latency", f"{overview['p99_latency']:.3f}s"],
            ["App Records", str(overview["total_app_records"])],
            ["App Errors", str(overview["app_errors"])],
            ["App Warnings", str(overview["app_warnings"])],
            ["Login Records", str(overview["total_login_records"])],
            ["Login Failures", str(overview["login_failures"])],
            ["Login Successes", str(overview["login_successes"])],
            ["Resource Samples", str(overview["total_resource_records"])],
            ["Total Sessions", str(overview["total_sessions"])],
            ["Sessions w/ Errors", str(overview["sessions_with_errors"])],
        ],
    )

    if overview["top_paths"]:
        _print_table(
            "Top Paths",
            ["Path", "Count"],
            [[p["path"], str(p["count"])] for p in overview["top_paths"]],
        )

    if overview["top_ips"]:
        _print_table(
            "Top IPs",
            ["IP", "Count"],
            [[ip["ip"], str(ip["count"])] for ip in overview["top_ips"]],
        )


def print_anomalies(anomalies: List[AnomalyEvent]) -> None:
    if not anomalies:
        print("\n  No anomalies detected.")
        return

    rows = []
    for a in anomalies:
        rows.append([
            _fmt_ts(a.time_window_start),
            a.anomaly_type,
            a.severity.upper(),
            a.description[:60],
        ])

    _print_table(
        f"异常审计清单 / Anomaly Audit ({len(anomalies)} events)",
        ["Time Window Start", "Type", "Severity", "Description"],
        rows,
    )


def print_sessions(sessions: List[Session], limit: int = 20) -> None:
    if not sessions:
        return

    rows = []
    for s in sessions[:limit]:
        status_str = " ".join(f"{k}:{v}" for k, v in sorted(s.status_distribution.items()))
        rows.append([
            s.session_id,
            s.client_ip,
            _fmt_ts(s.start_time),
            str(s.request_count),
            _fmt_duration(s.duration_seconds),
            "YES" if s.has_error else "no",
            status_str,
        ])

    _print_table(
        f"Sessions (showing {min(limit, len(sessions))} of {len(sessions)})",
        ["Session ID", "Client IP", "Start", "Reqs", "Duration", "Error?", "Status Dist"],
        rows,
    )


def compute_service_stats(
    records: List[LogRecord],
    window_seconds: int = 300,
) -> List[Dict[str, Any]]:
    from log_audit.correlator import get_time_windows

    windows = get_time_windows(records, window_seconds)
    stats = []

    for wk in sorted(windows.keys()):
        gw = windows[wk].get("gateway", [])
        app = windows[wk].get("app", [])
        login = windows[wk].get("login", [])
        resource = windows[wk].get("resource", [])

        if not any([gw, app, login, resource]):
            continue

        gw_5xx = sum(1 for r in gw if r.raw_data.get("status_code", 0) >= 500)
        gw_total = len(gw)
        durs = [r.raw_data["duration"] for r in gw if "duration" in r.raw_data]
        p95 = float(np.percentile(durs, 95)) if durs else 0.0

        app_errors = sum(1 for r in app if r.raw_data.get("level") == "ERROR")
        login_fail = sum(1 for r in login if r.raw_data.get("status") == "failure")

        cpu_vals = [r.raw_data["cpu"] for r in resource if "cpu" in r.raw_data]
        mem_vals = [r.raw_data["mem"] for r in resource if "mem" in r.raw_data]
        avg_cpu = float(np.mean(cpu_vals)) if cpu_vals else 0.0
        avg_mem = float(np.mean(mem_vals)) if mem_vals else 0.0

        ws = datetime.fromtimestamp(wk * window_seconds, tz=timezone.utc)
        we = datetime.fromtimestamp((wk + 1) * window_seconds, tz=timezone.utc)

        stats.append({
            "window_start": ws.isoformat(),
            "window_end": we.isoformat(),
            "gateway_requests": gw_total,
            "gateway_5xx": gw_5xx,
            "gateway_p95_latency": round(p95, 3),
            "app_records": len(app),
            "app_errors": app_errors,
            "login_records": len(login),
            "login_failures": login_fail,
            "avg_cpu": round(avg_cpu, 1),
            "avg_mem": round(avg_mem, 1),
        })

    return stats


def print_service_stats(stats: List[Dict[str, Any]], limit: int = 30) -> None:
    if not stats:
        return

    rows = []
    for s in stats[:limit]:
        rows.append([
            s["window_start"][:16],
            str(s["gateway_requests"]),
            str(s["gateway_5xx"]),
            f"{s['gateway_p95_latency']:.3f}",
            str(s["app_errors"]),
            str(s["login_failures"]),
            f"{s['avg_cpu']:.0f}",
            f"{s['avg_mem']:.0f}",
        ])

    _print_table(
        f"Service Stats by Window (showing {min(limit, len(stats))} of {len(stats)})",
        ["Window", "GW Reqs", "5xx", "P95(s)", "AppErr", "LoginFail", "CPU%", "Mem%"],
        rows,
    )


def export_csv(data: List[Dict[str, Any]], file_path: str) -> None:
    if not data:
        return
    os.makedirs(os.path.dirname(file_path) or ".", exist_ok=True)
    with open(file_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)


def _export_csv_with_fields(data: List[Dict[str, Any]], fieldnames: List[str], file_path: str) -> None:
    if not data:
        return
    os.makedirs(os.path.dirname(file_path) or ".", exist_ok=True)
    with open(file_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(data)


def export_json(data: Any, file_path: str) -> None:
    os.makedirs(os.path.dirname(file_path) or ".", exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)


def anomaly_to_dict(a: AnomalyEvent) -> Dict[str, Any]:
    return {
        "anomaly_type": a.anomaly_type,
        "time_window_start": a.time_window_start.isoformat(),
        "time_window_end": a.time_window_end.isoformat(),
        "severity": a.severity,
        "evidence": a.evidence,
        "description": a.description,
    }


def session_to_dict(s: Session) -> Dict[str, Any]:
    return {
        "session_id": s.session_id,
        "client_ip": s.client_ip,
        "start_time": s.start_time.isoformat(),
        "end_time": s.end_time.isoformat(),
        "request_count": s.request_count,
        "duration_seconds": round(s.duration_seconds, 2),
        "status_distribution": s.status_distribution,
        "has_error": s.has_error,
    }


def export_all(
    output_dir: str,
    overview: Dict[str, Any],
    anomalies: List[AnomalyEvent],
    sessions: List[Session],
    service_stats: List[Dict[str, Any]],
) -> None:
    os.makedirs(output_dir, exist_ok=True)

    export_json(overview, os.path.join(output_dir, "overview.json"))
    export_csv([{"metric": k, "value": str(v)} for k, v in overview.items()],
               os.path.join(output_dir, "overview.csv"))

    anomaly_dicts = [anomaly_to_dict(a) for a in anomalies]
    export_json(anomaly_dicts, os.path.join(output_dir, "anomalies.json"))
    if anomaly_dicts:
        flat_anomalies = []
        all_keys: set = set()
        for a in anomaly_dicts:
            flat = {
                "anomaly_type": a["anomaly_type"],
                "time_window_start": a["time_window_start"],
                "time_window_end": a["time_window_end"],
                "severity": a["severity"],
                "description": a["description"],
            }
            for ek, ev in a["evidence"].items():
                flat[f"evidence_{ek}"] = str(ev)
            all_keys.update(flat.keys())
            flat_anomalies.append(flat)
        base_keys = ["anomaly_type", "time_window_start", "time_window_end", "severity", "description"]
        extra_keys = sorted(all_keys - set(base_keys))
        fieldnames = base_keys + extra_keys
        for flat in flat_anomalies:
            for k in fieldnames:
                flat.setdefault(k, "")
        _export_csv_with_fields(flat_anomalies, fieldnames, os.path.join(output_dir, "anomalies.csv"))

    session_dicts = [session_to_dict(s) for s in sessions]
    export_json(session_dicts, os.path.join(output_dir, "sessions.json"))
    if session_dicts:
        export_csv(session_dicts, os.path.join(output_dir, "sessions.csv"))

    export_json(service_stats, os.path.join(output_dir, "service_stats.json"))
    if service_stats:
        export_csv(service_stats, os.path.join(output_dir, "service_stats.csv"))
