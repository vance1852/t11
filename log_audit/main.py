import argparse
import sys
import time
from typing import List

from log_audit.models import LogRecord
from log_audit.parsers import create_default_registry
from log_audit.session import build_sessions
from log_audit.correlator import correlate
from log_audit.anomaly import run_all_detectors
from log_audit.report import (
    compute_overview,
    print_overview,
    print_anomalies,
    print_sessions,
    compute_service_stats,
    print_service_stats,
    export_all,
)
from log_audit.generator import generate_all


def _parse_records(input_dir: str) -> List[LogRecord]:
    registry = create_default_registry()
    print(f"[1/4] Parsing logs from: {input_dir}")
    print(f"      Registered parsers: {', '.join(registry.registered_types)}")

    records = registry.parse_directory(input_dir)
    by_type = {}
    for r in records:
        by_type.setdefault(r.source_type, 0)
        by_type[r.source_type] += 1

    print(f"      Total records: {len(records)}")
    for st, cnt in sorted(by_type.items()):
        print(f"        {st}: {cnt}")

    if not records:
        print("ERROR: No records parsed. Check log files and parser detection.", file=sys.stderr)
        sys.exit(1)

    return records


def run_full(input_dir: str, output_dir: str) -> None:
    records = _parse_records(input_dir)

    print(f"\n[2/4] Building sessions...")
    gateway_records = [r for r in records if r.source_type == "gateway"]
    sessions = build_sessions(gateway_records)
    print(f"      Sessions found: {len(sessions)}")
    print(f"      Sessions with errors: {sum(1 for s in sessions if s.has_error)}")

    print(f"\n[3/4] Running anomaly detection...")
    anomalies = run_all_detectors(records)
    by_type = {}
    for a in anomalies:
        by_type.setdefault(a.anomaly_type, 0)
        by_type[a.anomaly_type] += 1
    print(f"      Anomalies found: {len(anomalies)}")
    for at, cnt in sorted(by_type.items()):
        print(f"        {at}: {cnt}")

    print(f"\n[4/4] Generating report...")
    correlated = correlate(records)
    overview = compute_overview(records, sessions)
    service_stats = compute_service_stats(records)

    print_overview(overview)
    print_sessions(sessions, limit=30)
    print_anomalies(anomalies)
    print_service_stats(service_stats, limit=40)

    export_all(output_dir, overview, anomalies, sessions, service_stats)
    print(f"\n      Exported to: {output_dir}/")
    print(f"        overview.json / overview.csv")
    print(f"        anomalies.json / anomalies.csv")
    print(f"        sessions.json / sessions.csv")
    print(f"        service_stats.json / service_stats.csv")


def run_quick(input_dir: str, output_dir: str) -> None:
    records = _parse_records(input_dir)

    gateway_records = [r for r in records if r.source_type == "gateway"]
    sessions = build_sessions(gateway_records)

    overview = compute_overview(records, sessions)

    print_overview(overview)
    print_sessions(sessions, limit=30)

    export_all(output_dir, overview, [], sessions, [])
    print(f"\n      [Quick mode] Exported to: {output_dir}/")
    print(f"        overview.json / overview.csv")
    print(f"        sessions.json / sessions.csv")


def run_generate(output_dir: str) -> None:
    print(f"Generating sample logs in: {output_dir}")
    paths = generate_all(output_dir)
    for name, path in paths.items():
        print(f"  {name}: {path}")
    print("Done. Now run with --input to analyze.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Log Audit Tool - Parse, correlate, and detect anomalies across multi-source logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m log_audit --generate ./sample_logs\n"
            "  python -m log_audit --input ./sample_logs --output ./report\n"
            "  python -m log_audit --input ./sample_logs --output ./report --quick\n"
        ),
    )

    parser.add_argument("--input", "-i", help="Input directory containing log files")
    parser.add_argument("--output", "-o", default="./log_audit_output", help="Output directory for reports (default: ./log_audit_output)")
    parser.add_argument("--quick", "-q", action="store_true", help="Quick mode: parse & normalize only, skip anomaly detection")
    parser.add_argument("--generate", "-g", metavar="DIR", help="Generate sample logs with embedded anomalies in DIR")

    args = parser.parse_args()

    if args.generate:
        run_generate(args.generate)
        return

    if not args.input:
        parser.error("Either --input or --generate is required")

    if args.quick:
        run_quick(args.input, args.output)
    else:
        run_full(args.input, args.output)


if __name__ == "__main__":
    main()
