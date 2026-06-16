import json
import os
import random
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any

SEED = 42

TZ_P8 = timezone(timedelta(hours=8))
TZ_P9 = timezone(timedelta(hours=9))
TZ_UTC = timezone.utc

NORMAL_IPS = ["192.168.1.100", "192.168.1.101", "192.168.1.102", "10.0.0.50", "10.0.0.51"]
ATTACKER_IP_LOGIN = "10.0.0.99"
ATTACKER_IP_SCAN = "10.0.0.88"

NORMAL_PATHS = [
    "/api/users", "/api/orders", "/api/products", "/api/health",
    "/", "/dashboard", "/api/search", "/api/cart", "/api/payments",
]
SCAN_PATHS = [
    "/admin", "/admin/login", "/admin/dashboard", "/wp-admin", "/wp-login.php",
    "/config", "/.env", "/.git", "/.git/config", "/backup.sql",
    "/api/debug", "/api/internal", "/api/admin", "/phpmyadmin",
    "/console", "/manager/html", "/actuator", "/actuator/health",
    "/server-status", "/.htaccess", "/wp-config.php", "/config.yml",
    "/debug", "/test", "/temp", "/tmp", "/old", "/backup",
    "/api/v1/debug", "/api/v1/internal", "/api/v2/admin",
    "/solr", "/solr/admin", "/elasticsearch", "/kibana",
    "/jenkins", "/jenkins/login", "/gitlab", "/grafana",
    "/prometheus", "/metrics", "/health-check", "/status",
    "/cgi-bin", "/cgi-bin/test", "/scripts", "/setup",
    "/install", "/phpinfo.php", "/info.php", "/web.config",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)",
]

USERS = ["admin", "user1", "user2", "operator", "dev"]

MODULES = ["main", "auth", "order-service", "payment-service", "user-service", "search"]

STACK_TRACES = [
    (
        "com.example.DatabaseException: Connection timeout",
        "    at com.example.DBPool.getConnection(DBPool.java:89)\n"
        "    at com.example.OrderService.process(OrderService.java:128)\n"
        "    at com.example.OrderController.handle(OrderController.java:45)\n"
        "    at sun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)"
    ),
    (
        "com.example.AuthException: Invalid token",
        "    at com.example.AuthService.validate(AuthService.java:42)\n"
        "    at com.example.AuthController.login(AuthController.java:28)\n"
        "    at com.example.FilterChain.doFilter(FilterChain.java:112)"
    ),
    (
        "java.lang.NullPointerException",
        "    at com.example.UserService.getProfile(UserService.java:67)\n"
        "    at com.example.UserController.handle(UserController.java:33)\n"
        "    at javax.servlet.http.HttpServlet.service(HttpServlet.java:623)"
    ),
]


def _gateway_ts(dt: datetime) -> str:
    months = ["", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    return dt.strftime(f"%d/{months[dt.month]}/%Y:%H:%M:%S +0800")


def _app_ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S,000 +0800")


def _login_ts(dt_utc: datetime) -> str:
    dt_p9 = dt_utc.astimezone(TZ_P9)
    return dt_p9.isoformat()


def _resource_ts(dt_utc: datetime) -> str:
    return dt_utc.isoformat()


def generate_gateway_log(output_dir: str) -> str:
    random.seed(SEED)
    lines: List[str] = []
    start = datetime(2026, 6, 15, 0, 0, 0, tzinfo=TZ_P8)

    for minute in range(0, 24 * 60):
        hour = minute // 60
        dt = start + timedelta(minutes=minute)

        if 8 <= hour < 20:
            req_count = random.randint(1, 3)
        else:
            req_count = random.randint(0, 1)

        is_slow_period = (hour == 10 and dt.minute < 20)
        is_error_period = (hour == 14 and dt.minute < 15)

        for _ in range(req_count):
            ip = random.choice(NORMAL_IPS)
            path = random.choice(NORMAL_PATHS)
            method = random.choice(["GET", "GET", "GET", "POST", "PUT"])
            ua = random.choice(USER_AGENTS)
            seconds_in_minute = random.randint(0, 59)
            req_dt = dt + timedelta(seconds=seconds_in_minute)

            if is_error_period and random.random() < 0.30:
                status = random.choice([500, 502, 503])
            elif random.random() < 0.01:
                status = random.choice([500, 502])
            else:
                status = random.choices(
                    [200, 200, 200, 200, 301, 404, 403],
                    weights=[50, 50, 50, 50, 5, 2, 1],
                )[0]

            if is_slow_period and path == "/api/orders":
                duration = round(random.uniform(2.0, 5.0), 3)
            else:
                duration = round(random.uniform(0.01, 0.5), 3)

            resp_bytes = random.randint(200, 5000)
            lines.append(
                f'{ip} [{_gateway_ts(req_dt)}] "{method} {path} HTTP/1.1" '
                f"{status} {resp_bytes} {duration} \"{ua}\""
            )

    scan_start_utc = datetime(2026, 6, 15, 14, 0, 0, tzinfo=TZ_UTC)
    scan_dt_p8 = scan_start_utc.astimezone(TZ_P8)
    for i, scan_path in enumerate(SCAN_PATHS):
        scan_req_dt = scan_dt_p8 + timedelta(seconds=i * 12 + random.randint(0, 5))
        lines.append(
            f'{ATTACKER_IP_SCAN} [{_gateway_ts(scan_req_dt)}] '
            f'"GET {scan_path} HTTP/1.1" 404 0 {round(random.uniform(0.001, 0.01), 3)} '
            f'"python-requests/2.28.0"'
        )

    fpath = os.path.join(output_dir, "gateway_access.log")
    with open(fpath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return fpath


def generate_app_log(output_dir: str) -> str:
    random.seed(SEED + 1)
    lines: List[str] = []
    start = datetime(2026, 6, 15, 0, 0, 0, tzinfo=TZ_P8)

    for minute in range(0, 24 * 60):
        hour = minute // 60
        dt = start + timedelta(minutes=minute)

        if 8 <= hour < 20:
            entry_count = random.randint(1, 3)
        else:
            entry_count = random.randint(0, 1)

        is_error_period = (hour == 14 and dt.minute < 15)

        for _ in range(entry_count):
            seconds_in_minute = random.randint(0, 59)
            entry_dt = dt + timedelta(seconds=seconds_in_minute)
            module = random.choice(MODULES)

            if is_error_period and random.random() < 0.25:
                level = "ERROR"
                msg_template = random.choice(STACK_TRACES)
                main_msg = msg_template[0]
                stack = msg_template[1]
                lines.append(f"{_app_ts(entry_dt)} ERROR [{module}] {main_msg}")
                for stack_line in stack.split("\n"):
                    lines.append(stack_line)
            elif random.random() < 0.05:
                level = "WARN"
                msg = random.choice([
                    "High memory usage detected",
                    "Slow query response",
                    "Retry attempt for external service",
                    "Cache miss rate elevated",
                ])
                lines.append(f"{_app_ts(entry_dt)} WARN  [{module}] {msg}")
            else:
                level = "INFO"
                msg = random.choice([
                    "Request processed successfully",
                    "User session started",
                    "Cache hit for query",
                    "Background job completed",
                    "Health check passed",
                ])
                lines.append(f"{_app_ts(entry_dt)} INFO  [{module}] {msg}")

    fpath = os.path.join(output_dir, "app_service.log")
    with open(fpath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return fpath


def generate_login_log(output_dir: str) -> str:
    random.seed(SEED + 2)
    lines: List[str] = []
    start_utc = datetime(2026, 6, 15, 0, 0, 0, tzinfo=TZ_UTC)

    for minute in range(0, 24 * 60):
        hour_utc = minute // 60
        dt_utc = start_utc + timedelta(minutes=minute)
        hour_local = hour_utc + 8

        if 8 <= hour_local < 20:
            login_chance = 0.3
        else:
            login_chance = 0.05

        if random.random() < login_chance:
            user = random.choice(USERS)
            ip = random.choice(NORMAL_IPS)
            seconds_in_minute = random.randint(0, 59)
            login_dt_utc = dt_utc + timedelta(seconds=seconds_in_minute)

            if random.random() < 0.1:
                status = "failure"
                reason = "bad_password"
            else:
                status = "success"
                reason = ""

            ts_str = _login_ts(login_dt_utc)
            line = f"{ts_str} LOGIN user={user} src_ip={ip} status={status}"
            if reason:
                line += f" reason={reason}"
            lines.append(line)

    burst_start_utc = datetime(2026, 6, 15, 10, 0, 0, tzinfo=TZ_UTC)
    for i in range(20):
        burst_dt = burst_start_utc + timedelta(seconds=i * 15 + random.randint(0, 5))
        ts_str = _login_ts(burst_dt)
        lines.append(
            f"{ts_str} LOGIN user=admin src_ip={ATTACKER_IP_LOGIN} "
            f"status=failure reason=bad_password"
        )

    fpath = os.path.join(output_dir, "login_audit.log")
    with open(fpath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return fpath


def generate_resource_log(output_dir: str) -> str:
    random.seed(SEED + 3)
    lines: List[str] = []
    start_utc = datetime(2026, 6, 15, 0, 0, 0, tzinfo=TZ_UTC)

    is_error_period_utc_start = datetime(2026, 6, 15, 6, 0, 0, tzinfo=TZ_UTC)
    is_error_period_utc_end = datetime(2026, 6, 15, 6, 15, 0, tzinfo=TZ_UTC)

    for minute in range(0, 24 * 60):
        dt_utc = start_utc + timedelta(minutes=minute)

        cpu = round(random.uniform(20, 60), 1)
        mem = round(random.uniform(40, 70), 1)
        disk = round(random.uniform(50, 80), 1)

        if is_error_period_utc_start <= dt_utc < is_error_period_utc_end:
            cpu = round(random.uniform(80, 99), 1)
            mem = round(random.uniform(85, 98), 1)

        lines.append(f"{_resource_ts(dt_utc)} cpu={cpu} mem={mem} disk={disk}")

    fpath = os.path.join(output_dir, "resource_metrics.log")
    with open(fpath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return fpath


def generate_answer_key(output_dir: str) -> str:
    answer_key = {
        "generated_at": datetime.now(TZ_UTC).isoformat(),
        "time_range": {
            "start_local": "2026-06-15T00:00:00+08:00",
            "end_local": "2026-06-15T23:59:59+08:00",
            "start_utc": "2026-06-14T16:00:00Z",
            "end_utc": "2026-06-15T15:59:59Z",
        },
        "timezone_notes": {
            "gateway_logs": "+0800 (Asia/Shanghai)",
            "app_logs": "+0800 (Asia/Shanghai)",
            "login_logs": "+0900 (Asia/Tokyo) - one hour ahead, tests timezone alignment",
            "resource_logs": "+0000 (UTC)",
        },
        "expected_anomalies": [
            {
                "id": 1,
                "type": "slow_request",
                "time_range_utc": ["2026-06-15T02:00:00Z", "2026-06-15T02:20:00Z"],
                "time_range_local": ["2026-06-15T10:00:00+08:00", "2026-06-15T10:20:00+08:00"],
                "description": "Slow requests on /api/orders, p95 2-5s (normal <0.5s)",
                "expected_severity": "high or critical",
                "expected_evidence": {
                    "path": "/api/orders",
                    "p95_range_seconds": [2.0, 5.0],
                    "normal_p95_seconds": [0.01, 0.5],
                },
            },
            {
                "id": 2,
                "type": "error_spike",
                "time_range_utc": ["2026-06-15T06:00:00Z", "2026-06-15T06:15:00Z"],
                "time_range_local": ["2026-06-15T14:00:00+08:00", "2026-06-15T14:15:00+08:00"],
                "description": "5xx error burst at ~30% rate, app ERROR logs with stack traces",
                "expected_severity": "critical",
                "expected_evidence": {
                    "5xx_rate": "~0.30",
                    "normal_5xx_rate": "~0.01",
                    "app_error_stack_traces": True,
                    "resource_cpu_spike": "80-99%",
                    "resource_mem_spike": "85-98%",
                },
            },
            {
                "id": 3,
                "type": "login_failure_burst",
                "time_range_utc": ["2026-06-15T10:00:00Z", "2026-06-15T10:05:00Z"],
                "time_range_local": ["2026-06-15T18:00:00+08:00 / 19:00:00+09:00", "2026-06-15T18:05:00+08:00 / 19:05:00+09:00"],
                "description": "20 login failures from 10.0.0.99 targeting admin user",
                "expected_severity": "high or critical",
                "expected_evidence": {
                    "src_ip": "10.0.0.99",
                    "failure_count": 20,
                    "targeted_user": "admin",
                    "login_log_timezone": "+0900",
                },
            },
            {
                "id": 4,
                "type": "scan_404",
                "time_range_utc": ["2026-06-15T14:00:00Z", "2026-06-15T14:10:00Z"],
                "time_range_local": ["2026-06-15T22:00:00+08:00", "2026-06-15T22:10:00+08:00"],
                "description": "50 unique 404 paths from 10.0.0.88, scanning for admin panels and configs",
                "expected_severity": "critical",
                "expected_evidence": {
                    "src_ip": "10.0.0.88",
                    "unique_404_paths": 50,
                    "total_404_requests": 50,
                    "user_agent": "python-requests/2.28.0",
                },
            },
        ],
        "expected_sessions": {
            "notes": (
                "Sessions split by 30-min gap. Normal IPs should produce several sessions "
                "during the day. Scanner IP 10.0.0.88 should produce one session during "
                "22:00-22:10 +0800. Login attacker 10.0.0.99 won't appear in gateway sessions "
                "(only in login logs)."
            ),
            "notable_ips": {
                "10.0.0.88": "Single short session during scan period",
            },
        },
        "multi_line_stack_trace_test": {
            "description": (
                "App ERROR entries during 14:00-14:15 +0800 should have multi-line stack traces. "
                "The parser must merge these into single records, not split them."
            ),
            "expected_error_count_approx": "Varies, but each ERROR should be ONE record with stack_trace field populated",
        },
    }

    fpath = os.path.join(output_dir, "answer_key.json")
    with open(fpath, "w", encoding="utf-8") as f:
        json.dump(answer_key, f, indent=2, ensure_ascii=False)
    return fpath


def generate_all(output_dir: str) -> Dict[str, str]:
    os.makedirs(output_dir, exist_ok=True)
    paths = {}
    paths["gateway"] = generate_gateway_log(output_dir)
    paths["app"] = generate_app_log(output_dir)
    paths["login"] = generate_login_log(output_dir)
    paths["resource"] = generate_resource_log(output_dir)
    paths["answer_key"] = generate_answer_key(output_dir)
    return paths
