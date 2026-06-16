from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Any


@dataclass
class LogRecord:
    timestamp: datetime
    source_type: str
    raw_data: Dict[str, Any]


@dataclass
class Session:
    session_id: str
    client_ip: str
    start_time: datetime
    end_time: datetime
    request_count: int
    duration_seconds: float
    status_distribution: Dict[int, int]
    has_error: bool
    requests: List[LogRecord] = field(default_factory=list)


@dataclass
class AnomalyEvent:
    anomaly_type: str
    time_window_start: datetime
    time_window_end: datetime
    severity: str
    evidence: Dict[str, Any]
    description: str


@dataclass
class CorrelatedGroup:
    window_start: datetime
    window_end: datetime
    gateway_records: List[LogRecord] = field(default_factory=list)
    app_records: List[LogRecord] = field(default_factory=list)
    login_records: List[LogRecord] = field(default_factory=list)
    resource_records: List[LogRecord] = field(default_factory=list)


@dataclass
class AuditReport:
    total_requests: int = 0
    error_rate: float = 0.0
    p50_latency: float = 0.0
    p95_latency: float = 0.0
    p99_latency: float = 0.0
    top_paths: List[Dict[str, Any]] = field(default_factory=list)
    top_ips: List[Dict[str, Any]] = field(default_factory=list)
    total_sessions: int = 0
    sessions_with_errors: int = 0
    anomalies: List[AnomalyEvent] = field(default_factory=list)
    correlated_groups: List[CorrelatedGroup] = field(default_factory=list)
    service_stats: Dict[str, Any] = field(default_factory=dict)
