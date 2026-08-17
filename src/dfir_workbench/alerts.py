"""Alert rule evaluation over the in-process metrics registry.

Small, dependency-free rule engine so alert conditions named in the incident
runbook (docs/observability-and-incident-operations.md) are executable and
testable, not just prose. A real deployment wires these same rules into
Prometheus Alertmanager (rule expressions are given in the runbook); this
module lets synthetic requests prove the *condition logic* is correct without
standing up Alertmanager.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from . import metrics as _metrics

# ponytail: threshold constants live here (not env-configurable) until a real
# Alertmanager rule file replaces this evaluator; upgrade path documented in
# docs/observability-and-incident-operations.md.
AUDIT_WRITE_FAILURE_THRESHOLD = 1
ERROR_RATE_THRESHOLD = 0.05  # 5% of requests returning 5xx


@dataclass(frozen=True)
class AlertResult:
    name: str
    firing: bool
    detail: str


def _audit_sink_degraded() -> AlertResult:
    failures = _metrics.counter_total("audit_write_failures_total")
    firing = failures >= AUDIT_WRITE_FAILURE_THRESHOLD
    return AlertResult("audit_sink_degraded", firing, f"audit_write_failures_total={failures}")


def _elevated_error_rate() -> AlertResult:
    total = 0.0
    errors = 0.0
    with _metrics._lock:  # read-only snapshot; module is the only writer
        for (name, labels), value in _metrics._counters.items():
            if name != "http_requests_total":
                continue
            total += value
            status = dict(labels).get("status", "")
            if status.startswith("5"):
                errors += value
    rate = (errors / total) if total else 0.0
    firing = total > 0 and rate >= ERROR_RATE_THRESHOLD
    return AlertResult("elevated_http_error_rate", firing, f"error_rate={rate:.3f} over {int(total)} requests")


RULES: tuple[Callable[[], AlertResult], ...] = (_audit_sink_degraded, _elevated_error_rate)


def evaluate_all() -> list[AlertResult]:
    """Evaluate every registered rule against current metrics state."""
    return [rule() for rule in RULES]


def firing_alerts() -> list[AlertResult]:
    return [r for r in evaluate_all() if r.firing]
