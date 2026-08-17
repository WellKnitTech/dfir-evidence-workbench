"""In-process metrics registry exposed as Prometheus text format at /metrics.

Stdlib-only counters/histograms; no client library dependency. Thread-safety is
not required (single-process asyncio event loop; FastAPI/uvicorn workers each
get their own registry, which is correct for a per-instance /metrics scrape).
"""

from __future__ import annotations

import threading
from collections import defaultdict

_lock = threading.Lock()
_counters: dict[tuple[str, tuple[tuple[str, str], ...]], float] = defaultdict(float)
_histograms: dict[tuple[str, tuple[tuple[str, str], ...]], list[float]] = defaultdict(list)

_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10)


def _key(labels: dict[str, str] | None) -> tuple[tuple[str, str], ...]:
    return tuple(sorted((labels or {}).items()))


def inc_counter(name: str, labels: dict[str, str] | None = None, value: float = 1.0) -> None:
    with _lock:
        _counters[(name, _key(labels))] += value


def observe_histogram(name: str, value: float, labels: dict[str, str] | None = None) -> None:
    with _lock:
        _histograms[(name, _key(labels))].append(value)


def reset() -> None:
    """Test helper: clear all recorded series."""
    with _lock:
        _counters.clear()
        _histograms.clear()


def counter_total(name: str, label_filter: dict[str, str] | None = None) -> float:
    """Sum a counter's value across all series matching an optional label subset.

    Used by alerts.py to evaluate rule conditions against live metric state
    without exposing the internal series dict.
    """
    with _lock:
        total = 0.0
        for (n, labels), value in _counters.items():
            if n != name:
                continue
            label_dict = dict(labels)
            if label_filter and not all(label_dict.get(k) == v for k, v in label_filter.items()):
                continue
            total += value
        return total


def _fmt_labels(labels: tuple[tuple[str, str], ...]) -> str:
    if not labels:
        return ""
    return "{" + ",".join(f'{k}="{v}"' for k, v in labels) + "}"


def render_prometheus_text() -> str:
    lines: list[str] = []
    with _lock:
        counter_names = sorted({name for name, _ in _counters})
        for name in counter_names:
            lines.append(f"# TYPE {name} counter")
            for (n, labels), value in sorted(_counters.items()):
                if n == name:
                    lines.append(f"{name}{_fmt_labels(labels)} {value}")
        hist_names = sorted({name for name, _ in _histograms})
        for name in hist_names:
            lines.append(f"# TYPE {name} histogram")
            for (n, labels), values in sorted(_histograms.items()):
                if n != name:
                    continue
                sorted_vals = sorted(values)
                total = len(sorted_vals)
                cumulative = 0
                for bound in _BUCKETS:
                    cumulative = sum(1 for v in sorted_vals if v <= bound)
                    le_labels = labels + (("le", str(bound)),)
                    lines.append(f"{name}_bucket{_fmt_labels(le_labels)} {cumulative}")
                inf_labels = labels + (("le", "+Inf"),)
                lines.append(f"{name}_bucket{_fmt_labels(inf_labels)} {total}")
                lines.append(f"{name}_sum{_fmt_labels(labels)} {sum(sorted_vals)}")
                lines.append(f"{name}_count{_fmt_labels(labels)} {total}")
    return "\n".join(lines) + "\n" if lines else ""
