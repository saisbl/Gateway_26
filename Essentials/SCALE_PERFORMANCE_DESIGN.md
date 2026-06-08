# Scale & Performance Design

## Current Performance

| Metric | 12 files (50x50 PNG) |
|--------|---------------------|
| Wall time | ~650ms |
| Per-file total | ~450ms |
| Per-file auth | ~30ms |
| Per-file sanitize | ~50ms |
| Per-file scan | ~215ms |
| Per-file infer | ~150ms |
| Throughput | ~18 files/sec |

**All 12 files processed concurrently** via ThreadPoolExecutor (50 workers). The architecture is I/O-bound for auth/scan/infer, but **CPU-bound for stego detection**.

---

## Bottleneck Analysis

### 1. Flask Dev Server (Single-Process, GIL-bound)

| Issue | Impact |
|-------|--------|
| Flask `threaded=True` creates threads per-request | Unbounded thread growth under load |
| No request queue | OS socket backlog only |
| Not production-grade | Known to hang under concurrent load |

**Fix**: Replace with Waitress — fixed thread pool, proper queueing, production track record.

### 2. Stego Detection Holds the GIL

`extract_lsb_texts()` loops over 500K+ pixels in pure Python. CPython's GIL means only **one** stego detection runs at a time even with 50 concurrent workers.

With 12 concurrent files: stego for file A blocks files B-L from making progress on scan/infer. This is why `scanning_ms` (~215ms) is 10x the actual scan time (21ms) — the scan request is waiting behind stego threads contending for the GIL.

**Fix**: Move CPU-heavy stego detection to `ProcessPoolExecutor`. Each process has its own GIL, enabling true parallelism.

### 3. Inter-Service HTTP Overhead

Each file triggers 4 HTTP calls (auth → sanitize → scan → infer). 12 files = 48 HTTP round-trips. Each has TCP handshake, header parsing, body transfer.

All are on localhost so latency is low (~1-5ms per hop), but this doesn't scale horizontally without service discovery.

**Fix**: Keep connection pool (already 50 persistent connections). Long-term: gRPC multiplexing.

### 4. In-Memory State

Rate limit counters, dedup store, concurrency slots — all reset on service restart. Fine for dev, unacceptable for production.

**Fix**: SQLite for critical state (API keys, rate limits, dedup).

---

## Recommended Changes (Prioritized)

### Priority 1 — Replace Flask with Waitress

```python
from waitress import serve
serve(app, host='0.0.0.0', port=5003, threads=50)
```

| Before (Flask) | After (Waitress) |
|----------------|------------------|
| Thread per request (unbounded) | Fixed 50-thread pool |
| No queue | Internal queue + backlog |
| OS socket backlog only | Configurable queue depth |
| Hangs under load | Production-proven |

**Apply to all 4 services** (scanner, policy, dashboard, mock-gpu).

### Priority 2 — ProcessPoolExecutor for Stego

```python
# scanner-service/engines/steganography.py
import concurrent.futures
import atexit

_stego_pool = concurrent.futures.ProcessPoolExecutor(max_workers=2)

@atexit.register
def _close_pool():
    _stego_pool.shutdown(wait=False)

def detect_stego_on_bytes_async(data, fn, timeout=30):
    """Offload CPU-bound stego detection to a separate process."""
    return _stego_pool.submit(detect_stego_on_bytes, data, fn).result(timeout=timeout)
```

In `/sanitize` route, replace:
```python
stego = _detect_stego_on_bytes(data, fn)
```
with:
```python
stego = detect_stego_on_bytes_async(data, fn)
```

| Metric | Inline (current) | ProcessPool (2 workers) |
|--------|-----------------|------------------------|
| Stego per file (800x600) | ~330ms | ~330ms + ~5ms pickle |
| 12 files concurrent | ~2s wall (GIL serialized) | ~0.5-1s wall |
| Throughput (12 files) | ~18 files/sec | ~30+ files/sec |
| Additional memory | 0 | ~100MB per worker process |

### Priority 3 — Lazy Stego Detection (Optional)

Run a fast 2-pass heuristic first:
1. **Quick check** (~5ms): entropy of LSB plane, chi-square on sampled bytes
2. Only run full LSB extraction if heuristic flags suspicion

Saves 300-1000ms per clean file at the cost of a tiny false-negative window for sophisticated stego.

### Priority 4 — Circuit Breakers

Prevents one slow/crashing service from occupying all 50 workers and cascading failure:

```python
class CircuitBreaker:
    def __init__(self, fail_max=5, reset_timeout=30):
        self.fail_max = fail_max
        self.reset_timeout = reset_timeout
        self.failures = 0
        self.last_failure = 0
        self.state = 'closed'

    def call(self, fn, *args, **kwargs):
        if self.state == 'open':
            if time.time() - self.last_failure > self.reset_timeout:
                self.state = 'half-open'
            else:
                raise CircuitBreakerOpen()
        try:
            result = fn(*args, **kwargs)
            self.failures = 0
            self.state = 'closed'
            return result
        except Exception:
            self.failures += 1
            self.last_failure = time.time()
            if self.failures >= self.fail_max:
                self.state = 'open'
            raise
```

Wrap each inter-service HTTP call (auth, sanitize, scan, infer) with its own breaker.

### Priority 5 — Persistent Storage for Critical State

Switch from in-memory dicts to SQLite:
- **API keys** — survive restart
- **Rate limit counters** — survive restart
- **File hash dedup** — survive restart
- **Concurrency slots** — can be left in-memory (auto-cleaned after 30s)

SQLite is zero-ops, <10ms local queries, no external dependency.

---

## Implementation Plan

### Phase 1 — Immediate
- [ ] Replace Flask with Waitress on all 4 services
- [ ] Add ProcessPoolExecutor for stego detection
- [ ] Verify latency improvement (target: <500ms for 12 files)

### Phase 2 — Near-term
- [ ] Circuit breakers between all service HTTP calls
- [ ] Lazy stego detection (2-pass heuristic)
- [ ] SQLite for API keys, rate limits, dedup store

### Phase 3 — Production Scale
- [ ] Replace inter-service HTTP with gRPC
- [ ] Stateless services behind load balancer
- [ ] Prometheus + Grafana dashboards
- [ ] Containerize (Docker) each service

---

## Summary

The single biggest gain is **ProcessPoolExecutor for stego** (Priority 2) — it directly addresses the GIL contention that inflates wall time under concurrent load. **Waitress** (Priority 1) is a prerequisite for any production deployment but doesn't fix the GIL issue alone. **Circuit breakers** (Priority 4) prevent cascade failures.

For the current workload (dozens to hundreds of files), Priorities 1-2 are sufficient. Priorities 3-5 matter when scaling to thousands of files or running in production.
