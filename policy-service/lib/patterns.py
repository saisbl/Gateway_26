import time
from collections import defaultdict

from .config import PATTERN_WINDOW, PATTERN_MAX_EVENTS


request_patterns = defaultdict(list)


def track_pattern(api_key, endpoint, client_ip=''):
    now = time.time()
    cutoff = now - PATTERN_WINDOW
    events = request_patterns[api_key]
    events.append((now, endpoint, client_ip))
    while events and events[0][0] < cutoff:
        events.pop(0)
    if len(events) > PATTERN_MAX_EVENTS:
        events[:len(events) - PATTERN_MAX_EVENTS] = []


def get_pattern_summary(api_key):
    now = time.time()
    cutoff = now - PATTERN_WINDOW
    events = [e for e in request_patterns.get(api_key, []) if e[0] > cutoff]
    endpoint_counts = defaultdict(int)
    ip_counts = defaultdict(int)
    interval_sum = 0.0
    for i, (t, ep, ip) in enumerate(events):
        endpoint_counts[ep] += 1
        ip_counts[ip] += 1
        if i > 0:
            interval_sum += t - events[i - 1][0]
    return {
        'total_requests': len(events),
        'endpoint_breakdown': dict(endpoint_counts),
        'unique_ips': len(ip_counts),
        'avg_interval_ms': round((interval_sum / max(len(events) - 1, 1)) * 1000, 1),
    }
