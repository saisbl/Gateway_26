from collections import defaultdict

from .config import (MAX_REQUESTS_PER_MINUTE, MAX_REQUESTS_PER_MINUTE_PER_IP,
                     BATCH_REQUESTS_PER_MINUTE)
from .helpers import now_utc


rate_limits = defaultdict(int)
ip_rate_limits = defaultdict(int)
batch_rate_limits = defaultdict(int)


def _get_reset_seconds():
    return max(1, 60 - now_utc().second)


def _set_rate_limit_headers(resp, key_count, key_limit, ip_count, ip_limit):
    remaining = max(0, key_limit - key_count)
    ip_remaining = max(0, ip_limit - ip_count)
    reset = _get_reset_seconds()
    resp.headers['X-RateLimit-Limit'] = str(key_limit)
    resp.headers['X-RateLimit-Remaining'] = str(remaining)
    resp.headers['X-RateLimit-Reset'] = str(reset)
    resp.headers['X-IP-RateLimit-Limit'] = str(ip_limit)
    resp.headers['X-IP-RateLimit-Remaining'] = str(ip_remaining)


def check_rate_limits(api_key, client_ip):
    current_minute = now_utc().strftime('%Y%m%d%H%M')
    rate_key = f"{api_key}:{current_minute}"
    rate_limits[rate_key] += 1
    key_count = rate_limits[rate_key]
    if key_count > MAX_REQUESTS_PER_MINUTE:
        return False, 'rate_limit_exceeded', f"Key rate limit exceeded: {MAX_REQUESTS_PER_MINUTE} req/min", key_count, ip_rate_limits.get(f"{client_ip}:{current_minute}", 0)
    ip_key = f"{client_ip}:{current_minute}"
    ip_rate_limits[ip_key] += 1
    ip_count = ip_rate_limits[ip_key]
    if ip_count > MAX_REQUESTS_PER_MINUTE_PER_IP:
        return False, 'ip_rate_limit_exceeded', f"IP rate limit exceeded: {MAX_REQUESTS_PER_MINUTE_PER_IP} req/min from this IP", key_count, ip_count
    return True, None, None, key_count, ip_count


def check_batch_rate_limit(api_key):
    current_minute = now_utc().strftime('%Y%m%d%H%M')
    key = f"{api_key}:batch:{current_minute}"
    batch_rate_limits[key] += 1
    count = batch_rate_limits[key]
    if count > BATCH_REQUESTS_PER_MINUTE:
        return False, count, BATCH_REQUESTS_PER_MINUTE
    return True, count, BATCH_REQUESTS_PER_MINUTE
