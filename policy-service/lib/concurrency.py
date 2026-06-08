import time
from collections import defaultdict

from .config import MAX_CONCURRENT_PER_TENANT, CONCURRENCY_TIMEOUT_SECONDS


concurrency_slots = defaultdict(list)


def check_concurrency(tenant):
    now = time.time()
    slots = concurrency_slots[tenant]
    slots[:] = [ts for ts in slots if now - ts < CONCURRENCY_TIMEOUT_SECONDS]
    if len(slots) >= MAX_CONCURRENT_PER_TENANT:
        return False, 'concurrency_limit_exceeded', f"Concurrent request limit reached: {MAX_CONCURRENT_PER_TENANT}"
    slots.append(now)
    return True, None, None


def release_concurrency(tenant):
    slots = concurrency_slots.get(tenant, [])
    if slots:
        slots.pop(0)
