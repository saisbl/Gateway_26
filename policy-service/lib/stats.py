from collections import defaultdict

daily_quotas = defaultdict(int)
last_day_reset = None

stats = {
    'total_authorized': 0,
    'total_rejected': 0,
    'total_auth_time_ms': 0.0,
}


def check_daily_quota(tenant):
    global last_day_reset
    from .helpers import now_utc
    from .keystore import API_KEYS
    from .config import DAILY_QUOTA_DEFAULT

    current_day = now_utc().strftime('%Y%m%d')
    if last_day_reset != current_day:
        daily_quotas.clear()
        last_day_reset = current_day
    quota_key = f"{tenant}:{current_day}"
    daily = daily_quotas[quota_key] + 1
    daily_quotas[quota_key] = daily
    limit = API_KEYS.get(tenant, {}).get('daily_limit', DAILY_QUOTA_DEFAULT) if tenant in API_KEYS else DAILY_QUOTA_DEFAULT
    if daily > limit:
        return False, 'daily_quota_exceeded', f"Daily quota exceeded: {limit} requests"
    return True, None, None
