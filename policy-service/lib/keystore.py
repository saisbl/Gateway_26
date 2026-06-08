from .helpers import parse_iso_timestamp, now_utc


API_KEYS = {
    'demo-key-123': {
        'tenant': 'tenant-1', 'endpoints': ['/infer', '/upload'],
        'secret': 'sk-demo-secret-abc-123',
        'created_at': '2026-01-01T00:00:00Z', 'expires_at': '2027-01-01T00:00:00Z',
        'is_active': True, 'key_type': 'production', 'daily_limit': 10000,
    },
    'test-key-456': {
        'tenant': 'tenant-2', 'endpoints': ['/infer'],
        'secret': 'sk-test-secret-def-456',
        'created_at': '2026-01-01T00:00:00Z', 'expires_at': '2026-06-01T00:00:00Z',
        'is_active': True, 'key_type': 'development', 'daily_limit': 500,
    },
    'expired-key-789': {
        'tenant': 'tenant-3', 'endpoints': ['/infer'],
        'secret': 'sk-expired-secret-789',
        'created_at': '2025-01-01T00:00:00Z', 'expires_at': '2025-06-01T00:00:00Z',
        'is_active': True, 'key_type': 'development', 'daily_limit': 100,
    },
    'inactive-key-000': {
        'tenant': 'tenant-4', 'endpoints': ['/infer'],
        'secret': 'sk-inactive-secret-000',
        'created_at': '2026-01-01T00:00:00Z', 'expires_at': '2027-01-01T00:00:00Z',
        'is_active': False, 'key_type': 'development', 'daily_limit': 100,
    },
}


def validate_api_key(api_key):
    if not api_key or api_key not in API_KEYS:
        return False, 'invalid_api_key', 'Invalid or missing API key'
    key_info = API_KEYS[api_key]
    if not key_info['is_active']:
        return False, 'key_inactive', 'API key is deactivated'
    expires = parse_iso_timestamp(key_info['expires_at'])
    if expires and now_utc() > expires:
        return False, 'key_expired', f"API key expired at {key_info['expires_at']}"
    return True, None, None
