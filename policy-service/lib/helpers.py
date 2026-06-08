import hashlib
from datetime import datetime, timezone


def get_extension(filename):
    return filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''


def sha256_hash(data):
    return hashlib.sha256(data).hexdigest() if isinstance(data, bytes) else hashlib.sha256(data.encode()).hexdigest()


def parse_iso_timestamp(ts):
    try:
        return datetime.fromisoformat(ts.replace('Z', '+00:00'))
    except Exception:
        return None


def now_utc():
    return datetime.now(timezone.utc)
