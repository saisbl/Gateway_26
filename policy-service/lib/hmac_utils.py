import time
import hmac
import hashlib

from .config import HMAC_TIMESTAMP_WINDOW_SECONDS
from .keystore import API_KEYS


def verify_hmac(api_key, body_bytes, sig_header, ts_header):
    key_info = API_KEYS.get(api_key)
    if not key_info:
        return False, 'invalid_key_for_hmac'
    secret = key_info.get('secret', '')
    if not ts_header:
        return False, 'missing_timestamp'
    try:
        ts = int(ts_header)
        now_s = int(time.time())
        if abs(now_s - ts) > HMAC_TIMESTAMP_WINDOW_SECONDS:
            return False, 'timestamp_out_of_window'
    except ValueError:
        return False, 'invalid_timestamp'
    msg = body_bytes + str(ts).encode()
    expected = hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()
    if not sig_header:
        return False, 'missing_signature'
    if not hmac.compare_digest(expected, sig_header):
        return False, 'signature_mismatch'
    return True, None
