import time
import threading


decode_store = {}
decode_lock = threading.Lock()
_next_batch = [0]


def clean_decode_store():
    now = time.time()
    with decode_lock:
        expire = [bid for bid, (ts, _) in decode_store.items() if now - ts > 300]
        for bid in expire:
            del decode_store[bid]


def put_decode_batch(files_bytes):
    with decode_lock:
        bid = _next_batch[0]
        _next_batch[0] += 1
        decode_store[bid] = (time.time(), files_bytes)
    return bid


def get_decode_file(batch_id, idx):
    with decode_lock:
        entry = decode_store.get(batch_id)
        if not entry:
            return None
        _, files = entry
        if idx < 0 or idx >= len(files):
            return None
        return files[idx]
