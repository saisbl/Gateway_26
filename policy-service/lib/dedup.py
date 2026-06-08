import time
from collections import defaultdict

from .config import FILE_HASH_TTL_SECONDS


file_hashes = defaultdict(dict)


def check_file_hash(tenant, file_hash):
    if not file_hash:
        return True, None, None
    now = time.time()
    store = file_hashes[tenant]
    expired = [h for h, t in store.items() if now - t > FILE_HASH_TTL_SECONDS]
    for h in expired:
        del store[h]
    if file_hash in store:
        return False, 'duplicate_file', 'This exact file was already processed recently (duplicate detected)'
    store[file_hash] = now
    return True, None, None


def check_file_hash_only(tenant, file_hash):
    store = file_hashes.get(tenant, {})
    return file_hash in store
