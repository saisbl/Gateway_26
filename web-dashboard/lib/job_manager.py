import time
import threading

from .config import CHUNK_SIZE
from .helpers import cleanup_session
from .pipeline import process_chunk
from .decode_store import put_decode_batch

jobs = {}
jobs_lock = threading.Lock()


def run_job(job_id, session_dir, saved_files, api_key, client_ip):
    chunks = [saved_files[i:i+CHUNK_SIZE] for i in range(0, len(saved_files), CHUNK_SIZE)]
    total = len(saved_files)

    with jobs_lock:
        jobs[job_id]['total'] = total
        jobs[job_id]['status'] = 'processing'

    all_results = []
    start_time = time.time()

    for chunk_idx, chunk in enumerate(chunks):
        chunk_start = time.time()
        chunk_results, _ = process_chunk(chunk, api_key, client_ip)
        chunk_elapsed = (time.time() - chunk_start) * 1000
        all_results.extend(chunk_results.values())

        with jobs_lock:
            j = jobs[job_id]
            j['processed'] = min(j['processed'] + len(chunk), total)
            j['passed'] = sum(1 for r in all_results if r['status'] == 'success')
            j['rejected'] = sum(1 for r in all_results if r['status'] == 'rejected')
            j['errors'] = sum(1 for r in all_results if r['status'] == 'error')
            j['progress_pct'] = round(j['processed'] / total * 100, 1) if total > 0 else 100
            j['chunk_time_ms'] = round(chunk_elapsed, 2)

    total_time = (time.time() - start_time) * 1000

    orig_files = []
    for sf in saved_files:
        try:
            with open(sf['filepath'], 'rb') as _rfh:
                orig_files.append(_rfh.read())
        except Exception:
            orig_files.append(b'')
    decode_bid = put_decode_batch(orig_files)

    cleanup_session(session_dir)

    with jobs_lock:
        jobs[job_id]['status'] = 'completed'
        jobs[job_id]['results'] = all_results
        jobs[job_id]['decode_batch_id'] = decode_bid
        jobs[job_id]['total_time_ms'] = round(total_time, 2)
