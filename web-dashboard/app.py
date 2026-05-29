from flask import Flask, render_template, request, jsonify
import requests
import os
import time
import uuid
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')

session = requests.Session()
adapter = requests.adapters.HTTPAdapter(pool_connections=50, pool_maxsize=50, max_retries=3)
session.mount('http://', adapter)
session.mount('https://', adapter)

GPU_SERVICE_URL = "http://127.0.0.1:5001"
POLICY_SERVICE_URL = "http://127.0.0.1:5002"
SCANNER_SERVICE_URL = "http://127.0.0.1:5003"

jobs = {}
jobs_lock = threading.Lock()

CHUNK_SIZE = 250
MAX_WORKERS = 50

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

# ── Helpers ──────────────────────────────────────────────────

def sha256_file(filepath):
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()

def save_uploaded_files(files):
    session_id = str(uuid.uuid4())
    session_dir = os.path.join(app.config['UPLOAD_FOLDER'], session_id)
    os.makedirs(session_dir, exist_ok=True)
    saved = []
    for f in files:
        if not f.filename:
            continue
        filepath = os.path.join(session_dir, f.filename)
        f.save(filepath)
        saved.append({
            'filename': f.filename,
            'filepath': filepath,
            'file_size': os.path.getsize(filepath),
            'file_hash': sha256_file(filepath),
        })
    return session_id, session_dir, saved

def cleanup_session(session_dir):
    import shutil
    if os.path.exists(session_dir):
        shutil.rmtree(session_dir, ignore_errors=True)

# ── Chunked Pipeline ─────────────────────────────────────────

def process_chunk(chunk, api_key, client_ip):
    results = {}

    auth_payload = {
        'api_key': api_key,
        'endpoint': '/infer',
        'client_ip': client_ip,
        'files': [{'filename': f['filename'], 'file_size': f['file_size'], 'file_hash': f['file_hash']} for f in chunk],
    }
    auth_start = time.time()
    try:
        auth_resp = session.post(f"{POLICY_SERVICE_URL}/batch-authorize", json=auth_payload, timeout=15)
        auth_data = auth_resp.json()
    except Exception as e:
        for f in chunk:
            results[f['filename']] = {'status': 'error', 'step': 'authorization', 'error': f'Auth failed: {e}', 'latency': {}}
        return results, True
    auth_wall_ms = (time.time() - auth_start) * 1000

    if not auth_data.get('allowed'):
        for i, f in enumerate(chunk):
            fr = auth_data.get('files', [{}])[i] if i < len(auth_data.get('files', [])) else {}
            results[f['filename']] = {
                'status': 'rejected', 'step': 'authorization',
                'reason': fr.get('reason', auth_data.get('reason', 'unknown')),
                'message': fr.get('message', auth_data.get('message', '')),
                'authorization': {'allowed': False, 'reason': fr.get('reason', auth_data.get('reason', 'unknown'))},
                'latency': {},
            }
        return results, True

    auth_map = {}
    for fr in auth_data.get('files', []):
        idx = fr.get('index')
        if idx is not None and idx < len(chunk):
            auth_map[chunk[idx]['filename']] = fr

    allowed_files = [f for f in chunk if auth_map.get(f['filename'], {}).get('allowed')]

    scan_map = {}
    scan_wall_ms = 0
    if allowed_files:
        scan_start = time.time()
        try:
            scan_files = []
            for f in allowed_files:
                scan_files.append(('file', (f['filename'], open(f['filepath'], 'rb'), 'application/octet-stream')))
            scan_resp = session.post(f"{SCANNER_SERVICE_URL}/scan-batch", files=scan_files, timeout=30)
            scan_data = scan_resp.json()
            for sr in scan_data.get('results', []):
                scan_map[sr.get('filename', '')] = sr
            for _, _, fh in scan_files:
                fh.close()
        except Exception as e:
            err_msg = f"{type(e).__name__}: {str(e)}"
            for f in allowed_files:
                scan_map[f['filename']] = {'allowed': False, 'reason': 'scan_error', 'message': err_msg}
        finally:
            scan_wall_ms = (time.time() - scan_start) * 1000

    scan_passed = [f for f in allowed_files if scan_map.get(f['filename'], {}).get('allowed')]

    gpu_results = {}
    if scan_passed:
        with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(scan_passed))) as executor:
            def infer_file(f):
                start = time.time()
                try:
                    with open(f['filepath'], 'rb') as fh:
                        resp = session.post(f"{GPU_SERVICE_URL}/infer", files={'file': fh}, timeout=15)
                    latency = (time.time() - start) * 1000
                    return f['filename'], {
                        'status': 'success' if resp.status_code == 200 else 'error',
                        'response': resp.json(),
                        'latency_ms': round(latency, 2),
                    }
                except Exception as e:
                    latency = (time.time() - start) * 1000
                    return f['filename'], {'status': 'error', 'error': str(e), 'latency_ms': round(latency, 2)}
            futures = {executor.submit(infer_file, f): f for f in scan_passed}
            for future in as_completed(futures):
                name, result = future.result()
                gpu_results[name] = result

    for f in chunk:
        fn = f['filename']
        ai = auth_map.get(fn, {})
        si = scan_map.get(fn, {})
        gi = gpu_results.get(fn, {})

        lat = {}
        if ai.get('allowed'):
            lat['authorization_ms'] = round(auth_wall_ms, 2)
        if si.get('scan_time_ms'):
            lat['scanning_ms'] = round(scan_wall_ms, 2)
        if gi.get('latency_ms'):
            lat['inference_ms'] = round(gi['latency_ms'], 2)
        if 'authorization_ms' in lat or 'scanning_ms' in lat:
            lat['total_security_ms'] = round(lat.get('authorization_ms', 0) + lat.get('scanning_ms', 0), 2)
        if 'authorization_ms' in lat or 'scanning_ms' in lat or 'inference_ms' in lat:
            lat['total_processing_ms'] = round(lat.get('authorization_ms', 0) + lat.get('scanning_ms', 0) + lat.get('inference_ms', 0), 2)

        status = 'success' if gi.get('status') == 'success' else \
                 ('rejected' if not ai.get('allowed') or not si.get('allowed') else \
                  'error' if gi.get('status') == 'error' else 'pending')

        result = {
            'filename': fn, 'status': status, 'latency': lat,
            'authorization': ai, 'scanning': si, 'inference': gi.get('response') if gi.get('response') else None,
        }
        if status == 'rejected':
            if not ai.get('allowed'):
                result['step'] = 'authorization'
                result['reason'] = ai.get('reason', auth_data.get('reason', 'unknown'))
                result['message'] = ai.get('message', auth_data.get('message', ''))
            elif not si.get('allowed'):
                result['step'] = 'scanning'
                result['reason'] = si.get('reason', 'unknown')
                result['message'] = si.get('message', '')
        elif status == 'error' and not gi.get('response'):
            result['error'] = gi.get('error', 'GPU processing failed')

        results[fn] = result

    return results, False

# ── Job Worker ───────────────────────────────────────────────

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
    cleanup_session(session_dir)

    with jobs_lock:
        jobs[job_id]['status'] = 'completed'
        jobs[job_id]['results'] = all_results
        jobs[job_id]['total_time_ms'] = round(total_time, 2)

# ── Routes ───────────────────────────────────────────────────

@app.route('/upload', methods=['POST'])
def upload_file():
    files = request.files.getlist('files')
    files = [f for f in files if f.filename]
    if not files:
        return jsonify({'error': 'No files provided'}), 400

    api_key = request.form.get('api_key', 'demo-key-123')

    client_ip = request.remote_addr
    if len(files) < 50:
        total_start = time.time()
        results_raw = {}
        with ThreadPoolExecutor(max_workers=min(50, len(files))) as executor:
            def process_one(f):
                fn = f.filename
                fp = os.path.join(app.config['UPLOAD_FOLDER'], fn)
                f.save(fp)
                try:
                    size = os.path.getsize(fp)
                    auth_start = time.time()
                    auth_r = session.post(f"{POLICY_SERVICE_URL}/authorize", json={
                        'api_key': api_key, 'endpoint': '/infer', 'file_size': size, 'client_ip': client_ip,
                    }, timeout=10).json()
                    auth_ms = (time.time() - auth_start) * 1000
                    if not auth_r.get('allowed'):
                        os.remove(fp)
                        return fn, {'filename': fn, 'status': 'rejected', 'step': 'authorization', 'reason': auth_r.get('reason'),
                                    'message': auth_r.get('message'), 'authorization': auth_r, 'latency': {}}
                    scan_start = time.time()
                    with open(fp, 'rb') as fh:
                        scan_r = session.post(f"{SCANNER_SERVICE_URL}/scan", files={'file': fh}, timeout=10).json()
                    scan_ms = (time.time() - scan_start) * 1000
                    if not scan_r.get('allowed'):
                        os.remove(fp)
                        return fn, {'filename': fn, 'status': 'rejected', 'step': 'scanning', 'reason': scan_r.get('reason'),
                                    'message': scan_r.get('message'), 'scanning': scan_r, 'latency': {}}
                    infer_start = time.time()
                    with open(fp, 'rb') as fh:
                        gpu_r = session.post(f"{GPU_SERVICE_URL}/infer", files={'file': fh}, timeout=10).json()
                    infer_ms = (time.time() - infer_start) * 1000
                    os.remove(fp)
                    a_ms = round(auth_ms, 2)
                    s_ms = round(scan_ms, 2)
                    g_ms = round(infer_ms, 2)
                    return fn, {
                        'filename': fn, 'status': 'success', 'authorization': auth_r, 'scanning': scan_r, 'inference': gpu_r,
                        'latency': {
                            'authorization_ms': a_ms,
                            'scanning_ms': s_ms,
                            'inference_ms': g_ms,
                            'total_security_ms': round(a_ms + s_ms, 2),
                            'total_processing_ms': round(a_ms + s_ms + g_ms, 2),
                        },
                    }
                except Exception as e:
                    if os.path.exists(fp): os.remove(fp)
                    return fn, {'filename': fn, 'status': 'error', 'error': str(e)}
            futures = {executor.submit(process_one, f): f for f in files}
            for future in as_completed(futures):
                fn, result = future.result()
                results_raw[fn] = result
        results = list(results_raw.values())
        total_time = (time.time() - total_start) * 1000
        return jsonify({
            'status': 'completed', 'total_files': len(files),
            'successful': sum(1 for r in results if r['status'] == 'success'),
            'failed': sum(1 for r in results if r['status'] in ('rejected', 'error')),
            'total_processing_time_ms': round(total_time, 2), 'results': results,
        })
    else:
        return redirect_to_large(files, api_key, request.remote_addr)


@app.route('/upload-large', methods=['POST'])
def upload_large():
    files = request.files.getlist('files')
    files = [f for f in files if f.filename]
    if not files:
        return jsonify({'error': 'No files provided'}), 400
    api_key = request.form.get('api_key', 'demo-key-123')
    return redirect_to_large(files, api_key, request.remote_addr)


def redirect_to_large(files, api_key, client_ip):
    session_id, session_dir, saved_files = save_uploaded_files(files)
    job_id = session_id
    with jobs_lock:
        jobs[job_id] = {
            'id': job_id, 'status': 'queued', 'total': len(saved_files),
            'processed': 0, 'passed': 0, 'rejected': 0, 'errors': 0,
            'progress_pct': 0, 'chunk_time_ms': 0, 'total_time_ms': 0, 'results': None,
        }
    thread = threading.Thread(target=run_job, args=(job_id, session_dir, saved_files, api_key, client_ip), daemon=True)
    thread.start()
    return jsonify({'job_id': job_id, 'status': 'queued', 'total_files': len(saved_files),
                    'message': 'Upload accepted. Poll /job-status/' + job_id + ' for progress.'}), 202


@app.route('/job-status/<job_id>', methods=['GET'])
def job_status(job_id):
    with jobs_lock:
        j = jobs.get(job_id)
    if not j:
        return jsonify({'error': 'Job not found'}), 404
    return jsonify({
        'job_id': job_id, 'status': j['status'], 'total_files': j['total'],
        'processed': j['processed'], 'passed': j['passed'], 'rejected': j['rejected'],
        'errors': j['errors'], 'progress_pct': j['progress_pct'],
        'chunk_time_ms': j['chunk_time_ms'], 'total_time_ms': j['total_time_ms'],
    })


@app.route('/job-result/<job_id>', methods=['GET'])
def job_result(job_id):
    with jobs_lock:
        j = jobs.get(job_id)
    if not j:
        return jsonify({'error': 'Job not found'}), 404
    if j['status'] != 'completed':
        return jsonify({'error': 'Job not yet completed', 'status': j['status'], 'progress_pct': j['progress_pct']}), 200
    results = j.get('results', [])
    return jsonify({
        'job_id': job_id, 'status': 'completed', 'total_files': j['total'],
        'successful': j['passed'], 'failed': j['rejected'] + j['errors'],
        'total_processing_time_ms': j['total_time_ms'], 'results': results,
    })


@app.route('/health')
def health():
    services = {
        'gpu_service': f"{GPU_SERVICE_URL}/health",
        'policy_service': f"{POLICY_SERVICE_URL}/health",
        'scanner_service': f"{SCANNER_SERVICE_URL}/health",
    }
    results = {}
    for name, url in services.items():
        try:
            r = requests.get(url, timeout=2)
            results[name] = {'status': 'healthy' if r.status_code == 200 else 'unhealthy', 'response': r.json()}
        except Exception as e:
            results[name] = {'status': 'unhealthy', 'error': str(e)}
    return jsonify(results)


if __name__ == '__main__':
    print("Starting Web Dashboard...")
    print("Open http://127.0.0.1:8080 in your browser")
    app.run(host='0.0.0.0', port=8080, debug=True)
