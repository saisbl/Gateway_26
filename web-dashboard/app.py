import os
import time
import json
import base64
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import Flask, render_template, request, jsonify

from lib.config import (GPU_SERVICE_URL, POLICY_SERVICE_URL, SCANNER_SERVICE_URL,
                         CHUNK_SIZE, MAX_WORKERS)
from lib.helpers import save_uploaded_files
from lib.decode_store import put_decode_batch, get_decode_file, clean_decode_store
from lib.job_manager import jobs, jobs_lock, run_job

import requests

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')

session = requests.Session()
adapter = requests.adapters.HTTPAdapter(pool_connections=50, pool_maxsize=50, max_retries=3)
session.mount('http://', adapter)
session.mount('https://', adapter)

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def upload_file():
    files = request.files.getlist('files')
    files = [f for f in files if f.filename]
    if not files:
        return jsonify({'error': 'No files provided'}), 400

    api_key = request.form.get('api_key', 'demo-key-123')
    client_ip = request.remote_addr

    if len(files) < 50:
        return _process_sync(files, api_key, client_ip)
    else:
        return _process_async(files, api_key, client_ip)


def _process_sync(files, api_key, client_ip):
    total_start = time.time()
    results_raw = {}
    _orig_lock = threading.Lock()
    _orig_bytes = [None] * len(files)

    with ThreadPoolExecutor(max_workers=min(50, len(files))) as executor:
        def process_one(f, fidx):
            fn = f.filename
            fp = os.path.join(app.config['UPLOAD_FOLDER'], fn)
            f.save(fp)
            try:
                size = os.path.getsize(fp)
                with open(fp, 'rb') as _rbf:
                    _orig_bytes[fidx] = _rbf.read()

                auth_start = time.time()
                auth_r = session.post(f"{POLICY_SERVICE_URL}/authorize", json={
                    'api_key': api_key, 'endpoint': '/infer', 'file_size': size, 'client_ip': client_ip,
                }, timeout=10).json()
                auth_ms = (time.time() - auth_start) * 1000

                if not auth_r.get('allowed'):
                    os.remove(fp)
                    return fn, {'filename': fn, 'status': 'rejected', 'step': 'authorization',
                                'reason': auth_r.get('reason'), 'message': auth_r.get('message'),
                                'authorization': auth_r, 'latency': {}}

                sanitize_start = time.time()
                with open(fp, 'rb') as fh:
                    san_resp = session.post(f"{SCANNER_SERVICE_URL}/sanitize", files={'file': fh}, timeout=10)
                sanitize_ms = (time.time() - sanitize_start) * 1000

                if not san_resp.ok:
                    os.remove(fp)
                    err = san_resp.json() if san_resp.headers.get('Content-Type', '').startswith('application/json') else {'message': 'Sanitization failed'}
                    return fn, {'filename': fn, 'status': 'rejected', 'step': 'sanitization',
                                'reason': err.get('reason', 'sanitize_failed'), 'message': err.get('message', ''),
                                'sanitization': err, 'latency': {}}

                cleaned_bytes = san_resp.content
                stego_flagged = san_resp.headers.get('X-Steganography-Flagged', 'false') == 'true'
                stego_findings = None
                if stego_flagged:
                    stego_reasons = san_resp.headers.get('X-Steganography-Reasons', '').split(',')
                    stego_msgs = _parse_b64_header(san_resp.headers.get('X-Steganography-Messages-B64', ''), [])
                    stego_struct = _parse_b64_header(san_resp.headers.get('X-Steganography-Structural-B64', ''), [])
                    stego_meta = _parse_b64_header(san_resp.headers.get('X-Steganography-Metadata-B64', ''), [])
                    stego_findings = {
                        'flagged': True,
                        'reasons': [r for r in stego_reasons if r],
                        'extracted_messages': stego_msgs,
                        'structural_payloads': stego_struct if isinstance(stego_struct, list) else [],
                        'metadata_findings': stego_meta if isinstance(stego_meta, list) else [],
                    }

                tmp = tempfile.NamedTemporaryFile(delete=False, suffix='_' + fn)
                tmp.write(cleaned_bytes)
                tmp.close()
                sanitized_path = tmp.name

                scan_start = time.time()
                with open(sanitized_path, 'rb') as fh:
                    scan_r = session.post(f"{SCANNER_SERVICE_URL}/scan", files={'file': fh}, timeout=10).json()
                scan_ms = (time.time() - scan_start) * 1000

                if not scan_r.get('allowed'):
                    os.remove(fp)
                    os.unlink(sanitized_path)
                    return fn, {'filename': fn, 'status': 'rejected', 'step': 'scanning',
                                'reason': scan_r.get('reason'), 'message': scan_r.get('message'),
                                'scanning': scan_r, 'latency': {}, 'steganography': stego_findings}

                infer_start = time.time()
                with open(sanitized_path, 'rb') as fh:
                    gpu_r = session.post(f"{GPU_SERVICE_URL}/infer", files={'file': fh}, timeout=10).json()
                infer_ms = (time.time() - infer_start) * 1000

                os.remove(fp)
                os.unlink(sanitized_path)

                a_ms = round(auth_ms, 2)
                sn_ms = round(sanitize_ms, 2)
                s_ms = round(scan_ms, 2)
                g_ms = round(infer_ms, 2)

                return fn, {
                    'filename': fn, 'status': 'success',
                    'authorization': auth_r,
                    'sanitization': {'sanitized': True, 'original_size': size},
                    'scanning': scan_r, 'inference': gpu_r,
                    'steganography': stego_findings,
                    'latency': {
                        'authorization_ms': a_ms, 'sanitization_ms': sn_ms,
                        'scanning_ms': s_ms, 'inference_ms': g_ms,
                        'total_security_ms': round(a_ms + sn_ms + s_ms, 2),
                        'total_processing_ms': round(a_ms + sn_ms + s_ms + g_ms, 2),
                    },
                }
            except Exception as e:
                if os.path.exists(fp):
                    os.remove(fp)
                return fn, {'filename': fn, 'status': 'error', 'error': str(e)}

        futures = {executor.submit(process_one, f, i): f for i, f in enumerate(files)}
        for future in as_completed(futures):
            fn, result = future.result()
            results_raw[fn] = result

    results = list(results_raw.values())
    orig_files = [b for b in _orig_bytes if b is not None]
    decode_bid = put_decode_batch(orig_files)
    clean_decode_store()
    total_time = (time.time() - total_start) * 1000

    return jsonify({
        'status': 'completed', 'total_files': len(files),
        'successful': sum(1 for r in results if r['status'] == 'success'),
        'failed': sum(1 for r in results if r['status'] in ('rejected', 'error')),
        'total_processing_time_ms': round(total_time, 2),
        'results': results,
        'decode_batch_id': decode_bid,
    })


def _parse_b64_header(encoded, default):
    if not encoded:
        return default
    try:
        result = json.loads(base64.b64decode(encoded).decode())
        if isinstance(result, dict):
            return result.get('texts', result)
        return result
    except Exception:
        return default


def _process_async(files, api_key, client_ip):
    session_id, session_dir, saved_files = save_uploaded_files(files, app.config['UPLOAD_FOLDER'])
    job_id = session_id

    with jobs_lock:
        jobs[job_id] = {
            'id': job_id, 'status': 'queued', 'total': len(saved_files),
            'processed': 0, 'passed': 0, 'rejected': 0, 'errors': 0,
            'progress_pct': 0, 'chunk_time_ms': 0, 'total_time_ms': 0, 'results': None,
        }

    thread = threading.Thread(target=run_job, args=(job_id, session_dir, saved_files, api_key, client_ip), daemon=True)
    thread.start()

    return jsonify({
        'job_id': job_id, 'status': 'queued', 'total_files': len(saved_files),
        'message': 'Upload accepted. Poll /job-status/' + job_id + ' for progress.',
    }), 202


@app.route('/upload-large', methods=['POST'])
def upload_large():
    files = request.files.getlist('files')
    files = [f for f in files if f.filename]
    if not files:
        return jsonify({'error': 'No files provided'}), 400
    api_key = request.form.get('api_key', 'demo-key-123')
    return _process_async(files, api_key, request.remote_addr)


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
        return jsonify({'error': 'Job not yet completed', 'status': j['status'],
                        'progress_pct': j['progress_pct']}), 200
    results = j.get('results', [])
    return jsonify({
        'job_id': job_id, 'status': 'completed', 'total_files': j['total'],
        'successful': j['passed'], 'failed': j['rejected'] + j['errors'],
        'total_processing_time_ms': j['total_time_ms'], 'results': results,
        'decode_batch_id': j.get('decode_batch_id'),
    })


@app.route('/decode/<int:batch_id>/<int:idx>', methods=['GET'])
def decode_file(batch_id, idx):
    fbytes = get_decode_file(batch_id, idx)
    if fbytes is None:
        return jsonify({'error': 'File not found or expired'}), 404
    try:
        resp = session.post(f"{SCANNER_SERVICE_URL}/decode-stego",
            files={'file': ('decode.png', fbytes, 'image/png')}, timeout=10)
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        return jsonify({'error': f'Decode failed: {e}'}), 500


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
