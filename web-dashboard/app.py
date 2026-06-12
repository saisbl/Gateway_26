import os
import time
import json
import base64
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import Flask, render_template, request, jsonify, Response

from lib.config import GPU_SERVICE_URL, POLICY_SERVICE_URL, SCANNER_SERVICE_URL, MAX_WORKERS
from lib.decode_store import put_decode_batch, get_decode_file, clean_decode_store

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

    return _process_sync(files, api_key, client_ip)


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

                combined_start = time.time()
                with open(fp, 'rb') as fh:
                    combined_resp = session.post(f"{SCANNER_SERVICE_URL}/sanitize-and-scan", files={'file': fh}, timeout=30)
                    combined = combined_resp.json()
                combined_ms = (time.time() - combined_start) * 1000

                if not combined.get('allowed'):
                    os.remove(fp)
                    step = 'sanitization' if combined.get('reason') == 'sanitize_failed' else 'scanning'
                    scan_r = combined.get('scan', {})
                    return fn, {'filename': fn, 'status': 'rejected', 'step': step,
                                'reason': scan_r.get('reason', combined.get('reason', 'unknown')),
                                'message': scan_r.get('message', combined.get('message', '')),
                                'scanning': scan_r, 'latency': {},
                                'steganography': combined.get('steganography')}

                cleaned_bytes = base64.b64decode(combined['cleaned_data_base64'])
                scan_r = combined['scan']
                stego = combined.get('steganography', {})
                stego_findings = {
                    'flagged': stego.get('flagged', False),
                    'reasons': stego.get('reasons', []),
                    'extracted_messages': stego.get('extracted_messages', []),
                    'structural_payloads': stego.get('structural_payloads', []),
                    'metadata_findings': stego.get('metadata_findings', []),
                    'chi_square_scores': stego.get('chi_square_scores', {'R': 0, 'G': 0, 'B': 0}),
                    'lsb_zero_ratios': stego.get('lsb_zero_ratios', {'R': 0, 'G': 0, 'B': 0}),
                    'bitplane_correlations': stego.get('bitplane_correlations', {'R': 0, 'G': 0, 'B': 0}),
                    'pvd_smoothness': stego.get('pvd_smoothness', 0),
                    'pvd_zero_ratio': stego.get('pvd_zero_ratio', 0),
                    'rs_ratios': stego.get('rs_ratios', {'R': 0.5, 'G': 0.5, 'B': 0.5}),
                    'samples_analyzed': stego.get('samples_analyzed', 0),
                }

                tmp = tempfile.NamedTemporaryFile(delete=False, suffix='_' + fn)
                tmp.write(cleaned_bytes)
                tmp.close()
                sanitized_path = tmp.name

                sn_ms = round(combined.get('sanitize_time_ms', 0), 2)
                stego_ms = round(combined.get('stego_detection_ms', 0), 2)
                s_ms = round(scan_r.get('scan_time_ms', 0), 2)

                infer_start = time.time()
                with open(sanitized_path, 'rb') as fh:
                    gpu_r = session.post(f"{GPU_SERVICE_URL}/infer", files={'file': fh}, timeout=10).json()
                infer_ms = (time.time() - infer_start) * 1000

                os.remove(fp)
                os.unlink(sanitized_path)

                a_ms = round(auth_ms, 2)
                g_ms = round(infer_ms, 2)

                return fn, {
                    'filename': fn, 'status': 'success',
                    'authorization': auth_r,
                    'sanitization': {'sanitized': True, 'original_size': size},
                    'scanning': scan_r, 'inference': gpu_r,
                    'steganography': stego_findings,
                    'latency': {
                        'authorization_ms': a_ms, 'sanitization_ms': sn_ms,
                        'stego_detection_ms': stego_ms,
                        'scanning_ms': s_ms, 'inference_ms': g_ms,
                        'total_security_ms': round(a_ms + sn_ms + stego_ms + s_ms, 2),
                        'total_processing_ms': round(a_ms + sn_ms + stego_ms + s_ms + g_ms, 2),
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


@app.route('/decode/<int:batch_id>/<int:idx>', methods=['GET'])
def decode_file(batch_id, idx):
    fbytes = get_decode_file(batch_id, idx)
    if fbytes is None:
        return jsonify({'error': 'File not found or expired'}), 404
    try:
        resp = session.post(f"{SCANNER_SERVICE_URL}/decode-stego",
            files={'file': ('decode.png', fbytes, 'image/png')}, timeout=30)
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        return jsonify({'error': f'Decode failed: {e}'}), 500


@app.route('/preview/<int:batch_id>/<int:idx>', methods=['GET'])
def preview_file(batch_id, idx):
    fbytes = get_decode_file(batch_id, idx)
    if fbytes is None:
        return jsonify({'error': 'File not found or expired'}), 404
    mime = 'image/png'
    if fbytes[:2] == b'\xff\xd8':
        mime = 'image/jpeg'
    elif fbytes[:6] in (b'GIF87a', b'GIF89a'):
        mime = 'image/gif'
    elif fbytes[:4] == b'\x89PNG':
        mime = 'image/png'
    elif fbytes[:4] == b'RIFF':
        mime = 'image/webp'
    return Response(fbytes, mimetype=mime)


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
    from waitress import serve
    print("Starting Web Dashboard on http://127.0.0.1:8080")
    serve(app, host='0.0.0.0', port=8080, threads=50)
