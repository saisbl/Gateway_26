import os
import time
import json
import base64
import concurrent.futures

from flask import Flask, request, jsonify, Response

from engines.config import (ALLOWED_EXTENSIONS, MAX_FILE_SIZE_BYTES,
                             SCAN_TIMEOUT_SECONDS, MAX_WORKERS)
from engines.helpers import detect_mime, get_extension
from engines.scanner import scan_single_file, scan_file_wrapper, stats as scanner_stats
from engines.sanitizer import sanitize_bytes
from engines.steganography import detect_stego_on_bytes, detect_stego_on_bytes_async, add_stego_headers

app = Flask(__name__)


@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy', 'service': 'scanner-service', 'version': '2.0',
        'features': ['magic_bytes', 'dimension_check', 'image_bomb_detection',
                     'entropy_analysis', 'metadata_stripping', 'parallel_batch_scan',
                     'sanitize', 'sanitize_batch', 'decode_stego'],
        'allowed_extensions': sorted(ALLOWED_EXTENSIONS),
    }), 200


@app.route('/scan', methods=['POST'])
def scan():
    try:
        if 'file' not in request.files:
            return jsonify({'allowed': False, 'reason': 'no_file', 'message': 'No file provided'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'allowed': False, 'reason': 'no_filename', 'message': 'No file selected'}), 400
        result = scan_file_wrapper(file)
        scanner_stats['total_scanned'] += 1
        if result.get('allowed'):
            scanner_stats['total_passed'] += 1
        else:
            scanner_stats['total_rejected'] += 1
        scanner_stats['total_scan_time_ms'] += result.get('scan_time_ms', 0)
        status = 200 if result.get('allowed') else (403 if result.get('reason') not in ('no_file', 'no_filename') else 400)
        return jsonify(result), status
    except Exception as e:
        return jsonify({'allowed': False, 'reason': 'server_error', 'message': str(e)}), 500


@app.route('/scan-batch', methods=['POST'])
def scan_batch():
    try:
        files = request.files.getlist('file')
        if not files:
            return jsonify({'total_files': 0, 'passed': 0, 'rejected': 0, 'results': [], 'error': 'No files provided'}), 400
        total_start = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_map = {executor.submit(scan_file_wrapper, f): f.filename for f in files}
            results = []
            for future in concurrent.futures.as_completed(future_map, timeout=SCAN_TIMEOUT_SECONDS * len(files)):
                try:
                    result = future.result()
                    results.append(result)
                except concurrent.futures.TimeoutError:
                    results.append({
                        'filename': future_map.get(future, 'unknown'),
                        'allowed': False, 'reason': 'timeout',
                        'message': 'Scan timed out',
                        'scan_time_ms': SCAN_TIMEOUT_SECONDS * 1000,
                    })
        elapsed = (time.perf_counter() - total_start) * 1000
        passed = sum(1 for r in results if r.get('allowed'))
        rejected = sum(1 for r in results if not r.get('allowed'))
        scanner_stats['total_scanned'] += len(results)
        scanner_stats['total_passed'] += passed
        scanner_stats['total_rejected'] += rejected
        for r in results:
            scanner_stats['total_scan_time_ms'] += r.get('scan_time_ms', 0)
        return jsonify({
            'total_files': len(results), 'passed': passed, 'rejected': rejected,
            'total_scan_time_ms': round(elapsed, 2),
            'avg_scan_time_ms': round(elapsed / max(len(results), 1), 2),
            'results': results,
        }), 200
    except Exception as e:
        return jsonify({'total_files': 0, 'passed': 0, 'rejected': 0, 'results': [], 'error': str(e)}), 500


@app.route('/scan-metadata', methods=['POST'])
def scan_metadata():
    try:
        data = request.get_json()
        filename = data.get('filename', '')
        file_size = data.get('file_size', 0)

        if filename.count('.') > 1:
            return jsonify({'allowed': False, 'reason': 'double_extension', 'message': 'Double extensions are not allowed'}), 403
        extension = get_extension(filename)
        if extension not in ALLOWED_EXTENSIONS:
            return jsonify({'allowed': False, 'reason': 'invalid_extension', 'message': f"Extension '{extension}' not allowed"}), 403
        file_size_mb = file_size / (1024 * 1024)
        if file_size_mb > MAX_FILE_SIZE_BYTES / (1024 * 1024):
            return jsonify({'allowed': False, 'reason': 'file_too_large', 'message': 'File size exceeds limit'}), 413
        return jsonify({'allowed': True, 'extension': extension}), 200
    except Exception as e:
        return jsonify({'allowed': False, 'reason': 'error', 'message': str(e)}), 500


@app.route('/sanitize', methods=['POST'])
def sanitize():
    if 'file' not in request.files:
        return jsonify({'allowed': False, 'reason': 'no_file', 'message': 'No file provided'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'allowed': False, 'reason': 'no_filename', 'message': 'No file selected'}), 400
    data = file.read()
    if len(data) > MAX_FILE_SIZE_BYTES:
        return jsonify({'allowed': False, 'reason': 'file_too_large', 'message': 'File exceeds size limit'}), 413
    stego = detect_stego_on_bytes_async(data, file.filename)
    try:
        cleaned = sanitize_bytes(data, file.filename)
        resp = Response(cleaned, mimetype='application/octet-stream')
        resp.headers['X-Sanitized-Filename'] = file.filename
        resp.headers['X-Original-Size'] = str(len(data))
        resp.headers['X-Sanitized-Size'] = str(len(cleaned))
        resp.headers['X-Sanitized'] = 'true'
        add_stego_headers(resp, stego)
        return resp
    except Exception as e:
        resp = jsonify({'allowed': False, 'reason': 'sanitize_failed', 'message': str(e)})
        add_stego_headers(resp, stego)
        return resp, 400


class _BytesFileProxy:
    """Minimal file-like object wrapping bytes for scanner functions."""
    def __init__(self, data, filename):
        self._data = data
        self.filename = filename
        self.content_type = ''

    def read(self):
        return self._data


@app.route('/sanitize-and-scan', methods=['POST'])
def sanitize_and_scan():
    """Combined sanitize + scan in one request. Saves one HTTP round-trip per file."""
    if 'file' not in request.files:
        return jsonify({'allowed': False, 'reason': 'no_file', 'message': 'No file provided'}), 400
    f = request.files['file']
    if f.filename == '':
        return jsonify({'allowed': False, 'reason': 'no_filename', 'message': 'No file selected'}), 400
    data = f.read()
    if len(data) > MAX_FILE_SIZE_BYTES:
        return jsonify({'allowed': False, 'reason': 'file_too_large', 'message': 'File exceeds size limit'}), 413

    total_start = time.perf_counter()

    stego = detect_stego_on_bytes_async(data, f.filename)

    try:
        sanitize_start = time.perf_counter()
        cleaned = sanitize_bytes(data, f.filename)
        sanitize_time_ms = (time.perf_counter() - sanitize_start) * 1000
    except Exception as e:
        return jsonify({
            'allowed': False, 'reason': 'sanitize_failed', 'message': str(e),
            'steganography': stego,
            'time_ms': round((time.perf_counter() - total_start) * 1000, 2),
        }), 400

    proxy = _BytesFileProxy(cleaned, f.filename)
    scan_result = scan_single_file(proxy)
    # Inject stego detection (from original bytes) into scan result checks
    if 'checks' in scan_result and 'steganography' in scan_result['checks']:
        scan_result['checks']['steganography'] = {
            'passed': True,
            'flagged': stego.get('flagged', False),
            'chi_square_score': stego.get('chi_square_score', 0),
            'lsb_zero_ratio': stego.get('lsb_zero_ratio', 0),
            'bitplane_correlation': stego.get('bitplane_correlation', 0),
            'samples_analyzed': stego.get('samples_analyzed', 0),
            'reasons': stego.get('reasons', []),
            'extracted_messages': stego.get('extracted_messages', []),
            'structural_payloads': stego.get('structural_payloads', []),
            'metadata_findings': stego.get('metadata_findings', []),
        }
    scanner_stats['total_scanned'] += 1
    if scan_result.get('allowed'):
        scanner_stats['total_passed'] += 1
    else:
        scanner_stats['total_rejected'] += 1
    scanner_stats['total_scan_time_ms'] += scan_result.get('scan_time_ms', 0)

    allowed = scan_result.get('allowed', False)
    return jsonify({
        'allowed': allowed,
        'cleaned_data_base64': base64.b64encode(cleaned).decode(),
        'original_size': len(data),
        'sanitized_size': len(cleaned),
        'sanitize_time_ms': round(sanitize_time_ms, 2),
        'scan': scan_result,
        'steganography': stego,
        'time_ms': round((time.perf_counter() - total_start) * 1000, 2),
    }), 200 if allowed else 403


@app.route('/sanitize-batch', methods=['POST'])
def sanitize_batch():
    files = request.files.getlist('file')
    if not files:
        return jsonify({'total': 0, 'results': [], 'error': 'No files provided'}), 400
    results = []
    for f in files:
        entry = {'filename': f.filename, 'sanitized': False}
        data = f.read()
        if len(data) > MAX_FILE_SIZE_BYTES:
            entry['error'] = 'file_too_large'
            results.append(entry)
            continue
        try:
            stego = detect_stego_on_bytes_async(data, f.filename)
            cleaned = sanitize_bytes(data, f.filename)
            entry['sanitized'] = True
            entry['data_base64'] = base64.b64encode(cleaned).decode()
            entry['original_size'] = len(data)
            entry['sanitized_size'] = len(cleaned)
            if stego.get('flagged'):
                entry['steganography_flagged'] = True
                entry['steganography_reasons'] = stego.get('reasons', [])
                msgs = stego.get('extracted_messages', [])
                if msgs:
                    entry['steganography_messages_b64'] = base64.b64encode(json.dumps(msgs).encode()).decode()
                structural = stego.get('structural_payloads', [])
                if structural:
                    entry['steganography_structural_b64'] = base64.b64encode(json.dumps(structural).encode()).decode()
                metadata = stego.get('metadata_findings', [])
                if metadata:
                    entry['steganography_metadata_b64'] = base64.b64encode(json.dumps(metadata).encode()).decode()
        except Exception as e:
            entry['error'] = str(e)
        results.append(entry)
    return jsonify({'total': len(results), 'results': results}), 200


@app.route('/decode-stego', methods=['POST'])
def decode_stego():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    file = request.files['file']
    data = file.read()
    if len(data) > MAX_FILE_SIZE_BYTES:
        return jsonify({'error': 'File too large'}), 413
    stego = detect_stego_on_bytes(data, file.filename)
    result = {
        'filename': file.filename, 'file_size': len(data),
        'mime_type': detect_mime(data),
        'flagged': stego.get('flagged', False),
        'reasons': stego.get('reasons', []),
        'extracted_messages': stego.get('extracted_messages', []),
        'structural_payloads': stego.get('structural_payloads', []),
        'metadata_findings': stego.get('metadata_findings', []),
    }
    return jsonify(result), 200


@app.route('/allowed-types', methods=['GET'])
def allowed_types():
    return jsonify({
        'allowed_extensions': sorted(ALLOWED_EXTENSIONS),
        'max_file_size_mb': MAX_FILE_SIZE_BYTES / (1024 * 1024),
        'max_image_dimension_px': 10000,
        'max_megapixels': 50,
        'max_aspect_ratio': 100,
        'max_compression_ratio': 500,
        'max_entropy_score': 7.5,
        'max_pdf_pages': 500,
        'scan_timeout_seconds': SCAN_TIMEOUT_SECONDS,
        'max_workers': MAX_WORKERS,
    }), 200


@app.route('/metrics', methods=['GET'])
def metrics():
    avg_time = round(scanner_stats['total_scan_time_ms'] / max(scanner_stats['total_scanned'], 1), 2)
    return jsonify({
        'service': 'scanner-service', 'version': '2.0',
        'total_scanned': scanner_stats['total_scanned'],
        'total_passed': scanner_stats['total_passed'],
        'total_rejected': scanner_stats['total_rejected'],
        'pass_rate': round(scanner_stats['total_passed'] / max(scanner_stats['total_scanned'], 1) * 100, 2),
        'avg_scan_time_ms': avg_time,
        'total_scan_time_ms': round(scanner_stats['total_scan_time_ms'], 2),
        'allowed_extensions': sorted(ALLOWED_EXTENSIONS),
        'max_workers': MAX_WORKERS,
    }), 200


if __name__ == '__main__':
    from waitress import serve
    port = int(os.environ.get('PORT', 5003))
    serve(app, host='0.0.0.0', port=port, threads=50)
