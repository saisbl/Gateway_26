import os
import time
import json
import base64
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from .config import GPU_SERVICE_URL, POLICY_SERVICE_URL, SCANNER_SERVICE_URL, CHUNK_SIZE, MAX_WORKERS
from .decode_store import put_decode_batch

import requests

session = requests.Session()
adapter = requests.adapters.HTTPAdapter(pool_connections=50, pool_maxsize=50, max_retries=3)
session.mount('http://', adapter)
session.mount('https://', adapter)


def process_chunk(chunk, api_key, client_ip):
    results = {}

    # ── Auth ──
    auth_payload = {
        'api_key': api_key, 'endpoint': '/infer', 'client_ip': client_ip,
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

    # ── Sanitize + Stego Detect ──
    sanitize_map = {}
    sanitize_wall_ms = 0
    sanitized_dir = None
    if allowed_files:
        sanitize_start = time.time()
        try:
            san_files = []
            for f in allowed_files:
                san_files.append(('file', (f['filename'], open(f['filepath'], 'rb'), 'application/octet-stream')))
            san_resp = session.post(f"{SCANNER_SERVICE_URL}/sanitize-batch", files=san_files, timeout=60)
            san_data = san_resp.json()
            for _, _, fh in san_files:
                fh.close()

            if san_data.get('results'):
                sanitized_dir = tempfile.mkdtemp(prefix='sanitized_')
                for sr in san_data['results']:
                    fn = sr.get('filename', '')
                    if sr.get('sanitized') and sr.get('data_base64'):
                        cleaned = base64.b64decode(sr['data_base64'])
                        san_path = os.path.join(sanitized_dir, fn)
                        with open(san_path, 'wb') as sf:
                            sf.write(cleaned)
                        entry = {'sanitized': True, 'path': san_path,
                                 'original_size': sr.get('original_size', 0),
                                 'sanitized_size': sr.get('sanitized_size', 0)}
                        if sr.get('steganography_flagged'):
                            entry['steganography_flagged'] = True
                            entry['steganography_reasons'] = sr.get('steganography_reasons', [])
                            msgs_b64 = sr.get('steganography_messages_b64')
                            if msgs_b64:
                                try:
                                    entry['steganography_messages'] = json.loads(base64.b64decode(msgs_b64).decode())
                                except Exception:
                                    pass
                            struct_b64 = sr.get('steganography_structural_b64')
                            if struct_b64:
                                try:
                                    parsed = json.loads(base64.b64decode(struct_b64).decode())
                                    entry['steganography_structural'] = parsed.get('texts', []) if isinstance(parsed, dict) else parsed
                                except Exception:
                                    pass
                            meta_b64 = sr.get('steganography_metadata_b64')
                            if meta_b64:
                                try:
                                    entry['steganography_metadata'] = json.loads(base64.b64decode(meta_b64).decode())
                                except Exception:
                                    pass
                        sanitize_map[fn] = entry
                    else:
                        sanitize_map[fn] = {'sanitized': False, 'error': sr.get('error', 'sanitize_failed')}
        except Exception as e:
            err_msg = f"{type(e).__name__}: {str(e)}"
            for f in allowed_files:
                sanitize_map[f['filename']] = {'sanitized': False, 'error': err_msg}
        finally:
            sanitize_wall_ms = (time.time() - sanitize_start) * 1000

    sanitize_passed = [f for f in allowed_files if sanitize_map.get(f['filename'], {}).get('sanitized')]

    # ── Scan ──
    scan_map = {}
    scan_wall_ms = 0
    if sanitize_passed:
        scan_start = time.time()
        try:
            scan_files = []
            for f in sanitize_passed:
                san = sanitize_map[f['filename']]
                scan_files.append(('file', (f['filename'], open(san['path'], 'rb'), 'application/octet-stream')))
            scan_resp = session.post(f"{SCANNER_SERVICE_URL}/scan-batch", files=scan_files, timeout=30)
            scan_data = scan_resp.json()
            for sr in scan_data.get('results', []):
                scan_map[sr.get('filename', '')] = sr
            for _, _, fh in scan_files:
                fh.close()
        except Exception as e:
            err_msg = f"{type(e).__name__}: {str(e)}"
            for f in sanitize_passed:
                scan_map[f['filename']] = {'allowed': False, 'reason': 'scan_error', 'message': err_msg}
        finally:
            scan_wall_ms = (time.time() - scan_start) * 1000

    scan_passed = [f for f in sanitize_passed if scan_map.get(f['filename'], {}).get('allowed')]

    # ── GPU Inference ──
    gpu_results = {}
    if scan_passed:
        with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(scan_passed))) as executor:
            def infer_file(f):
                start = time.time()
                san = sanitize_map[f['filename']]
                try:
                    with open(san['path'], 'rb') as fh:
                        resp = session.post(f"{GPU_SERVICE_URL}/infer", files={'file': fh}, timeout=15)
                    latency = (time.time() - start) * 1000
                    return f['filename'], {'status': 'success' if resp.status_code == 200 else 'error',
                                           'response': resp.json(), 'latency_ms': round(latency, 2)}
                except Exception as e:
                    latency = (time.time() - start) * 1000
                    return f['filename'], {'status': 'error', 'error': str(e), 'latency_ms': round(latency, 2)}
            futures = {executor.submit(infer_file, f): f for f in scan_passed}
            for future in as_completed(futures):
                name, result = future.result()
                gpu_results[name] = result

    # ── Assemble ──
    for f in chunk:
        fn = f['filename']
        ai = auth_map.get(fn, {})
        si = sanitize_map.get(fn, {})
        sc = scan_map.get(fn, {})
        gi = gpu_results.get(fn, {})

        lat = {}
        if ai.get('allowed'):
            lat['authorization_ms'] = round(auth_wall_ms, 2)
        if si.get('sanitized'):
            lat['sanitization_ms'] = round(sanitize_wall_ms, 2)
        if sc.get('scan_time_ms'):
            lat['scanning_ms'] = round(scan_wall_ms, 2)
        if gi.get('latency_ms'):
            lat['inference_ms'] = round(gi['latency_ms'], 2)
        total_sec = lat.get('authorization_ms', 0) + lat.get('sanitization_ms', 0) + lat.get('scanning_ms', 0)
        if total_sec > 0:
            lat['total_security_ms'] = round(total_sec, 2)
        total_proc = total_sec + lat.get('inference_ms', 0)
        if total_proc > 0:
            lat['total_processing_ms'] = round(total_proc, 2)

        sanitized_ok = si.get('sanitized', True) if fn in sanitize_map else True
        status = 'success' if gi.get('status') == 'success' else \
                 ('rejected' if not ai.get('allowed') or not sanitized_ok or not sc.get('allowed') else \
                  'error' if gi.get('status') == 'error' else 'pending')

        stego_findings = None
        if si.get('steganography_flagged'):
            stego_findings = {
                'flagged': True,
                'reasons': si.get('steganography_reasons', []),
                'extracted_messages': si.get('steganography_messages', []),
                'structural_payloads': si.get('steganography_structural', []),
                'metadata_findings': si.get('steganography_metadata', []),
            }

        result = {
            'filename': fn, 'status': status, 'latency': lat,
            'authorization': ai, 'sanitization': si if fn in sanitize_map else {'sanitized': True},
            'scanning': sc, 'inference': gi.get('response') if gi.get('response') else None,
            'steganography': stego_findings,
        }
        if status == 'rejected':
            if not ai.get('allowed'):
                result['step'] = 'authorization'
                result['reason'] = ai.get('reason', auth_data.get('reason', 'unknown'))
                result['message'] = ai.get('message', auth_data.get('message', ''))
            elif not sanitized_ok:
                result['step'] = 'sanitization'
                result['reason'] = 'sanitize_failed'
                result['message'] = si.get('error', 'Sanitization failed')
            elif not sc.get('allowed'):
                result['step'] = 'scanning'
                result['reason'] = sc.get('reason', 'unknown')
                result['message'] = sc.get('message', '')
        elif status == 'error' and not gi.get('response'):
            result['error'] = gi.get('error', 'GPU processing failed')

        results[fn] = result

    # Clean up
    if sanitized_dir and os.path.exists(sanitized_dir):
        import shutil
        shutil.rmtree(sanitized_dir, ignore_errors=True)

    return results, False
