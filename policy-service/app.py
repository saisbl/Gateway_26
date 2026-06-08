import os
import time
import hmac
import hashlib

from flask import Flask, request, jsonify

from lib.config import (MAX_FILE_SIZE_BYTES, MAX_REQUESTS_PER_MINUTE,
                         MAX_REQUESTS_PER_MINUTE_PER_IP, ALLOWED_EXTENSIONS,
                         HMAC_REQUIRED, MAX_BATCH_SIZE, BATCH_REQUESTS_PER_MINUTE)
from lib.helpers import get_extension, parse_iso_timestamp, now_utc
from lib.keystore import API_KEYS, validate_api_key
from lib.hmac_utils import verify_hmac
from lib.ratelimiter import (check_rate_limits, check_batch_rate_limit,
                              _get_reset_seconds, _set_rate_limit_headers,
                              rate_limits, ip_rate_limits)
from lib.patterns import track_pattern, get_pattern_summary, request_patterns
from lib.concurrency import check_concurrency, release_concurrency, concurrency_slots
from lib.dedup import check_file_hash, check_file_hash_only, file_hashes
from lib.stats import check_daily_quota, daily_quotas, stats as policy_stats

app = Flask(__name__)


@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy', 'service': 'policy-service', 'version': '2.1',
        'storage': 'in-memory',
        'features': ['key_expiry', 'ip_rate_limiting', 'concurrency_caps',
                     'file_hash_dedup', 'hmac_signing', 'pattern_tracking', 'rate_limit_headers'],
        'active_keys': sum(1 for k in API_KEYS.values() if k['is_active']),
        'rate_limit_per_minute': MAX_REQUESTS_PER_MINUTE,
        'ip_rate_limit_per_minute': MAX_REQUESTS_PER_MINUTE_PER_IP,
        'batch_rate_limit_per_minute': BATCH_REQUESTS_PER_MINUTE,
        'max_batch_size': MAX_BATCH_SIZE,
        'concurrent_limit_per_tenant': 50,
    }), 200


@app.route('/authorize', methods=['POST'])
def authorize():
    start = time.perf_counter()
    try:
        data = request.get_json()
        api_key = data.get('api_key')
        endpoint = data.get('endpoint')
        file_size = data.get('file_size', 0)
        client_ip = data.get('client_ip', 'unknown')
        file_hash = data.get('file_hash', '')
        filename = data.get('filename', '')

        key_ok, key_reason, key_msg = validate_api_key(api_key)
        if not key_ok:
            policy_stats['total_rejected'] += 1
            return jsonify({'allowed': False, 'reason': key_reason, 'message': key_msg}), 401

        key_info = API_KEYS[api_key]
        tenant = key_info['tenant']

        sig = request.headers.get('X-Signature', '')
        ts = request.headers.get('X-Timestamp', '')
        if HMAC_REQUIRED or sig:
            body_bytes = request.get_data()
            hmac_ok, hmac_err = verify_hmac(api_key, body_bytes, sig, ts)
            if not hmac_ok:
                policy_stats['total_rejected'] += 1
                return jsonify({'allowed': False, 'reason': hmac_err,
                                'message': f'HMAC verification failed: {hmac_err}'}), 401

        if endpoint not in key_info['endpoints']:
            policy_stats['total_rejected'] += 1
            return jsonify({'allowed': False, 'reason': 'endpoint_not_allowed',
                            'message': f"Endpoint {endpoint} not allowed for this tenant"}), 403

        if file_size > MAX_FILE_SIZE_BYTES:
            policy_stats['total_rejected'] += 1
            return jsonify({'allowed': False, 'reason': 'file_too_large',
                            'message': f"File size exceeds {MAX_FILE_SIZE_BYTES // (1024*1024)}MB limit"}), 413

        if filename:
            ext = get_extension(filename)
            if ext not in ALLOWED_EXTENSIONS:
                policy_stats['total_rejected'] += 1
                return jsonify({'allowed': False, 'reason': 'invalid_extension',
                                'message': f"Extension '{ext}' not allowed"}), 403

        rl_ok, rl_reason, rl_msg, rl_key_count, rl_ip_count = check_rate_limits(api_key, client_ip)
        track_pattern(api_key, endpoint, client_ip)
        if not rl_ok:
            policy_stats['total_rejected'] += 1
            reset_sec = _get_reset_seconds()
            resp = jsonify({'allowed': False, 'reason': rl_reason, 'message': rl_msg,
                            'retry_after_seconds': reset_sec})
            resp.status_code = 429
            resp.headers['Retry-After'] = str(reset_sec)
            _set_rate_limit_headers(resp, rl_key_count, MAX_REQUESTS_PER_MINUTE,
                                    rl_ip_count, MAX_REQUESTS_PER_MINUTE_PER_IP)
            return resp

        quota_ok, quota_reason, quota_msg = check_daily_quota(tenant)
        if not quota_ok:
            policy_stats['total_rejected'] += 1
            return jsonify({'allowed': False, 'reason': quota_reason, 'message': quota_msg}), 429

        conc_ok, conc_reason, conc_msg = check_concurrency(tenant)
        if not conc_ok:
            policy_stats['total_rejected'] += 1
            return jsonify({'allowed': False, 'reason': conc_reason, 'message': conc_msg}), 429

        dedup_ok, dedup_reason, dedup_msg = check_file_hash(tenant, file_hash)
        if not dedup_ok:
            policy_stats['total_rejected'] += 1
            return jsonify({'allowed': False, 'reason': dedup_reason, 'message': dedup_msg}), 409

        current_day = now_utc().strftime('%Y%m%d')
        quota_key = f"{tenant}:{current_day}"
        daily_requests = daily_quotas[quota_key]
        remaining = max(0, MAX_REQUESTS_PER_MINUTE - rl_key_count)

        elapsed = (time.perf_counter() - start) * 1000
        policy_stats['total_authorized'] += 1
        policy_stats['total_auth_time_ms'] += elapsed

        resp = jsonify({
            'allowed': True, 'tenant': tenant,
            'key_type': key_info['key_type'],
            'key_expires_at': key_info['expires_at'],
            'requests_this_minute': rl_key_count,
            'requests_remaining': remaining,
            'daily_requests': daily_requests,
            'daily_limit': key_info['daily_limit'],
            'auth_time_ms': round(elapsed, 2),
        })
        _set_rate_limit_headers(resp, rl_key_count, MAX_REQUESTS_PER_MINUTE,
                                rl_ip_count, MAX_REQUESTS_PER_MINUTE_PER_IP)
        return resp, 200

    except Exception as e:
        policy_stats['total_rejected'] += 1
        return jsonify({'allowed': False, 'reason': 'internal_error', 'message': str(e)}), 500


@app.route('/batch-authorize', methods=['POST'])
def batch_authorize():
    start = time.perf_counter()
    try:
        data = request.get_json()
        api_key = data.get('api_key')
        endpoint = data.get('endpoint')
        client_ip = data.get('client_ip', 'unknown')
        files = data.get('files', [])

        if not files:
            return jsonify({'allowed': False, 'reason': 'no_files', 'message': 'No files provided', 'files': []}), 400
        if len(files) > MAX_BATCH_SIZE:
            return jsonify({'allowed': False, 'reason': 'batch_too_large',
                            'message': f'Batch size {len(files)} exceeds maximum of {MAX_BATCH_SIZE}'}), 413

        key_ok, key_reason, key_msg = validate_api_key(api_key)
        if not key_ok:
            policy_stats['total_rejected'] += len(files)
            return jsonify({'allowed': False, 'reason': key_reason, 'message': key_msg, 'files': []}), 401

        key_info = API_KEYS[api_key]
        tenant = key_info['tenant']

        if endpoint not in key_info['endpoints']:
            policy_stats['total_rejected'] += len(files)
            return jsonify({'allowed': False, 'reason': 'endpoint_not_allowed',
                            'message': f"Endpoint {endpoint} not allowed", 'files': []}), 403

        brl_ok, brl_current, brl_max = check_batch_rate_limit(api_key)
        if not brl_ok:
            policy_stats['total_rejected'] += len(files)
            reset_sec = _get_reset_seconds()
            resp = jsonify({'allowed': False, 'reason': 'batch_rate_limit_exceeded',
                            'message': f'Batch rate limit exceeded: {brl_max} batch requests/min',
                            'retry_after_seconds': reset_sec, 'files': []})
            resp.status_code = 429
            resp.headers['Retry-After'] = str(reset_sec)
            resp.headers['X-RateLimit-Limit'] = str(brl_max)
            resp.headers['X-RateLimit-Remaining'] = '0'
            resp.headers['X-RateLimit-Reset'] = str(reset_sec)
            return resp

        daily_allowed = True
        for _ in files:
            dq_ok, dq_reason, dq_msg = check_daily_quota(tenant)
            if not dq_ok:
                daily_allowed = False
                break

        file_results = []
        rejected_count = 0
        for i, f_info in enumerate(files):
            file_result = {'index': i, 'filename': f_info.get('filename', f'file_{i}'), 'allowed': False}
            file_size = f_info.get('file_size', 0)
            file_hash = f_info.get('file_hash', '')
            filename = f_info.get('filename', '')

            if file_size > MAX_FILE_SIZE_BYTES:
                file_result['reason'] = 'file_too_large'
                file_result['message'] = f'File size exceeds {MAX_FILE_SIZE_BYTES // (1024*1024)}MB limit'
                rejected_count += 1
                file_results.append(file_result)
                continue

            if filename:
                ext = get_extension(filename)
                if ext not in ALLOWED_EXTENSIONS:
                    file_result['reason'] = 'invalid_extension'
                    file_result['message'] = f"Extension '{ext}' not allowed"
                    rejected_count += 1
                    file_results.append(file_result)
                    continue

            dedup_ok, dedup_reason, dedup_msg = check_file_hash(tenant, file_hash)
            if not dedup_ok:
                file_result['reason'] = dedup_reason
                file_result['message'] = dedup_msg
                rejected_count += 1
                file_results.append(file_result)
                continue

            if not daily_allowed:
                file_result['reason'] = 'daily_quota_exceeded'
                file_result['message'] = 'Daily quota exceeded'
                rejected_count += 1
                file_results.append(file_result)
                continue

            file_result['allowed'] = True
            file_results.append(file_result)

        conc_ok, conc_reason, conc_msg = check_concurrency(tenant)
        if not conc_ok:
            for r in file_results:
                if r.get('allowed'):
                    r['allowed'] = False
                    r['reason'] = conc_reason
                    r['message'] = conc_msg
                    rejected_count += 1

        accepted = sum(1 for r in file_results if r.get('allowed'))
        elapsed = (time.perf_counter() - start) * 1000
        policy_stats['total_authorized'] += accepted
        policy_stats['total_rejected'] += rejected_count
        policy_stats['total_auth_time_ms'] += elapsed

        batch_remaining = max(0, brl_max - brl_current)
        reset_sec = _get_reset_seconds()
        resp = jsonify({
            'allowed': accepted > 0, 'tenant': tenant,
            'total_files': len(files), 'accepted': accepted, 'rejected': rejected_count,
            'batch_requests_this_minute': brl_current,
            'batch_request_limit': brl_max,
            'batch_requests_remaining': batch_remaining,
            'auth_time_ms': round(elapsed, 2),
            'files': file_results,
        })
        resp.headers['X-RateLimit-Limit'] = str(brl_max)
        resp.headers['X-RateLimit-Remaining'] = str(batch_remaining)
        resp.headers['X-RateLimit-Reset'] = str(reset_sec)
        return resp, 200

    except Exception as e:
        return jsonify({'allowed': False, 'reason': 'internal_error', 'message': str(e), 'files': []}), 500


@app.route('/release', methods=['POST'])
def release():
    try:
        data = request.get_json()
        tenant = data.get('tenant')
        if tenant:
            release_concurrency(tenant)
        return jsonify({'status': 'released'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/check-hash', methods=['POST'])
def check_hash():
    try:
        data = request.get_json()
        tenant = data.get('tenant', '')
        file_hash = data.get('file_hash', '')
        exists = check_file_hash_only(tenant, file_hash)
        return jsonify({'exists': exists, 'tenant': tenant}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/keys', methods=['GET'])
def list_keys():
    key_list = []
    for kid, info in API_KEYS.items():
        expires = parse_iso_timestamp(info['expires_at'])
        expired = expires is not None and now_utc() > expires
        key_list.append({
            'key_id': kid, 'tenant': info['tenant'],
            'key_type': info['key_type'], 'is_active': info['is_active'],
            'is_expired': expired, 'expires_at': info['expires_at'],
            'endpoints': info['endpoints'], 'daily_limit': info['daily_limit'],
        })
    return jsonify({'keys': key_list, 'total': len(key_list)}), 200


@app.route('/sign', methods=['POST'])
def sign():
    try:
        data = request.get_json()
        api_key = data.get('api_key', '')
        body = data.get('body', '')
        if api_key not in API_KEYS:
            return jsonify({'error': 'Unknown API key'}), 404
        secret = API_KEYS[api_key].get('secret', '')
        ts = str(int(time.time()))
        msg = (body.encode() if isinstance(body, str) else body) + ts.encode()
        signature = hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()
        return jsonify({'signature': signature, 'timestamp': ts, 'api_key': api_key}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/metrics', methods=['GET'])
def metrics():
    avg_time = round(policy_stats['total_auth_time_ms'] / max(policy_stats['total_authorized'] + policy_stats['total_rejected'], 1), 2)
    active_conc = {k: len([ts for ts in v if time.time() - ts < 30]) for k, v in concurrency_slots.items()}
    return jsonify({
        'service': 'policy-service', 'version': '2.1',
        'total_authorized': policy_stats['total_authorized'],
        'total_rejected': policy_stats['total_rejected'],
        'pass_rate': round(policy_stats['total_authorized'] / max(policy_stats['total_authorized'] + policy_stats['total_rejected'], 1) * 100, 2),
        'avg_auth_time_ms': avg_time,
        'rate_limit_keys': len(rate_limits),
        'ip_rate_limit_keys': len(ip_rate_limits),
        'active_concurrency_slots': active_conc,
        'file_hashes_stored': sum(len(v) for v in file_hashes.values()),
        'file_hash_tenants': len(file_hashes),
        'active_keys': sum(1 for k in API_KEYS.values() if k['is_active']),
        'expired_keys': sum(1 for k in API_KEYS.values() if parse_iso_timestamp(k['expires_at']) and now_utc() > parse_iso_timestamp(k['expires_at'])),
        'pattern_tracked_keys': len(request_patterns),
    }), 200


@app.route('/throttle-status', methods=['GET'])
def throttle_status():
    api_key = request.args.get('api_key', '')
    client_ip = request.args.get('client_ip', '')
    result = {}
    if api_key:
        result['key'] = {'summary': get_pattern_summary(api_key)}
    if client_ip:
        current_minute = now_utc().strftime('%Y%m%d%H%M')
        ip_key = f"{client_ip}:{current_minute}"
        ip_count = ip_rate_limits.get(ip_key, 0)
        usage_pct = round(ip_count / MAX_REQUESTS_PER_MINUTE_PER_IP * 100, 1)
        result['ip'] = {
            'requests_this_minute': ip_count,
            'limit': MAX_REQUESTS_PER_MINUTE_PER_IP,
            'usage_pct': usage_pct,
            'at_limit': ip_count >= MAX_REQUESTS_PER_MINUTE_PER_IP,
        }
    if not api_key and not client_ip:
        now = time.time()
        all_patterns = {k: get_pattern_summary(k) for k in list(request_patterns.keys())[:20]}
        hourly_keys = len([k for k, v in rate_limits.items()
                          if k.split(':')[-1].startswith(now_utc().strftime('%Y%m%d%H'))])
        result['overview'] = {
            'total_keys_tracked': len(request_patterns),
            'sample_keys': all_patterns,
            'active_minute_buckets': hourly_keys,
        }
    return jsonify(result), 200


if __name__ == '__main__':
    from waitress import serve
    port = int(os.environ.get('PORT', 5002))
    serve(app, host='0.0.0.0', port=port, threads=50)
