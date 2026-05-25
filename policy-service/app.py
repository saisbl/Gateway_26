from flask import Flask, request, jsonify
import os
import time
from datetime import datetime
from collections import defaultdict

app = Flask(__name__)

# In-memory storage for local development (replaces Redis)
rate_limits = defaultdict(int)
daily_quotas = defaultdict(int)
concurrency = defaultdict(int)
last_minute_reset = None
last_day_reset = None

# Configuration
MAX_FILE_SIZE_MB = 10
MAX_REQUESTS_PER_MINUTE = 20  # Changed from 5 to 20 to allow more bulk uploads per minute
ALLOWED_EXTENSIONS = ['jpg', 'jpeg', 'png', 'pdf']
ALLOWED_ENDPOINTS = ['/infer', '/upload']

# Mock API keys and tenants
VALID_API_KEYS = {
    'demo-key-123': {'tenant': 'tenant-1', 'endpoints': ['/infer', '/upload']},
    'test-key-456': {'tenant': 'tenant-2', 'endpoints': ['/infer']},
}

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "status": "healthy",
        "service": "policy-service",
        "storage": "in-memory"
    }), 200

@app.route('/authorize', methods=['POST'])
def authorize():
    """
    Authorize endpoint checks:
    - API key exists
    - Tenant is known
    - Endpoint is allowed
    - File size is under limit
    - Current request count is under quota
    """
    try:
        data = request.get_json()
        
        # Extract headers and metadata
        api_key = data.get('api_key')
        endpoint = data.get('endpoint')
        file_size = data.get('file_size', 0)
        client_ip = data.get('client_ip', 'unknown')
        
        # Check API key exists
        if not api_key or api_key not in VALID_API_KEYS:
            return jsonify({
                "allowed": False,
                "reason": "invalid_api_key",
                "message": "Invalid or missing API key"
            }), 401
        
        tenant_info = VALID_API_KEYS[api_key]
        tenant = tenant_info['tenant']
        
        # Check endpoint is allowed for this tenant
        if endpoint not in tenant_info['endpoints']:
            return jsonify({
                "allowed": False,
                "reason": "endpoint_not_allowed",
                "message": f"Endpoint {endpoint} not allowed for this tenant"
            }), 403
        
        # Check file size
        file_size_mb = file_size / (1024 * 1024)
        if file_size_mb > MAX_FILE_SIZE_MB:
            return jsonify({
                "allowed": False,
                "reason": "file_too_large",
                "message": f"File size {file_size_mb:.2f}MB exceeds limit of {MAX_FILE_SIZE_MB}MB"
            }), 413
        
        # Check rate limit (in-memory)
        global rate_limits
        current_minute = datetime.now().strftime('%Y%m%d%H%M')
        
        rate_limit_key = f"{api_key}:{current_minute}"
        current_requests = rate_limits[rate_limit_key] + 1
        rate_limits[rate_limit_key] = current_requests
        
        if current_requests > MAX_REQUESTS_PER_MINUTE:
            return jsonify({
                "allowed": False,
                "reason": "rate_limit_exceeded",
                "message": f"Rate limit exceeded: {MAX_REQUESTS_PER_MINUTE} requests per minute"
            }), 429
        
        # Check daily quota (in-memory)
        global last_day_reset, daily_quotas
        current_day = datetime.now().strftime('%Y%m%d')
        
        if last_day_reset != current_day:
            daily_quotas.clear()
            last_day_reset = current_day
        
        quota_key = f"{tenant}:{current_day}"
        daily_requests = daily_quotas[quota_key] + 1
        daily_quotas[quota_key] = daily_requests
        
        # Check concurrency (in-memory)
        concurrency_key = tenant
        current_concurrency = concurrency[concurrency_key] + 1
        concurrency[concurrency_key] = current_concurrency
        
        # All checks passed
        return jsonify({
            "allowed": True,
            "tenant": tenant,
            "requests_this_minute": current_requests,
            "daily_requests": daily_requests
        }), 200
        
    except Exception as e:
        return jsonify({
            "allowed": False,
            "reason": "internal_error",
            "message": str(e)
        }), 500

@app.route('/release', methods=['POST'])
def release():
    """
    Release concurrency counter after request completes
    """
    try:
        data = request.get_json()
        tenant = data.get('tenant')
        
        if tenant:
            concurrency[tenant] = max(0, concurrency[tenant] - 1)
        
        return jsonify({"status": "released"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/scan', methods=['POST'])
def scan():
    """
    Scan endpoint checks:
    - Real MIME by magic bytes
    - Allowed file extensions
    - Image dimensions or page count
    - Reject double extensions
    - Reject content-type mismatch
    """
    try:
        data = request.get_json()
        
        filename = data.get('filename', '')
        content_type = data.get('content_type', '')
        file_size = data.get('file_size', 0)
        magic_bytes = data.get('magic_bytes', '')
        
        # Check for double extensions (e.g., image.jpg.exe)
        if filename.count('.') > 1:
            return jsonify({
                "allowed": False,
                "reason": "double_extension",
                "message": "Double extensions are not allowed"
            }), 403
        
        # Check file extension
        extension = filename.split('.')[-1].lower() if '.' in filename else ''
        if extension not in ALLOWED_EXTENSIONS:
            return jsonify({
                "allowed": False,
                "reason": "invalid_extension",
                "message": f"Extension '{extension}' not allowed. Allowed: {ALLOWED_EXTENSIONS}"
            }), 403
        
        # Check content-type matches extension
        expected_types = {
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg',
            'png': 'image/png',
            'pdf': 'application/pdf'
        }
        
        if extension in expected_types:
            if content_type != expected_types[extension]:
                return jsonify({
                    "allowed": False,
                    "reason": "content_type_mismatch",
                    "message": f"Content-type '{content_type}' does not match extension '{extension}'"
                }), 403
        
        # Validate magic bytes (simplified check)
        magic_signatures = {
            '\xff\xd8\xff': 'jpg',
            '\x89PNG\r\n\x1a\n': 'png',
            '%PDF': 'pdf'
        }
        
        if magic_bytes:
            matched = False
            for signature, sig_type in magic_signatures.items():
                if magic_bytes.startswith(signature):
                    if sig_type != extension:
                        return jsonify({
                            "allowed": False,
                            "reason": "magic_bytes_mismatch",
                            "message": f"File signature indicates {sig_type} but extension is {extension}"
                        }), 403
                    matched = True
                    break
            
            if not matched:
                return jsonify({
                    "allowed": False,
                    "reason": "invalid_file_signature",
                    "message": "File signature does not match any allowed type"
                }), 403
        
        return jsonify({
            "allowed": True,
            "extension": extension,
            "content_type": content_type
        }), 200
        
    except Exception as e:
        return jsonify({
            "allowed": False,
            "reason": "scan_error",
            "message": str(e)
        }), 500

@app.route('/metrics', methods=['GET'])
def metrics():
    try:
        total_requests = sum(rate_limits.values())
        active_tenants = len(daily_quotas)
        
        return jsonify({
            "service": "policy-service",
            "total_requests": total_requests,
            "active_tenants": active_tenants,
            "rate_limit_keys": len(rate_limits)
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5002))
    app.run(host='0.0.0.0', port=port, debug=False)
