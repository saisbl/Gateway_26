from flask import Flask, render_template, request, jsonify, redirect, url_for
import requests
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max for large bulk uploads

# Configure session with connection pooling for better performance
session = requests.Session()
adapter = requests.adapters.HTTPAdapter(
    pool_connections=50,
    pool_maxsize=50,
    max_retries=3
)
session.mount('http://', adapter)
session.mount('https://', adapter)

# Authorization cache to avoid repeated checks
auth_cache = {}
auth_cache_ttl = 60  # Cache for 60 seconds

# Create uploads directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Service URLs
GPU_SERVICE_URL = "http://localhost:5001"
POLICY_SERVICE_URL = "http://localhost:5002"
SCANNER_SERVICE_URL = "http://localhost:5003"

@app.route('/')
def index():
    return render_template('index.html')

def process_single_file(file, api_key, client_ip):
    """Process a single file through the security gateway"""
    file_result = {
        'filename': file.filename,
        'status': 'pending',
        'latency': {}
    }
    
    # Save file temporarily
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(filepath)
    
    try:
        # Step 1: Authorize with Policy Service
        auth_start = time.time()
        file_size = os.path.getsize(filepath)
        auth_data = {
            "api_key": api_key,
            "endpoint": "/infer",
            "file_size": file_size,
            "client_ip": client_ip
        }
        
        auth_response = session.post(f"{POLICY_SERVICE_URL}/authorize", json=auth_data, timeout=10)
        auth_result = auth_response.json()
        auth_latency = (time.time() - auth_start) * 1000  # Convert to ms
        
        file_result['latency']['authorization_ms'] = round(auth_latency, 2)
        
        if not auth_result.get('allowed'):
            os.remove(filepath)
            file_result.update({
                'status': 'rejected',
                'step': 'authorization',
                'reason': auth_result.get('reason'),
                'message': auth_result.get('message')
            })
            return file_result
        
        # Step 2: Scan with Scanner Service
        scan_start = time.time()
        with open(filepath, 'rb') as f:
            scan_response = session.post(f"{SCANNER_SERVICE_URL}/scan", files={'file': f}, timeout=10)
        
        scan_result = scan_response.json()
        scan_latency = (time.time() - scan_start) * 1000  # Convert to ms
        
        file_result['latency']['scanning_ms'] = round(scan_latency, 2)
        
        if not scan_result.get('allowed'):
            os.remove(filepath)
            file_result.update({
                'status': 'rejected',
                'step': 'scanning',
                'reason': scan_result.get('reason'),
                'message': scan_result.get('message')
            })
            return file_result
        
        # Step 3: Process with GPU Service
        gpu_start = time.time()
        with open(filepath, 'rb') as f:
            gpu_response = session.post(f"{GPU_SERVICE_URL}/infer", files={'file': f}, timeout=10)
        
        gpu_result = gpu_response.json()
        gpu_latency = (time.time() - gpu_start) * 1000  # Convert to ms
        
        file_result['latency']['inference_ms'] = round(gpu_latency, 2)
        file_result['latency']['total_security_ms'] = round(auth_latency + scan_latency, 2)
        file_result['latency']['total_processing_ms'] = round(auth_latency + scan_latency + gpu_latency, 2)
        
        # Clean up
        os.remove(filepath)
        
        file_result.update({
            'status': 'success',
            'authorization': auth_result,
            'scanning': scan_result,
            'inference': gpu_result
        })
        return file_result
        
    except Exception as e:
        if os.path.exists(filepath):
            os.remove(filepath)
        file_result.update({
            'status': 'error',
            'error': str(e)
        })
        return file_result

@app.route('/upload', methods=['POST'])
def upload_file():
    files = request.files.getlist('files')
    
    if not files or len(files) == 0:
        return jsonify({'error': 'No files provided'}), 400
    
    # Filter out empty file selections
    files = [f for f in files if f.filename != '']
    
    if not files:
        return jsonify({'error': 'No files selected'}), 400
    
    # Get API key from form
    api_key = request.form.get('api_key', 'demo-key-123')
    
    results = []
    total_start_time = time.time()
    
    # Process files in parallel using ThreadPoolExecutor with increased workers
    # Increased to 50 workers for better parallelization of large batches
    max_workers = min(50, len(files))  # Increased from 5 to 50 for better throughput
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all file processing tasks
        future_to_file = {
            executor.submit(process_single_file, file, api_key, request.remote_addr): file
            for file in files
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_file):
            result = future.result()
            results.append(result)
    
    total_time = (time.time() - total_start_time) * 1000
    
    return jsonify({
        'status': 'completed',
        'total_files': len(files),
        'successful': len([r for r in results if r['status'] == 'success']),
        'failed': len([r for r in results if r['status'] in ['rejected', 'error']]),
        'total_processing_time_ms': round(total_time, 2),
        'results': results
    })

@app.route('/health')
def health():
    """Check health of all services"""
    services = {
        'gpu_service': f"{GPU_SERVICE_URL}/health",
        'policy_service': f"{POLICY_SERVICE_URL}/health",
        'scanner_service': f"{SCANNER_SERVICE_URL}/health"
    }
    
    results = {}
    for name, url in services.items():
        try:
            response = requests.get(url, timeout=2)
            results[name] = {
                'status': 'healthy' if response.status_code == 200 else 'unhealthy',
                'response': response.json()
            }
        except Exception as e:
            results[name] = {
                'status': 'unhealthy',
                'error': str(e)
            }
    
    return jsonify(results)

if __name__ == '__main__':
    print("Starting Web Dashboard...")
    print("Open http://localhost:8080 in your browser")
    app.run(host='0.0.0.0', port=8080, debug=True)
