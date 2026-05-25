from flask import Flask, render_template, request, jsonify, redirect, url_for
import requests
import os

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max

# Create uploads directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Service URLs
GPU_SERVICE_URL = "http://localhost:5001"
POLICY_SERVICE_URL = "http://localhost:5002"
SCANNER_SERVICE_URL = "http://localhost:5003"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Get API key from form
    api_key = request.form.get('api_key', 'demo-key-123')
    
    # Save file temporarily
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(filepath)
    
    try:
        # Step 1: Authorize with Policy Service
        file_size = os.path.getsize(filepath)
        auth_data = {
            "api_key": api_key,
            "endpoint": "/infer",
            "file_size": file_size,
            "client_ip": request.remote_addr
        }
        
        auth_response = requests.post(f"{POLICY_SERVICE_URL}/authorize", json=auth_data)
        auth_result = auth_response.json()
        
        if not auth_result.get('allowed'):
            os.remove(filepath)
            return jsonify({
                'status': 'rejected',
                'step': 'authorization',
                'reason': auth_result.get('reason'),
                'message': auth_result.get('message')
            }), 403
        
        # Step 2: Scan with Scanner Service
        with open(filepath, 'rb') as f:
            scan_response = requests.post(f"{SCANNER_SERVICE_URL}/scan", files={'file': f})
        
        scan_result = scan_response.json()
        
        if not scan_result.get('allowed'):
            os.remove(filepath)
            return jsonify({
                'status': 'rejected',
                'step': 'scanning',
                'reason': scan_result.get('reason'),
                'message': scan_result.get('message')
            }), 403
        
        # Step 3: Process with GPU Service
        with open(filepath, 'rb') as f:
            gpu_response = requests.post(f"{GPU_SERVICE_URL}/infer", files={'file': f})
        
        gpu_result = gpu_response.json()
        
        # Clean up
        os.remove(filepath)
        
        return jsonify({
            'status': 'success',
            'authorization': auth_result,
            'scanning': scan_result,
            'inference': gpu_result
        })
        
    except Exception as e:
        if os.path.exists(filepath):
            os.remove(filepath)
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

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
