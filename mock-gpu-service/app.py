from flask import Flask, request, jsonify
import time
import random
import os

app = Flask(__name__)

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy", "service": "mock-gpu-service"}), 200

@app.route('/infer', methods=['POST'])
def infer():
    """
    Mock GPU inference endpoint.
    Accepts a file and returns simulated processing results.
    """
    start_time = time.time()
    
    # Check if file is present
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    # Simulate processing time (100-200ms)
    processing_time = random.uniform(0.1, 0.2)
    time.sleep(processing_time)
    
    # Simulate different labels based on file type
    filename = file.filename.lower()
    if filename.endswith('.pdf'):
        labels = ["document", "text"]
    elif filename.endswith(('.jpg', '.jpeg', '.png')):
        labels = ["image", "visual"]
    else:
        labels = ["unknown"]
    
    latency_ms = int(processing_time * 1000)
    
    response = {
        "status": "processed",
        "model": "mock-vision-v1",
        "labels": labels,
        "latency_ms": latency_ms,
        "file_size": len(file.read()) if file else 0
    }
    
    return jsonify(response), 200

@app.route('/metrics', methods=['GET'])
def metrics():
    return jsonify({
        "service": "mock-gpu-service",
        "requests_processed": 0,
        "avg_latency_ms": 150
    }), 200

if __name__ == '__main__':
    from waitress import serve
    port = int(os.environ.get('PORT', 5001))
    serve(app, host='0.0.0.0', port=port, threads=50)
