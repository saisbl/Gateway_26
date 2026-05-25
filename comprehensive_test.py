import requests
import time

def test_rate_limiting():
    """Test rate limiting by sending 6 requests (limit is 5)"""
    print("\n=== Testing Rate Limiting ===")
    
    url = "http://localhost:5002/authorize"
    data = {
        "api_key": "demo-key-123",
        "endpoint": "/infer",
        "file_size": 1024,
        "client_ip": "127.0.0.1"
    }
    
    blocked = False
    for i in range(1, 7):
        response = requests.post(url, json=data)
        result = response.json()
        
        if response.status_code == 429:
            print(f"  Request {i}: BLOCKED (429) - Rate limit exceeded [OK]")
            blocked = True
        elif response.status_code == 200:
            print(f"  Request {i}: ALLOWED (200) - Requests this minute: {result.get('requests_this_minute')}")
        else:
            print(f"  Request {i}: Unexpected status {response.status_code}")
        
        time.sleep(0.3)
    
    if blocked:
        print("  [OK] Rate limiting working correctly")
    else:
        print("  [FAIL] Rate limiting NOT working - 6th request should have been blocked")
    
    return blocked

def test_invalid_api_key():
    """Test that invalid API key is rejected"""
    print("\n=== Testing Invalid API Key ===")
    
    url = "http://localhost:5002/authorize"
    data = {
        "api_key": "invalid-key",
        "endpoint": "/infer",
        "file_size": 1024,
        "client_ip": "127.0.0.1"
    }
    
    response = requests.post(url, json=data)
    
    if response.status_code == 401:
        print("  [OK] Invalid API key correctly rejected (401)")
        return True
    else:
        print(f"  [FAIL] Invalid API key NOT rejected - Status: {response.status_code}")
        return False

def test_file_size_limit():
    """Test that oversized files are rejected"""
    print("\n=== Testing File Size Limit ===")
    
    url = "http://localhost:5002/authorize"
    data = {
        "api_key": "demo-key-123",
        "endpoint": "/infer",
        "file_size": 15 * 1024 * 1024,  # 15MB (over 10MB limit)
        "client_ip": "127.0.0.1"
    }
    
    response = requests.post(url, json=data)
    
    if response.status_code == 413:
        print("  [OK] Oversized file correctly rejected (413)")
        return True
    else:
        print(f"  [FAIL] Oversized file NOT rejected - Status: {response.status_code}")
        return False

def test_scanner_with_different_files():
    """Test scanner with different file types"""
    print("\n=== Testing Scanner with Different Files ===")
    
    url = "http://localhost:5003/scan"
    
    # Test valid PNG
    try:
        with open("demo-files/valid-image.png", "rb") as f:
            response = requests.post(url, files={"file": f})
        
        if response.status_code == 200 and response.json().get("allowed"):
            print("  [OK] Valid PNG accepted")
        else:
            print(f"  [FAIL] Valid PNG rejected - Status: {response.status_code}")
    except FileNotFoundError:
        print("  - Valid PNG test skipped (file not found)")
    
    # Test fake file (double extension)
    try:
        with open("demo-files/fake-image.jpg.exe", "rb") as f:
            response = requests.post(url, files={"file": f})
        
        if response.status_code == 403:
            print("  [OK] Fake file (double extension) correctly rejected (403)")
        else:
            print(f"  [FAIL] Fake file NOT rejected - Status: {response.status_code}")
    except FileNotFoundError:
        print("  - Fake file test skipped (file not found)")
    
    # Test malformed file
    try:
        with open("demo-files/malformed.jpg", "rb") as f:
            response = requests.post(url, files={"file": f})
        
        if response.status_code == 403:
            print("  [OK] Malformed file correctly rejected (403)")
        else:
            print(f"  [FAIL] Malformed file NOT rejected - Status: {response.status_code}")
    except FileNotFoundError:
        print("  - Malformed file test skipped (file not found)")

def test_gpu_inference():
    """Test GPU inference with valid file"""
    print("\n=== Testing GPU Inference ===")
    
    url = "http://localhost:5001/infer"
    
    try:
        with open("demo-files/valid-image.png", "rb") as f:
            response = requests.post(url, files={"file": f})
        
        if response.status_code == 200:
            result = response.json()
            print(f"  [OK] Inference successful")
            print(f"    Status: {result.get('status')}")
            print(f"    Labels: {result.get('labels')}")
            print(f"    Latency: {result.get('latency_ms')}ms")
            return True
        else:
            print(f"  [FAIL] Inference failed - Status: {response.status_code}")
            return False
    except FileNotFoundError:
        print("  - Inference test skipped (file not found)")
        return False

def test_endpoint_permissions():
    """Test that API keys have correct endpoint permissions"""
    print("\n=== Testing Endpoint Permissions ===")
    
    url = "http://localhost:5002/authorize"
    
    # Test demo-key-123 (should have access to /infer and /upload)
    data = {
        "api_key": "demo-key-123",
        "endpoint": "/infer",
        "file_size": 1024
    }
    response = requests.post(url, json=data)
    if response.status_code == 200 and response.json().get("allowed"):
        print("  [OK] demo-key-123 has access to /infer")
    else:
        print("  [FAIL] demo-key-123 does NOT have access to /infer")
    
    # Test test-key-456 (should only have access to /infer)
    data = {
        "api_key": "test-key-456",
        "endpoint": "/infer",
        "file_size": 1024
    }
    response = requests.post(url, json=data)
    if response.status_code == 200 and response.json().get("allowed"):
        print("  [OK] test-key-456 has access to /infer")
    else:
        print("  [FAIL] test-key-456 does NOT have access to /infer")
    
    # Test test-key-456 with /upload (should be denied)
    data = {
        "api_key": "test-key-456",
        "endpoint": "/upload",
        "file_size": 1024
    }
    response = requests.post(url, json=data)
    if response.status_code == 403:
        print("  [OK] test-key-456 correctly denied access to /upload (403)")
    else:
        print(f"  [FAIL] test-key-456 should NOT have access to /upload - Status: {response.status_code}")

if __name__ == "__main__":
    print("=" * 60)
    print("COMPREHENSIVE GATEWAY SECURITY TESTS")
    print("=" * 60)
    
    # Test basic functionality
    test_gpu_inference()
    
    # Test security features
    test_invalid_api_key()
    test_file_size_limit()
    test_endpoint_permissions()
    
    # Test scanner
    test_scanner_with_different_files()
    
    # Test rate limiting (wait a bit to reset counter)
    print("\n  Waiting 2 seconds before rate limit test...")
    time.sleep(2)
    test_rate_limiting()
    
    print("\n" + "=" * 60)
    print("ALL TESTS COMPLETE")
    print("=" * 60)
