import requests
import os

def test_service(url, name):
    try:
        response = requests.get(url, timeout=5)
        print(f"{name}: {response.status_code} - {response.json()}")
        return True
    except Exception as e:
        print(f"{name}: FAILED - {str(e)}")
        return False

def test_gpu_service():
    print("\n=== Testing Mock GPU Service ===")
    test_service("http://localhost:5001/health", "Health Check")
    
    # Test inference with a file
    try:
        with open("demo-files/valid-image.png", "rb") as f:
            response = requests.post("http://localhost:5001/infer", files={"file": f})
        print(f"Inference Test: {response.status_code} - {response.json()}")
    except Exception as e:
        print(f"Inference Test: FAILED - {str(e)}")

def test_policy_service():
    print("\n=== Testing Policy Service ===")
    test_service("http://localhost:5002/health", "Health Check")
    
    # Test authorization
    try:
        data = {
            "api_key": "demo-key-123",
            "endpoint": "/infer",
            "file_size": 1024,
            "client_ip": "127.0.0.1"
        }
        response = requests.post("http://localhost:5002/authorize", json=data)
        print(f"Authorize Test: {response.status_code} - {response.json()}")
    except Exception as e:
        print(f"Authorize Test: FAILED - {str(e)}")

def test_scanner_service():
    print("\n=== Testing Scanner Service ===")
    test_service("http://localhost:5003/health", "Health Check")
    
    # Test scan with a file
    try:
        with open("demo-files/valid-image.png", "rb") as f:
            response = requests.post("http://localhost:5003/scan", files={"file": f})
        print(f"Scan Test: {response.status_code} - {response.json()}")
    except FileNotFoundError:
        print(f"Scan Test: SKIPPED - File not found at demo-files/valid-image.png")
    except Exception as e:
        print(f"Scan Test: FAILED - {str(e)}")

if __name__ == "__main__":
    print("Testing Gateway Services...")
    test_gpu_service()
    test_policy_service()
    test_scanner_service()
    print("\n=== All Tests Complete ===")
