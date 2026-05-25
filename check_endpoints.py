import requests
import json

def check_endpoint(url, name):
    try:
        response = requests.get(url, timeout=5)
        print(f"\n{name}")
        print(f"URL: {url}")
        print(f"Status: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
    except Exception as e:
        print(f"\n{name}")
        print(f"URL: {url}")
        print(f"Error: {str(e)}")

print("=" * 60)
print("AVAILABLE SERVICE ENDPOINTS")
print("=" * 60)

# Mock GPU Service endpoints
print("\n--- MOCK GPU SERVICE (Port 5001) ---")
check_endpoint("http://localhost:5001/health", "Health Check")

# Policy Service endpoints
print("\n--- POLICY SERVICE (Port 5002) ---")
check_endpoint("http://localhost:5002/health", "Health Check")
check_endpoint("http://localhost:5002/metrics", "Metrics")

# Scanner Service endpoints
print("\n--- SCANNER SERVICE (Port 5003) ---")
check_endpoint("http://localhost:5003/health", "Health Check")
check_endpoint("http://localhost:5003/metrics", "Metrics")

print("\n" + "=" * 60)
print("You can access these URLs in your browser:")
print("=" * 60)
print("http://localhost:5001/health - GPU Service Health")
print("http://localhost:5002/health - Policy Service Health")
print("http://localhost:5002/metrics - Policy Service Metrics")
print("http://localhost:5003/health - Scanner Service Health")
print("http://localhost:5003/metrics - Scanner Service Metrics")
print("=" * 60)
