import requests
import time

def test_rate_limit():
    """Test rate limiting with new limit of 20 requests per minute"""
    print("\n=== Testing Rate Limiting (20 requests per minute) ===")
    
    url = "http://localhost:5002/authorize"
    data = {
        "api_key": "demo-key-123",
        "endpoint": "/infer",
        "file_size": 1024,
        "client_ip": "127.0.0.1"
    }
    
    blocked_count = 0
    for i in range(1, 22):  # Test 21 requests (should block after 20)
        response = requests.post(url, json=data)
        result = response.json()
        
        if response.status_code == 429:
            print(f"  Request {i}: BLOCKED (429) - Rate limit exceeded [OK]")
            blocked_count += 1
        elif response.status_code == 200:
            print(f"  Request {i}: ALLOWED (200) - Requests this minute: {result.get('requests_this_minute')}")
        else:
            print(f"  Request {i}: Unexpected status {response.status_code}")
        
        time.sleep(0.2)  # Small delay between requests
    
    if blocked_count >= 1:
        print(f"  [OK] Rate limiting working correctly - {blocked_count} request(s) blocked after 20 allowed")
    else:
        print("  [FAIL] Rate limiting NOT working - 21st request should have been blocked")

if __name__ == "__main__":
    test_rate_limit()
