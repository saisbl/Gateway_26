#!/bin/bash

# Test malicious file detection
# This script tests that malicious/fake files are rejected

echo "=== Testing Malicious File Detection ==="
echo ""

GATEWAY_URL="http://localhost:8080"
API_KEY="demo-key-123"

echo "Test 1: Double extension (fake-image.jpg.exe)"
curl -s -X POST "${GATEWAY_URL}/api/infer" \
  -H "x-api-key: ${API_KEY}" \
  -F "file=@demo-files/fake-image.jpg.exe" \
  -w "\nHTTP Status: %{http_code}\n"

echo ""
echo "Test 2: Oversized file (large-file.jpg)"
curl -s -X POST "${GATEWAY_URL}/api/infer" \
  -H "x-api-key: ${API_KEY}" \
  -F "file=@demo-files/large-file.jpg" \
  -w "\nHTTP Status: %{http_code}\n"

echo ""
echo "Test 3: Malformed file (malformed.jpg)"
curl -s -X POST "${GATEWAY_URL}/api/infer" \
  -H "x-api-key: ${API_KEY}" \
  -F "file=@demo-files/malformed.jpg" \
  -w "\nHTTP Status: %{http_code}\n"

echo ""
echo "Test 4: Invalid API key"
curl -s -X POST "${GATEWAY_URL}/api/infer" \
  -H "x-api-key: invalid-key" \
  -F "file=@demo-files/valid-image.png" \
  -w "\nHTTP Status: %{http_code}\n"

echo ""
echo "=== Expected: All blocked with appropriate error codes ==="
echo "- Double extension: 403"
echo "- Oversized: 413"
echo "- Malformed: 403"
echo "- Invalid key: 401"
