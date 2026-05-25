#!/bin/bash

# Test valid file upload
# This script tests that a valid file is accepted by the gateway

echo "=== Testing Valid File Upload ==="
echo ""

GATEWAY_URL="http://localhost:8080"
API_KEY="demo-key-123"

echo "Testing with valid-image.png..."
curl -X POST "${GATEWAY_URL}/api/infer" \
  -H "x-api-key: ${API_KEY}" \
  -F "file=@demo-files/valid-image.png" \
  -v

echo ""
echo "=== Expected: 200 OK with processed response ==="
