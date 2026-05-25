#!/bin/bash

# Test rate limiting
# This script tests that rate limiting blocks excessive requests

echo "=== Testing Rate Limiting ==="
echo ""

GATEWAY_URL="http://localhost:8080"
API_KEY="demo-key-123"
MAX_REQUESTS=6  # Exceeds the limit of 5 per minute

echo "Sending ${MAX_REQUESTS} requests (limit is 5 per minute)..."
echo ""

for i in $(seq 1 $MAX_REQUESTS); do
  echo "Request ${i}:"
  response=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "${GATEWAY_URL}/api/infer" \
    -H "x-api-key: ${API_KEY}" \
    -F "file=@demo-files/valid-image.png")
  
  if [ $response -eq 429 ]; then
    echo "  ✗ Blocked (429) - Rate limit exceeded"
  elif [ $response -eq 200 ]; then
    echo "  ✓ Allowed (200)"
  else
    echo "  ? Unexpected response: ${response}"
  fi
  
  sleep 0.5
done

echo ""
echo "=== Expected: First 5 requests allowed, 6th blocked with 429 ==="
