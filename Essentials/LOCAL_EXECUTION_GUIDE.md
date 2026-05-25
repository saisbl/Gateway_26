# Local Execution Guide (Without Docker)

This guide explains how to run the Gateway Architecture Demo locally without Docker, which is the alternative approach used when Docker is not available on the system.

## Overview

The project has been adapted to run locally without Docker by:
- Replacing Redis with in-memory Python data structures
- Removing `python-magic` dependency and implementing basic magic byte detection
- Running services as standalone Python processes

## Prerequisites

- Python 3.14 or higher
- pip (Python package manager)

## Installation

### 1. Install Dependencies

Install dependencies for each service:

```bash
# Mock GPU Service
pip install -r mock-gpu-service/requirements.txt

# Policy Service
pip install -r policy-service/requirements.txt

# Scanner Service
pip install -r scanner-service/requirements.txt

# Web Dashboard
pip install -r web-dashboard/requirements.txt
```

### 2. Create Demo Files

Create test files for testing:

```bash
mkdir demo-files
# Add your test images here (valid-image.png, fake-image.jpg.exe, malformed.jpg, etc.)
```

## Starting Services

### Start Backend Services (in separate terminals)

```bash
# Terminal 1: Mock GPU Service
cd mock-gpu-service
python app.py

# Terminal 2: Policy Service
cd policy-service
python app.py

# Terminal 3: Scanner Service
cd scanner-service
python app.py
```

### Start Web Dashboard

```bash
# Terminal 4: Web Dashboard
cd web-dashboard
python app.py
```

The web dashboard will be available at: http://localhost:8080

## Service Ports

- **Mock GPU Service**: http://localhost:5001
- **Policy Service**: http://localhost:5002
- **Scanner Service**: http://localhost:5003
- **Web Dashboard**: http://localhost:8080

## Key Modifications from Docker Version

### Policy Service (`policy-service/app.py`)

**Changes:**
- Removed Redis dependency
- Replaced `redis_client` with Python `defaultdict` for in-memory storage
- Updated rate limiting, daily quotas, and concurrency to use in-memory structures
- Health check endpoint shows `"storage": "in-memory"`

**Configuration:**
```python
MAX_FILE_SIZE_MB = 10
MAX_REQUESTS_PER_MINUTE = 20  # Increased from 5 for bulk uploads
ALLOWED_EXTENSIONS = ['jpg', 'jpeg', 'png', 'pdf']
```

### Scanner Service (`scanner-service/app.py`)

**Changes:**
- Removed `python-magic` dependency (which requires libmagic)
- Implemented basic magic byte detection for common file types:
  - PNG: `\x89PNG\r\n\x1a\n`
  - JPEG: `\xff\xd8\xff`
  - PDF: `%PDF`
- Windows-compatible without requiring external C libraries

### Web Dashboard (`web-dashboard/app.py`)

**Changes:**
- Increased worker pool from 5 to 50 for better parallelization
- Added authorization result caching (60-second TTL)
- Increased connection pool size from 10 to 50
- Increased max upload size from 100MB to 500MB
- Reduced request timeouts from 10s to 5s
- Supports bulk upload of multiple files

## Testing

### Run Basic Tests

```bash
python test_services.py
```

### Run Comprehensive Security Tests

```bash
python comprehensive_test.py
```

### Test Rate Limiting

```bash
python test_rate_limit.py
```

### Check Service Endpoints

```bash
python check_endpoints.py
```

## Using the Web Dashboard

1. Open http://localhost:8080 in your browser
2. Select multiple files (JPG, PNG, PDF)
3. Enter API key (default: `demo-key-123`)
4. Click "Upload and Process"
5. View results and latency metrics

## API Keys

- **demo-key-123**: Access to `/infer` and `/upload` endpoints
- **test-key-456**: Access to `/infer` endpoint only

## Rate Limiting

- **Limit**: 20 requests per minute per API key
- **Tracking**: Per API key per minute (in-memory)
- **Bulk Upload**: Unlimited files per request (up to 500MB total)

## Performance Optimizations

The local execution includes several performance optimizations:

1. **Parallel Processing**: 50 concurrent workers for bulk uploads
2. **Connection Pooling**: 50 HTTP connections reused across requests
3. **Authorization Caching**: 60-second cache for repeated auth checks
4. **Reduced Timeouts**: 5-second timeouts for faster failure detection

## Troubleshooting

### Port Already in Use

If a port is already in use, find and kill the process:

```bash
netstat -ano | findstr :5001
taskkill /F /PID <PID>
```

### Module Not Found

Install missing dependencies:

```bash
pip install flask requests werkzeug pillow
```

### Service Not Responding

Check if the service is running:

```bash
curl http://localhost:5001/health
curl http://localhost:5002/health
curl http://localhost:5003/health
```

## Differences from Docker Version

| Feature | Docker Version | Local Version |
|---------|---------------|--------------|
| Storage | Redis | In-memory (defaultdict) |
| File Type Detection | python-magic | Basic magic byte detection |
| Rate Limit | 5 req/min | 20 req/min |
| Worker Pool | 5 workers | 50 workers |
| Connection Pool | 10 connections | 50 connections |
| Max Upload | 100MB | 500MB |
| Deployment | Docker Compose | Manual process management |

## Stopping Services

To stop all services, press `Ctrl+C` in each terminal or use:

```bash
# Find and kill all Python processes on specific ports
netstat -ano | findstr "5001 5002 5003 8080"
taskkill /F /PID <PID>
```

## Notes

- **Persistence**: In-memory storage is not persistent across service restarts
- **Scalability**: Local execution is suitable for development and testing, not production
- **Security**: Same security checks as Docker version (authorization, scanning, rate limiting)
- **Performance**: Optimized for local development with reduced network overhead

## Next Steps

For production deployment, consider:
- Using Docker with Redis for persistent storage
- Implementing proper message queues for async processing
- Adding monitoring and logging infrastructure
- Using gRPC for inter-service communication
- Implementing proper load balancing
