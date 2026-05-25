# Security Gateway Demo

A comprehensive demonstration of an API gateway architecture that protects AI services with authentication, rate limiting, file scanning, and observability.

## Demo Story

This demo showcases how a gateway protects expensive AI services without adding significant latency. In 5 minutes, you'll see:

- **Valid image upload** gets accepted and forwarded to the backend
- **Oversized or fake files** get rejected before reaching the GPU service
- **Too many requests** trigger rate-limiting to prevent abuse
- **Dashboard** shows the request path and failure reasons

The message is clear: the gateway protects backend services from resource exhaustion and malicious inputs while maintaining low latency.

## Architecture

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Envoy     │  ← Front door (Port 8080)
│  (Gateway)  │
└──────┬──────┘
       │
       ├──────────────┐
       │              │
       ▼              ▼
┌─────────────┐  ┌─────────────┐
│   Policy    │  │  Scanner    │
│  Service    │  │  Service    │
│  (Authz)    │  │  (Scan)     │
└──────┬──────┘  └─────────────┘
       │
       ▼
┌─────────────┐
│    Redis    │  ← Rate limiting & quotas
└─────────────┘
       │
       ▼
┌─────────────┐
│  Mock GPU   │  ← Protected backend service
│  Service    │
└─────────────┘
```

### Components

- **Envoy**: API gateway with external authorization
- **Policy Service**: Authorization, rate limiting, quota management
- **Scanner Service**: Deep file validation (magic bytes, MIME types, dimensions)
- **Mock GPU Service**: Simulated AI inference backend
- **Redis**: Rate limiting and quota storage
- **OpenTelemetry Collector**: Observability (traces, metrics, logs)
- **Prometheus**: Metrics visualization

## Security Features

### 1. Authentication & Authorization
- API key validation
- Tenant-based access control
- Endpoint-level permissions

### 2. Rate Limiting
- 5 requests per minute per API key
- Daily quota per tenant
- Concurrency limits

### 3. File Scanning
- Magic byte validation (real MIME type detection)
- Extension whitelist (jpg, jpeg, png, pdf)
- Double extension rejection (e.g., image.jpg.exe)
- Content-type mismatch detection
- File size limits (10MB max)
- Image dimension validation
- PDF page count limits

### 4. Observability
- Request tracing across all services
- Metrics for requests, rejections, latency
- Logs with failure reasons

## Quick Start

### Prerequisites

- Docker and Docker Compose
- (Optional) Python 3.11+ for running test scripts locally

### Start the Demo

```bash
# Start all services
docker-compose up -d

# Check service status
docker-compose ps

# View logs
docker-compose logs -f
```

Services will be available at:
- **Gateway**: http://localhost:8080
- **Envoy Admin**: http://localhost:9901
- **Prometheus**: http://localhost:9090
- **Policy Service**: http://localhost:5002
- **Scanner Service**: http://localhost:5003
- **Mock GPU Service**: http://localhost:5001

### Generate Test Files

```bash
cd demo-files
python generate_test_files.py
```

This creates:
- `valid-image.png` - Small valid PNG (should be accepted)
- `large-file.jpg` - Oversized JPG (>10MB, should be rejected)
- `fake-image.jpg.exe` - Double extension (should be rejected)
- `malformed.jpg` - Invalid magic bytes (should be rejected)
- `valid-document.pdf` - Valid PDF (should be accepted)

## Running Tests

### Windows (PowerShell)

```powershell
cd scripts
.\test-all.ps1
```

### Linux/Mac (Bash)

```bash
cd scripts

# Test valid file
bash test-valid.sh

# Test rate limiting
bash test-rate-limit.sh

# Test malicious files
bash test-malicious.sh
```

### Manual Testing with curl

```bash
# Valid upload (should succeed)
curl -X POST http://localhost:8080/api/infer \
  -H "x-api-key: demo-key-123" \
  -F "file=@demo-files/valid-image.png"

# Invalid API key (should fail with 401)
curl -X POST http://localhost:8080/api/infer \
  -H "x-api-key: invalid-key" \
  -F "file=@demo-files/valid-image.png"

# Rate limiting (6th request should fail with 429)
for i in {1..6}; do
  curl -X POST http://localhost:8080/api/infer \
    -H "x-api-key: demo-key-123" \
    -F "file=@demo-files/valid-image.png"
  echo "Request $i"
  sleep 0.5
done
```

## API Endpoints

### Gateway (via Envoy)

- `POST /api/infer` - Upload file for inference
- `POST /api/upload` - Upload file (routed to policy)
- `GET /health` - Health check
- `GET /metrics` - Service metrics

### Policy Service

- `POST /authorize` - Authorization check
- `POST /scan` - File metadata scan
- `POST /release` - Release concurrency counter
- `GET /health` - Health check
- `GET /metrics` - Policy metrics

### Scanner Service

- `POST /scan` - Deep file validation
- `POST /scan-metadata` - Lightweight metadata scan
- `GET /health` - Health check
- `GET /metrics` - Scanner metrics

### Mock GPU Service

- `POST /infer` - Simulated inference endpoint
- `GET /health` - Health check
- `GET /metrics` - GPU service metrics

## Configuration

### API Keys

Valid API keys (configured in `policy-service/app.py`):
- `demo-key-123` - Full access (tenant-1)
- `test-key-456` - Limited access (tenant-2)

### Rate Limits

- 5 requests per minute per API key
- 10MB maximum file size
- 10000px maximum image dimension
- 100 pages maximum for PDFs

### Allowed File Types

- Images: jpg, jpeg, png
- Documents: pdf

## Observability

### Prometheus Metrics

Access Prometheus at http://localhost:9090

Key metrics:
- Request count by status
- Rejection count by reason
- P95 latency
- Bytes uploaded
- Active tenants

### OpenTelemetry Traces

The OpenTelemetry Collector receives traces from all services:
- Gateway receive
- Auth check
- File scan
- Backend inference
- Response return

### Envoy Admin Interface

Access Envoy admin at http://localhost:9901

Useful endpoints:
- `/stats` - Statistics
- `/clusters` - Cluster status
- `/listeners` - Listener configuration

## Development

### Running Services Locally

If you prefer to run services without Docker:

```bash
# Install dependencies
cd policy-service && pip install -r requirements.txt
cd ../scanner-service && pip install -r requirements.txt
cd ../mock-gpu-service && pip install -r requirements.txt

# Start Redis (required)
docker run -d -p 6379:6379 redis:7-alpine

# Start services (in separate terminals)
cd policy-service && python app.py
cd scanner-service && python app.py
cd mock-gpu-service && python app.py

# Start Envoy
docker run -d -p 8080:8080 -p 9901:9901 \
  -v $(pwd)/envoy/envoy.yaml:/etc/envoy/envoy.yaml \
  envoyproxy/envoy:v1.29.0
```

### Adding New Security Rules

Edit `policy-service/app.py` to add:
- New API keys
- Different rate limits
- Additional authorization checks

Edit `scanner-service/app.py` to add:
- New file type validations
- Additional magic byte checks
- Custom scanning logic

## Troubleshooting

### Services won't start

```bash
# Check logs
docker-compose logs

# Restart specific service
docker-compose restart policy-service

# Rebuild containers
docker-compose up -d --build
```

### Rate limiting not working

Check Redis connection:
```bash
docker-compose exec redis redis-cli ping
```

### File scanning fails

Ensure system dependencies are installed in scanner-service Dockerfile:
```dockerfile
RUN apt-get update && apt-get install -y libmagic1
```

## Project Structure

```
security-gateway-demo/
├── docker-compose.yml          # Orchestration
├── README.md                   # This file
├── envoy/
│   └── envoy.yaml              # Envoy gateway config
├── policy-service/
│   ├── app.py                  # Authorization & rate limiting
│   ├── requirements.txt
│   └── Dockerfile
├── scanner-service/
│   ├── app.py                  # File validation
│   ├── requirements.txt
│   └── Dockerfile
├── mock-gpu-service/
│   ├── app.py                  # Simulated AI backend
│   ├── requirements.txt
│   └── Dockerfile
├── otel/
│   └── otel-collector-config.yaml  # OpenTelemetry config
├── prometheus/
│   └── prometheus.yml          # Prometheus config
├── demo-files/
│   ├── generate_test_files.py
│   └── README.md
└── scripts/
    ├── test-valid.sh
    ├── test-rate-limit.sh
    ├── test-malicious.sh
    └── test-all.ps1
```

## Security Best Practices Demonstrated

1. **Defense in Depth**: Multiple validation layers (auth, scan, rate limit)
2. **Fail Secure**: Default deny policy, explicit allow
3. **Least Privilege**: Tenant-based access control
4. **Input Validation**: Magic bytes, MIME types, extensions
5. **Resource Protection**: Rate limiting, quotas, size limits
6. **Observability**: Full tracing and metrics for security events

## References

- [Envoy Gateway Documentation](https://gateway.envoy.dev/)
- [Envoy External Authorization](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/http/ext_authz/v3/ext_authz.proto)
- [OpenTelemetry Demo](https://opentelemetry.io/docs/demo/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)

## License

This is a demonstration project for educational purposes.
