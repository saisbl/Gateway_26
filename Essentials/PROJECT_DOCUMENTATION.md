# Gateway Architecture Demo - Complete Documentation

## Table of Contents
1. [Overview](#overview)
2. [Tech Stack](#tech-stack)
3. [Architecture](#architecture)
4. [Component Deep Dive](#component-deep-dive)
5. [How It Works](#how-it-works)
6. [Building the Project](#building-the-project)
7. [Running the Project](#running-the-project)
8. [Security Features](#security-features)
9. [Testing](#testing)
10. [Troubleshooting](#troubleshooting)
11. [Performance](#performance)
12. [Best Practices](#best-practices)
13. [Next Steps](#next-steps)

---

## Overview

This project demonstrates a secure gateway architecture for protecting AI/ML inference services. It implements multiple security layers including authentication, authorization, rate limiting, file validation, and malicious file detection.

### Key Features
- **External Authorization**: Envoy ExtAuthz integration for request-level security
- **Rate Limiting**: Per-API-key rate limiting with configurable quotas
- **File Validation**: Magic byte detection to prevent file type spoofing
- **Malicious File Detection**: Scanning for double extensions and malformed files
- **Observability**: OpenTelemetry integration with Prometheus and Grafana
- **Containerization**: Docker and Docker Compose for easy deployment

---

## Tech Stack

### Gateway Layer
- **Envoy**: High-performance proxy for external authorization and routing
- **OpenTelemetry**: Distributed tracing and metrics collection
- **Prometheus**: Metrics storage and querying
- **Grafana**: Visualization and monitoring dashboard

### Backend Services
- **Python 3.14**: Primary programming language
- **Flask**: Web framework for microservices
- **Redis**: Rate limiting and quota management (or in-memory for local execution)
- **python-magic**: File type detection via magic bytes (or custom implementation for local execution)

### Infrastructure
- **Docker**: Containerization
- **Docker Compose**: Multi-container orchestration
- **Linux/Unix**: Primary deployment target (with Windows support for local execution)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Client Request                          │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                    Envoy Gateway                             │
│  - External Authorization (ExtAuthz)                        │
│  - Rate Limiting                                            │
│  - Routing                                                  │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                  Policy Service                              │
│  - API Key Validation                                       │
│  - Endpoint Authorization                                   │
│  - File Size Checks                                         │
│  - Rate Limiting (Redis/In-memory)                          │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                  Scanner Service                             │
│  - Magic Byte Detection                                     │
│  - Extension Validation                                     │
│  - Malicious File Detection                                 │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                  GPU Service                                 │
│  - Image Inference                                          │
│  - Model Processing                                         │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                  Response to Client                          │
└─────────────────────────────────────────────────────────────┘
```

---

## Component Deep Dive

### 1. Envoy Gateway

**Purpose**: Acts as the entry point for all requests, implementing security policies before routing to backend services.

**Key Features**:
- **ExtAuthz**: External authorization integration with Policy Service
- **Rate Limiting**: Request-level rate limiting
- **Routing**: Intelligent routing to backend services
- **Observability**: OpenTelemetry integration for tracing and metrics

**Configuration**: `envoy.yaml`

### 2. Policy Service

**Purpose**: Central authorization and policy enforcement service.

**Key Features**:
- **API Key Validation**: Validates API keys against a whitelist
- **Endpoint Authorization**: Checks if API key has access to requested endpoint
- **File Size Validation**: Ensures files don't exceed size limits
- **Rate Limiting**: Enforces per-API-key rate limits (20 requests/minute)
- **Quota Management**: Tracks daily quotas per tenant

**Storage**: Redis (Docker) or in-memory defaultdict (local execution)

**Endpoints**:
- `/health`: Health check
- `/authorize`: Authorization check
- `/scan`: File metadata scan
- `/release`: Release concurrency
- `/metrics`: Service metrics

### 3. Scanner Service

**Purpose**: Validates file integrity and detects malicious files.

**Key Features**:
- **Magic Byte Detection**: Validates actual file type against extension
- **Extension Validation**: Checks against allowed extensions
- **Malicious File Detection**: Identifies double extensions and malformed files

**File Type Detection**: python-magic (Docker) or custom magic byte detection (local execution)

**Endpoints**:
- `/health`: Health check
- `/scan`: File scan
- `/scan-metadata`: Metadata scan
- `/metrics`: Service metrics

### 4. GPU Service (Mock)

**Purpose**: Simulates GPU inference for image processing.

**Key Features**:
- **Image Inference**: Processes images and returns labels
- **Latency Tracking**: Measures inference latency
- **Mock Implementation**: Simulates real GPU service behavior

**Endpoints**:
- `/health`: Health check
- `/infer`: Image inference

### 5. Web Dashboard

**Purpose**: Web interface for testing and monitoring the gateway.

**Key Features**:
- **Bulk Upload**: Supports uploading multiple files at once
- **Latency Tracking**: Displays security layer latency metrics
- **Service Status**: Real-time health monitoring
- **Results Visualization**: Shows processing results for each file

**Optimizations**:
- 50 concurrent workers for parallel processing
- Authorization result caching (60-second TTL)
- Connection pooling (50 connections)
- 500MB max upload size

---

## How It Works

### Request Flow

1. **Client Request**: Client sends request with API key and file
2. **Envoy Gateway**: Envoy forwards request to Policy Service for authorization
3. **Policy Service**: Validates API key, checks rate limits, authorizes endpoint
4. **Scanner Service**: Validates file type, checks for malicious files
5. **GPU Service**: Processes image and returns inference results
6. **Response**: Results returned to client through the gateway

### Security Layers

**Layer 1: Authentication**
- API key validation
- Tenant identification

**Layer 2: Authorization**
- Endpoint access control
- Permission checks

**Layer 3: Rate Limiting**
- Per-API-key rate limits
- Daily quota enforcement

**Layer 4: File Validation**
- File size checks
- Extension validation
- Magic byte detection

**Layer 5: Malicious File Detection**
- Double extension detection
- Malformed file identification

---

## Building the Project

### Prerequisites

- Docker and Docker Compose (for Docker deployment)
- Python 3.14+ (for local execution)
- pip (Python package manager)

### Docker Build

```bash
# Build all services
docker-compose build

# Or build individual services
docker-compose build gpu-service
docker-compose build policy-service
docker-compose build scanner-service
```

### Local Execution

See `Essentials/LOCAL_EXECUTION_GUIDE.md` for detailed instructions.

---

## Running the Project

### Docker Deployment

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Local Execution

```bash
# Start services in separate terminals
cd mock-gpu-service && python app.py
cd policy-service && python app.py
cd scanner-service && python app.py
cd web-dashboard && python app.py
```

### Access Points

- **Web Dashboard**: http://localhost:8080
- **GPU Service**: http://localhost:5001
- **Policy Service**: http://localhost:5002
- **Scanner Service**: http://localhost:5003

---

## Security Features

### Authentication

- API key validation against whitelist
- Tenant identification and isolation

### Authorization

- Endpoint-level access control
- Permission-based routing

### Rate Limiting

- 20 requests per minute per API key
- Daily quota enforcement
- In-memory or Redis-based tracking

### File Validation

- 10MB file size limit
- Allowed extensions: jpg, jpeg, png, pdf
- Magic byte detection to prevent spoofing

### Malicious File Detection

- Double extension detection (e.g., image.jpg.exe)
- Malformed file identification
- Content-type validation

---

## Testing

### Automated Tests

```bash
# Basic service tests
python test_services.py

# Comprehensive security tests
python comprehensive_test.py

# Rate limiting tests
python test_rate_limit.py

# Endpoint checks
python check_endpoints.py
```

### Manual Testing

Use the web dashboard at http://localhost:8080 to:
- Upload test files
- Test different API keys
- Verify rate limiting
- Check file validation

---

## Troubleshooting

### Common Issues

**Port Already in Use**
```bash
netstat -ano | findstr :5001
taskkill /F /PID <PID>
```

**Service Not Responding**
```bash
curl http://localhost:5001/health
curl http://localhost:5002/health
curl http://localhost:5003/health
```

**Module Not Found**
```bash
pip install flask requests werkzeug pillow
```

### Docker Issues

**Container Won't Start**
```bash
docker-compose logs <service-name>
docker-compose down
docker-compose up -d
```

**Network Issues**
```bash
docker network ls
docker network prune
```

---

## Performance

### Latency Metrics

- **Authorization**: ~1-2ms (cached: 0.1ms)
- **Scanning**: ~1-2ms
- **Inference**: ~100-130ms
- **Security Layer Total**: ~2-4ms
- **Total Processing**: ~100-135ms

### Throughput

- **Single File**: ~100-135ms
- **50 Files (Parallel)**: ~100-150ms total
- **Rate Limit**: 20 requests/minute

### Optimizations

- Connection pooling (50 connections)
- Parallel processing (50 workers)
- Authorization caching (60-second TTL)
- Reduced timeouts (5 seconds)

---

## Best Practices

### Security

1. **API Key Management**: Rotate API keys regularly
2. **Rate Limiting**: Monitor and adjust based on usage patterns
3. **File Validation**: Keep allowed extensions list minimal
4. **Monitoring**: Set up alerts for security events

### Performance

1. **Connection Pooling**: Reuse HTTP connections
2. **Caching**: Cache authorization results
3. **Parallel Processing**: Use concurrent workers for bulk operations
4. **Timeouts**: Set appropriate timeouts for external calls

### Operations

1. **Health Checks**: Implement comprehensive health checks
2. **Logging**: Use structured logging for debugging
3. **Metrics**: Collect and monitor key metrics
4. **Alerting**: Set up alerts for critical failures

---

## Next Steps

### Immediate

- [ ] Add more comprehensive test coverage
- [ ] Implement proper error handling
- [ ] Add monitoring dashboards

### Short-term

- [ ] Implement message queue for async processing
- [ ] Add batch GPU processing
- [ ] Implement proper logging infrastructure

### Long-term

- [ ] Migrate to gRPC for inter-service communication
- [ ] Implement proper load balancing
- [ ] Add Kubernetes deployment configurations
- [ ] Implement proper secrets management

---

## Additional Resources

- **Local Execution Guide**: `Essentials/LOCAL_EXECUTION_GUIDE.md`
- **Project Status**: `Essentials/PROJECT_STATUS.md`
- **Envoy Documentation**: https://www.envoyproxy.io/docs
- **OpenTelemetry**: https://opentelemetry.io
- **Flask Documentation**: https://flask.palletsprojects.com

---

## Support

For issues or questions:
1. Check the troubleshooting section
2. Review the local execution guide
3. Check service logs
4. Verify all services are running
