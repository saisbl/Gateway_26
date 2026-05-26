# AGENTS.md — Project Handoff

**Agent Model**: opencode/big-pickle
**Last Updated**: 2026-05-26T13:00:00+05:30

---

## Project Overview

- **Name**: Gateway Architecture Demo
- **Path**: `C:\Users\15496\Desktop\Gateway 26\Gateway-Architecture-`
- **Execution Mode**: Local (no Docker — daemon unavailable)
- **Status**: All 4 services running and healthy

A security gateway demo that protects AI/ML inference services with authentication, rate limiting, file scanning, and observability. Flask-based microservices running as standalone Python processes.

---

## Architecture Flow

```
Client → Web Dashboard (:8080) → Policy Service (:5002) → Scanner Service (:5003) → Mock GPU Service (:5001)
```

(Docker mode uses Envoy as the front door; local mode uses the Web Dashboard directly.)

---

## Services

| Service | Port | Role | Key File |
|---------|------|------|----------|
| **Mock GPU Service** | 5001 | Simulated AI inference (100-200ms) | `mock-gpu-service/app.py` |
| **Policy Service** | 5002 | API key auth (expiry, active/inactive), per-IP + per-key rate limiting (20/min key, 100/min IP), concurrency caps (50/tenant), file hash dedup (SHA-256, 1h TTL), optional HMAC-SHA256 signing | `policy-service/app.py` |
| **Scanner Service** | 5003 | Magic byte detection (8 formats), image bomb detection, dimension/megapixel/ratio limits, color depth, entropy flagging, EXIF detection, parallel batch scan via ThreadPoolExecutor (50 workers) | `scanner-service/app.py` |
| **Web Dashboard** | 8080 | Flask UI with bulk upload, latency tracking, service health, inspection modal, disk-backed async batch pipeline (Phase 3) | `web-dashboard/app.py` + `templates/index.html` |

---

## Running Locally

```powershell
$py = "C:\Users\15496\AppData\Local\Python\bin\python.exe"

Start-Process -FilePath $py -ArgumentList "app.py" -WorkingDirectory "<root>\mock-gpu-service" -WindowStyle Hidden
Start-Process -FilePath $py -ArgumentList "app.py" -WorkingDirectory "<root>\policy-service" -WindowStyle Hidden
Start-Process -FilePath $py -ArgumentList "app.py" -WorkingDirectory "<root>\scanner-service" -WindowStyle Hidden
Start-Process -FilePath $py -ArgumentList "app.py" -WorkingDirectory "<root>\web-dashboard" -WindowStyle Hidden

# Stop all
Get-NetTCPConnection -LocalPort 5001,5002,5003,8080 | Stop-Process -Id {$_.OwningProcess} -Force
```

**Python**: `C:\Users\15496\AppData\Local\Python\bin\python.exe` (v3.14.5)

---

## Key Configuration

| Setting | Value |
|---------|-------|
| Key Rate Limit | 20 requests/min per API key |
| IP Rate Limit | 100 requests/min per IP |
| Concurrency Cap | 50 concurrent per tenant (30s auto-clean) |
| Storage | In-memory (defaultdict, no Redis) |
| Max File Size | 10MB per file |
| Max Upload | 500MB per request |
| Allowed Extensions | jpg, jpeg, png, pdf, gif, bmp, tiff, webp |
| File Detection | Advanced magic byte detection (9 signatures) |
| Image Bomb Threshold | Compression ratio ≤ 500:1 |
| Entropy | Flagged if >7.5 (never blocks) |
| Max Image Dimension | 10000px per side, 50MP, 100:1 aspect ratio |
| Worker Pool | 50 concurrent workers |
| Scanner Batch | ThreadPoolExecutor with 50 workers, 5s per-file timeout |
| Auth Cache TTL | 60 seconds |
| File Hash TTL | 3600 seconds (1 hour) |
| HMAC | Optional (opt-in via `X-Signature` + `X-Timestamp` headers), SHA-256 |
| Batch Chunk Size | 250 files per chunk |
| Batch Rate Limit (Policy) | 100 requests/min (separate from interactive 20/min) |
| Async Job Routing | <50 files: sync per-file pipeline, ≥50 files: async disk-backed job |
| Max Batch Auth | 500 files per `/batch-authorize` call |

## API Keys

| Key | Tenant | Type | Expires | Endpoints |
|-----|--------|------|---------|-----------|
| `demo-key-123` | tenant-1 | production | 2027-01-01 | `/infer`, `/upload` |
| `test-key-456` | tenant-2 | development | 2026-06-01 | `/infer` |
| `expired-key-789` | tenant-3 | development | 2025-06-01 (expired) | `/infer` |
| `inactive-key-000` | tenant-4 | development | 2027-01-01 (deactivated) | `/infer` |

---

## Recent Changes (May 26, 2026)

### Phase 3 — Dashboard Batch Pipeline ✅
- Disk-backed chunked async pipeline for 50k-image uploads
- Three-tier routing: <50 files sync, ≥50 files async job
- Async job system: `/upload-large` → job_id, `/job-status/<id>`, `/job-result/<id>`
- `/batch-authorize` endpoint in Policy Service (separate 100 req/min rate pool)
- Session temp dir auto-cleanup via shutil.rmtree

### Phase 2 — Policy Service Hardening
- Rewrote to v2.0: key expiry, per-IP rate limiting (100/min), concurrency caps (50/tenant), file hash dedup (SHA-256, 1h TTL), optional HMAC-SHA256 signing
- 4 API keys with lifecycle metadata (production, dev, expired, inactive)
- New endpoints: `/keys`, `/sign`, `/check-hash`

### Phase 1 — Scanner Service Enhancement
- Rewrote to v2.0: 8 formats, 6 validation layers, image bomb detection, entropy flagging, parallel batch scan (50 workers)

---

## Project Structure

```
├── AGENTS.md                    # This file
├── Essentials/                  # Documentation (PROJECT_STATUS, PROJECT_DOCUMENTATION, LOCAL_EXECUTION_GUIDE, SCANNER_ENHANCEMENT_PLAN, POLICY_ENHANCEMENT_PLAN)
├── docker-compose.yml
├── envoy/envoy.yaml
├── policy-service/app.py        # v2.0 — key expiry, IP limit, concurrency, hash dedup, HMAC
├── policy-service/app.py.bak    # v1.0 backup
├── scanner-service/app.py       # v2.0 — 8 formats, 6 validation layers, parallel batch
├── scanner-service/app.py.bak   # v1.0 backup
├── mock-gpu-service/app.py
├── web-dashboard/
│   ├── app.py                    # v2.0 (Phase 3) — disk-backed chunked async batch pipeline
│   └── templates/index.html
├── demo-files/
├── scripts/
├── otel/
└── prometheus/
```

---

## Golden Rules for New Chats

1. Read this `AGENTS.md` first, then `Essentials/PROJECT_STATUS.md`
2. Every change must be logged in `PROJECT_STATUS.md`
3. Restart services after editing any `app.py` or `index.html`
4. When restarting, kill ALL processes on the port (use `Get-NetTCPConnection -State Listen` to find exact PID)
5. Prefer `docker compose up -d` if Docker daemon becomes available
6. Keep ports 5001-5003, 8080 — hardcoded across services
