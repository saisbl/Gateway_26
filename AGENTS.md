# AGENTS.md — Project Handoff

**Agent Model**: opencode/big-pickle
**Last Updated**: 2026-06-08T19:00:00+05:30

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
Client → Web Dashboard (:8080) → Policy Service (:5002, Auth) → Scanner Service (:5003, Sanitize + Stego Detect) → Scanner Service (:5003, Scan) → Mock GPU Service (:5001, Infer)
```

Pipeline: Auth → Sanitize (with stego detection on original) → Scan → Infer

(Docker mode uses Envoy as the front door; local mode uses the Web Dashboard directly.)

---

## Services

| Service | Port | Role | Key Files |
|---------|------|------|-----------|
| **Mock GPU Service** | 5001 | Simulated AI inference (100-200ms) | `mock-gpu-service/app.py` |
| **Policy Service** (v2.1) | 5002 | API key auth, per-IP + per-key rate limiting (100/min each), `X-RateLimit-*` headers, request pattern tracking, concurrency caps (50/tenant), file hash dedup (SHA-256, 1h TTL), HMAC | `policy-service/app.py` (routes) + `policy-service/lib/` |
| **Scanner Service** | 5003 | Magic byte detection, image bomb detection, dimension limits, entropy flagging, sanitization + **3-engine steganography detection**, parallel batch scan | `scanner-service/app.py` (routes) + `scanner-service/engines/` |
| **Web Dashboard** | 8080 | Flask UI with bulk upload, latency tracking, service health, inspection modal, disk-backed async batch pipeline, **on-demand decode** | `web-dashboard/app.py` (routes) + `web-dashboard/lib/` |

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
| Key Rate Limit | 100 requests/min per API key (hard reject at limit, pattern tracking always on) |
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
| Batch Rate Limit (Policy) | 100 requests/min (separate from interactive) |
| Rate Limit Headers | `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, `X-IP-RateLimit-*` |
| Pattern Tracking | Per-key: endpoint/IP/timestamp history, 60s window, `/throttle-status` endpoint |
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

### Steganography Detection — Three-Engine Architecture ✅
The sanitization layer now runs three steganography detection engines on the **original file bytes** before any metadata stripping or re-encoding:

**1. Spatial Engine (LSB Extraction)**
- Extracts LSB-1 from R, G, B channels individually and combined RGB
- Extracts LSB-2 (bit-1 plane) from each channel
- Extracts alpha channel LSB (if RGBA mode)
- Converts bit streams to bytes and scans for printable ASCII sequences (min 5 chars, 4 for LSB-2)
- Reports found text with channel, confidence, byte offset

**2. Structural Engine (Post-EOF Payloads)**
- Scans raw file bytes for data appended after end-of-file markers:
  - PNG: data after IEND chunk
  - JPEG: data after FFD9 (EOI) marker
  - GIF: data after 3B (trailer) byte
- Reports payload size, entropy, and any readable text in the appended data
- Runs independently of PIL — works even on corrupted images

**3. Metadata Engine (Hidden Content in Metadata)**
- Examines PNG text chunks (tEXt, zTXt, iTXt, Comment, Description)
- Flags oversized metadata fields (>500 bytes)
- Reports EXIF presence and oversized EXIF (>2000 bytes)
- Reports content of text metadata fields

**Pipeline Integration**
- Detection runs in `/sanitize` (single) and `/sanitize-batch` (batch) endpoints, before stripping
- Results returned as `X-Steganography-*` headers (single) or `steganography_*` fields (batch)
- Dashboard parses findings and includes `steganography` field in every result with `extracted_messages`, `structural_payloads`, `metadata_findings`
- Statistical checks (chi-square, bit-plane correlation, LSB skew) retained in scan step
- All stego findings are flag-only (never block)
- Structural engine reports findings even if image is corrupted (PIL fails)
- Sanitize endpoint includes stego headers even if sanitization fails

**Verified**
- LSB stego: "SECRET_MESSAGE_12345" extracted from blue channel ✅
- Post-EOF: text detected in appended payload ✅
- Metadata: text fields detected and reported ✅
- Corrupted + post-EOF: structural findings reported despite PIL failure ✅
- Clean image: zero false positives ✅

### File/Folder Restructure — Modular Packages ✅
Every monolith `app.py` has been split into focused modules under `engines/` or `lib/`:

- **`scanner-service/engines/`**: config, helpers, validator, sanitizer, steganography (3 engines), scanner
- **`policy-service/lib/`**: config, helpers, keystore, hmac_utils, ratelimiter, patterns, concurrency, dedup, stats
- **`web-dashboard/lib/`**: config, helpers, decode_store, pipeline, job_manager

Each `app.py` is now a thin route-only file (no inline logic). Verified end-to-end after restructure.

### On-Demand Decode Feature ✅
- Scanner `/decode-stego` endpoint runs all three engines on a file and returns JSON
- Dashboard stores original file bytes in decode store (5-min TTL, keyed by batch ID) for both sync and async paths
- Dashboard `/decode/<batch_id>/<idx>` retrieves stored file and calls scanner's decode-stego
- Frontend inspection modal has "Decode Hidden Message" button that calls `/decode/<batch_id>/<idx>`
- Extracted messages, structural payloads, and metadata findings displayed inline in the modal
- Verified: LSB stego `FLAG{secret_decode_test}` extracted from B channel via full dashboard → scanner round-trip ✅

### Policy v2.1 — Pattern Tracking & Rate Limit Headers ✅
- `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, `Retry-After` headers (zero-latency)
- Per-key request pattern tracking (endpoint, IP, timestamps, 60s window)
- `/throttle-status` endpoint for abuse analysis
- `requests_remaining` in authorize responses
- Note: Graduated throttling (progressive delays) was implemented and then reverted — `time.sleep()` in the request path added unacceptable latency to a security gateway. Blind rejection at 100/min restored.

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
├── AGENTS.md                       # This file
├── Essentials/                     # Documentation
├── mock-gpu-service/app.py         # Simulated AI inference
│
├── policy-service/
│   ├── app.py                      # Thin Flask routes only
│   └── lib/
│       ├── __init__.py
│       ├── config.py               # Constants & limits
│       ├── helpers.py              # get_extension, sha256_hash, timestamps
│       ├── keystore.py             # API_KEYS dict + validate_api_key()
│       ├── hmac_utils.py           # HMAC-SHA256 verification
│       ├── ratelimiter.py          # Per-key, per-IP, batch rate limits
│       ├── patterns.py             # Request pattern tracking
│       ├── concurrency.py          # Per-tenant concurrency caps
│       ├── dedup.py                # File hash deduplication (SHA-256)
│       └── stats.py                # Daily quotas + global stats
│
├── scanner-service/
│   ├── app.py                      # Thin Flask routes only
│   └── engines/
│       ├── __init__.py
│       ├── config.py               # All scan thresholds & magic signatures
│       ├── helpers.py              # get_extension, detect_mime, entropy, bits/bytes
│       ├── validator.py            # Extension, magic bytes, dimensions, bomb, color, PDF
│       ├── sanitizer.py            # strip_image_metadata(), sanitize_bytes()
│       ├── steganography.py        # 3 engines: spatial (LSB), structural (post-EOF), metadata
│       └── scanner.py              # scan_single_file(), scan_file_wrapper(), stats
│
├── web-dashboard/
│   ├── app.py                      # Thin Flask routes only
│   ├── templates/index.html        # Full frontend (HTML/CSS/JS)
│   └── lib/
│       ├── __init__.py
│       ├── config.py               # Service URLs, chunk size, workers
│       ├── helpers.py              # sha256_file, save_uploaded_files, cleanup
│       ├── decode_store.py         # In-memory decode store with TTL
│       ├── pipeline.py             # process_one (sync), process_chunk (async)
│       └── job_manager.py          # Async job system (run_job, jobs dict)
│
├── scripts/                        # Test scripts
├── envoy/envoy.yaml                # Envoy config
├── otel/otel-collector-config.yaml # OpenTelemetry config
├── prometheus/prometheus.yml       # Prometheus config
├── docker-compose.yml
├── README.md
└── PROJECT_DOCUMENTATION.md
```

---

## Golden Rules for New Chats

1. Read this `AGENTS.md` first, then `Essentials/PROJECT_STATUS.md`
2. Every change must be logged in `PROJECT_STATUS.md`
3. Restart services after editing any `app.py` or `index.html`
4. When restarting, kill ALL processes on the port (use `Get-NetTCPConnection -State Listen` to find exact PID)
5. Prefer `docker compose up -d` if Docker daemon becomes available
6. Keep ports 5001-5003, 8080 — hardcoded across services
