# Dashboard Batch Pipeline Plan — Phase 3

**Created**: May 26, 2026
**Status**: ✅ COMPLETED
**Target**: Handle 50k-image uploads with memory safety, rate-limit awareness, and async job processing

---

## Bottlenecks Solved

| Problem | 50k Impact | Solution |
|---------|-----------|----------|
| RAM: `request.files` holds all files | 50k × 100KB = 5GB | Stream to disk session dir immediately |
| Auth: 1 `/authorize` call per file | 50k calls @ 20/min = 41 hours | Batch authorize: 1 call per chunk |
| Sync request timeout | Browser times out >60s | Async job: return job_id immediately |
| Per-file scan HTTP overhead | 50k calls | Batch scan: `/scan-batch` endpoint |

---

## Architecture

```
POST /upload-large → save files to disk → create job → return job_id
                                                  ↓
                                          Background worker:
                                          chunk → batch_authorize → batch_scan → GPU
                                                  ↓
GET /job-status/<id>  ←  job store updated after each chunk
GET /job-result/<id>  ←  final results when done
```

---

## Changes

### 1. Policy Service — `/batch-authorize`
- Accept: `{api_key, endpoint, client_ip, files: [{filename, file_size, file_hash}...]}`
- Validates key/endpoint/concurrency once (batch-level)
- Per-file: size, extension, hash dedup
- Consumes 1 unit from batch rate limit pool (100/min, separate from interactive limit)
- Returns: `{allowed: true, tenant, files: [{index, allowed, reason}...]}`

### 2. Dashboard — Disk-backed Storage
- Save files to `sessions/<job_id>/` temp dir immediately
- File metadata stored in memory (sizes, hashes, paths)
- Temp dir cleaned after job completes

### 3. Dashboard — Async Job System
- `POST /upload-large`: Saves files, creates job, starts background thread, returns job_id
- `GET /job-status/<job_id>`: Returns `{status, total, processed, passed, rejected}`
- `GET /job-result/<job_id>`: Returns full results array when completed
- Thread-safe job store (dict with lock)

### 4. Dashboard — Chunked Pipeline
```
for chunk in chunks(files, CHUNK_SIZE=250):
    auth = batch_authorize(chunk)           # 1 call
    allowed = [f for f in chunk if passed]
    scanned = batch_scan(allowed)            # 1 call
    for file in allowed & scanned:
        gpu_result = infer(file)            # parallel
```

---

## Performance Targets (50k images, 100KB avg)

| Phase | Detail | Time |
|-------|--------|------|
| Save to disk | 50k files × 0.1ms | 5s |
| Auth (batch) | 200 chunks @ 100/min limit | 2min |
| Scan (batch) | 200 chunks × 50 workers | 10s |
| GPU | 50k × 200ms / 50 workers | 200s |
| **Total** | | **~4 min** |

---

## Files Modified

- `policy-service/app.py` — added `/batch-authorize` ✅
- `web-dashboard/app.py` — major rewrite with disk-backed chunked async pipeline ✅

---

## Rollback

Backups of both files will be created before changes.

---

## Checklist

### Policy Service
- [x] Add `/batch-authorize` endpoint
- [x] Separate rate limit pool for batch (100 req/min)
- [x] Per-file: size, extension, hash dedup
- [x] Key/endpoint/concurrency validation at batch level

### Dashboard — Storage
- [x] Disk-backed session dir per job
- [x] File metadata tracked in memory
- [x] Temp dir cleaned after completion

### Dashboard — Async Job System
- [x] `/upload-large` saves files, creates job, returns job_id
- [x] Background thread processes chunks
- [x] `/job-status/<id>` polling endpoint
- [x] `/job-result/<id>` final results endpoint
- [x] Thread-safe job store

### Dashboard — Chunked Pipeline
- [x] Chunk size 250 files
- [x] Batch authorize per chunk
- [x] Batch scan per chunk
- [x] Parallel GPU inference per chunk (50 workers)
- [x] Auto-cleanup on job completion
