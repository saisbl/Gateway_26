# Scanner Service Enhancement Plan — Phase 1

**Created**: May 26, 2026
**Target**: Production-grade image security gateway for AI model inference

---

## Objectives

1. **Parallel processing** — Handle up to 50k images per batch using `ThreadPoolExecutor`/`asyncio`
2. **Advanced threat detection** — Image bombs, adversarial inputs, format-specific exploits
3. **Format expansion** — Support GIF, BMP, TIFF, WebP alongside existing JPG/PNG/PDF
4. **Metadata sanitization** — Strip EXIF and embedded scripts from images
5. **Entropy & anomaly scoring** — Flag statistically suspicious files
6. **Per-file timeout** — Prevent slowloris-style attacks via image bombs
7. **Graceful degradation** — Per-file error isolation, partial batch acceptance

---

## Threat Coverage

| Attack Vector | Detection Method |
|---|---|
| Decompression bomb (Zip Bomb variant) | Compression ratio analysis (bytes_in / bytes_out) |
| Image with embedded executable | Magic byte consistency + entropy spike |
| EXIF with JavaScript payload | Metadata scanning & stripping |
| Billion laughs / XML bomb (in PDF) | Recursive reference depth check |
| Adversarial perturbation | Pixel-level anomaly scoring |
| Large dimension DoS | Configurable max width/height + megapixel cap |
| Color channel overflow | Channel count + bit depth validation |
| Polyglot files | Multi-layer magic byte analysis |
| Pixel flood (1x1000000 images) | Aspect ratio + megapixel limits |
| Malformed header | Format-specific header parsing + PIL verify |
| Timeout via slow decode | Per-file timeout (max 5s per scan) |

---

## Implementation Checklist

### 1. Configuration Module (`app.py` — top section)
- [ ] Add config constants: `MAX_IMAGE_DIMENSION`, `MAX_MEGAPIXELS`, `MAX_ASPECT_RATIO`, `MAX_COMPRESSION_RATIO`, `MAX_ENTROPY_SCORE`, `MAX_EXIF_SIZE`, `SCAN_TIMEOUT_SECONDS`, `MAX_WORKERS`, `BATCH_SIZE`
- [ ] Expand `ALLOWED_EXTENSIONS` to include `gif`, `bmp`, `tiff`, `webp`
- [ ] Expand magic byte signatures for all supported formats

### 2. Core Scan Refactor (`/scan` endpoint)
- [ ] Accept single file OR batch (list of files via `request.files` multi-dict)
- [ ] Wrap per-file scan logic in isolated try/except (one bad file doesn't kill batch)
- [ ] Return per-file results array with individual `allowed`, `reason`, `scan_time_ms`

### 3. Batch Processing Engine
- [ ] Add `ThreadPoolExecutor(max_workers=MAX_WORKERS)` for parallel scanning
- [ ] Submit all files as futures, collect results as completed (`as_completed`)
- [ ] Track per-file timing with `time.perf_counter()`
- [ ] Return aggregate stats: `total_files`, `passed`, `rejected`, `total_scan_time_ms`, `avg_scan_time_ms`

### 4. Image Validation Functions
- [ ] `check_image_bomb(img, file_content)` — compute compression ratio
- [ ] `check_dimensions(img)` — enforce max dims + megapixels + aspect ratio
- [ ] `check_color_depth(img)` — verify mode & bit depth
- [ ] `check_entropy(file_content)` — Shannon entropy score
- [ ] `strip_metadata(img)` — remove EXIF + ICC profiles before passing to GPU
- [ ] `validate_format_specific(img, extension)` — per-format header checks

### 5. Workflow: Single File Scan
```
read file → detect magic bytes → validate extension match →
→ open with PIL → verify integrity → check dimensions →
→ check compression ratio → check entropy → strip metadata →
→ return result (allowed, metadata, stripped file)
```

### 6. Workflow: Batch Scan (`/scan-batch`)
```
receive N files → submit all to ThreadPoolExecutor →
→ collect results as they complete →
→ return summary + per-file results (pass/fail + latency)
```

### 7. Additional Endpoints
- [ ] `/scan-batch` — Parallel batch scan (POST, multipart with multiple files)
- [ ] `/allowed-types` — Return current allowed extensions & limits
- [ ] `/stats` — Return scan statistics (total scanned, pass/reject ratio, avg time)

### 8. Metrics & Logging
- [ ] Add in-memory scan counter (total, passed, rejected, avg latency)
- [ ] Return detailed scan metadata per file (dimensions, format, entropy score)
- [ ] Log per-file scan results with timestamps

---

## Performance Targets (for 50k images)

| Metric | Target |
|--------|--------|
| Single file scan | < 5ms |
| 100-image batch | < 100ms |
| 10k-image batch | < 2s |
| 50k-image batch | < 10s |
| Memory per file | < 50MB |
| Failure isolation | 1 bad file = no impact on other 49,999 |

---

## Files Modified

- `C:\Users\15496\Desktop\Gateway 26\Gateway-Architecture-\scanner-service\app.py`
- `C:\Users\15496\Desktop\Gateway 26\Gateway-Architecture-\Essentials\PROJECT_STATUS.md`

---

## Rollback

Before any changes, the current `scanner-service/app.py` will be backed up. If reversion is needed, restore from backup and restart the service.
