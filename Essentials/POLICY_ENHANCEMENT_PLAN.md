# Policy Service Enhancement Plan — Phase 2

**Created**: May 26, 2026
**Target**: Production-grade authentication, authorization, and rate limiting gateway

---

## Objectives

1. **API key lifecycle management** — Expiry dates, key rotation, active/inactive states
2. **Per-IP rate limiting** — Limit requests per client IP, separate from per-key limits
3. **Per-tenant concurrent request caps** — Hard limit on simultaneous in-flight requests
4. **File hash deduplication** — Reject known-bad file hashes, prevent replay attacks
5. **HMAC request signing** — Optional body signing with shared secrets for request integrity
6. **Enhanced observability** — Granular metrics per tenant, per key, per endpoint

---

## Threat Coverage

| Attack Vector | Mitigation |
|---|---|
| Stolen API key usage after expiry | Key expiry + active/inactive toggle |
| IP-based brute force | Per-IP rate limiting (separate from key limit) |
| Tenant A exhausting tenant B's quota | Per-tenant concurrent request caps |
| Replay attack with same file | File hash deduplication with TTL window |
| Request tampering in transit | HMAC-SHA256 body signing (optional) |
| Key leak via rotation gap | Graceful key rotation with overlap window |
| Credential stuffing across IPs | Combined per-key + per-IP rate limits |

---

## Implementation Checklist

### 1. API Key Model Enhancement
- [ ] Add key metadata: `secret`, `created_at`, `expires_at`, `is_active`, `key_type`, `daily_limit`
- [ ] Auto-reject expired keys
- [ ] Auto-reject inactive keys
- [ ] Key rotation support: multiple keys per tenant with overlap

### 2. Per-IP Rate Limiting
- [ ] Add `ip_rate_limits` defaultdict tracking IP:minute
- [ ] Config: `MAX_REQUESTS_PER_MINUTE_PER_IP = 100`
- [ ] Reject if either per-key OR per-IP limit exceeded

### 3. Concurrent Request Caps
- [ ] Config: `MAX_CONCURRENT_PER_TENANT = 50`
- [ ] Reject if tenant has >= MAX_CONCURRENT in-flight requests
- [ ] Track ingress at authorize, egress at release

### 4. File Hash Deduplication
- [ ] Compute SHA-256 hash of file content
- [ ] Store per-tenant with TTL (default 1 hour)
- [ ] Optional: reject exact duplicate within window
- [ ] Endpoint: `/check-hash` to query without consuming rate limit

### 5. HMAC Request Signing (Optional)
- [ ] Accept `X-Signature` and `X-Timestamp` headers
- [ ] Verify HMAC-SHA256(signing_secret, body + timestamp)
- [ ] Replay protection via timestamp window (±300s)
- [ ] Config flag: `HMAC_REQUIRED = False` (opt-in)

### 6. New & Enhanced Endpoints
- [ ] `/health` — Version info, feature flags, config summary
- [ ] `/keys` — List active keys and their metadata
- [ ] `/sign` — Generate HMAC signature for test clients
- [ ] `/check-hash` — File hash lookup (no rate limit consumed)
- [ ] Enhanced `/metrics` — Per-tenant, per-key stats, active concurrency, hash store size

### 7. Backward Compatibility
- [ ] Dashboard's existing `/authorize` call must work unchanged
- [ ] HMAC verification opt-in only (default: off)
- [ ] New fields in response must not break existing consumers

---

## Files Modified

- `C:\Users\15496\Desktop\Gateway 26\Gateway-Architecture-\policy-service\app.py`
- `C:\Users\15496\Desktop\Gateway 26\Gateway-Architecture-\Essentials\PROJECT_STATUS.md`

---

## Rollback

Backup of `policy-service/app.py` will be created before changes.
