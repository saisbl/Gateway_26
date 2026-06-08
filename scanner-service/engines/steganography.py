import io
import json
import base64

from PIL import Image

from .config import STEG_CHI_SQUARE_THRESHOLD, STEG_LSB_SKEW_THRESHOLD, STEG_MAX_SAMPLES
from .helpers import get_extension, detect_mime, shannon_entropy, _extract_text_from_bytes, _bits_to_bytes

PNG_IEND_MARKER = b'\x00\x00\x00\x00IEND\xae\x42\x60\x82'
JPEG_EOI_MARKER = b'\xff\xd9'
GIF_TRAILER = b'\x3b'


# ── Structural Engine ─────────────────────────────────────────

def check_structural_payloads(data):
    """Scan raw file bytes for data appended after end-of-file markers."""
    findings = []

    if data[:8] == b'\x89PNG\r\n\x1a\n':
        iend_pos = data.rfind(PNG_IEND_MARKER)
        if iend_pos < 0:
            iend_pos = data.rfind(b'IEND')
        if iend_pos >= 0:
            after_iend = iend_pos + 12
            payload = data[after_iend:]
            if len(payload) > 0:
                ent = round(shannon_entropy(payload), 4)
                findings.append({
                    'type': 'post_eof_payload', 'format': 'PNG',
                    'size': len(payload), 'entropy': ent,
                    'description': f'{len(payload)} bytes appended after IEND chunk (entropy {ent})',
                })
                texts = _extract_text_from_bytes(payload, min_length=4)
                for t in texts:
                    findings.append({
                        'type': 'post_eof_text', 'format': 'PNG', 'text': t,
                        'description': f'Readable text in post-IEND payload: "{t}"',
                    })

    elif data[:2] == b'\xff\xd8':
        eoi_pos = data.rfind(JPEG_EOI_MARKER)
        if eoi_pos >= 0:
            payload = data[eoi_pos + 2:]
            if len(payload) > 0:
                ent = round(shannon_entropy(payload), 4)
                findings.append({
                    'type': 'post_eof_payload', 'format': 'JPEG',
                    'size': len(payload), 'entropy': ent,
                    'description': f'{len(payload)} bytes appended after EOI marker (entropy {ent})',
                })
                texts = _extract_text_from_bytes(payload, min_length=4)
                for t in texts:
                    findings.append({
                        'type': 'post_eof_text', 'format': 'JPEG', 'text': t,
                        'description': f'Readable text in post-EOI payload: "{t}"',
                    })

    elif data[:3] in (b'GIF',):
        trailer_pos = data.rfind(GIF_TRAILER)
        if trailer_pos >= 0:
            payload = data[trailer_pos + 1:]
            if len(payload) > 0:
                ent = round(shannon_entropy(payload), 4)
                findings.append({
                    'type': 'post_eof_payload', 'format': 'GIF',
                    'size': len(payload), 'entropy': ent,
                    'description': f'{len(payload)} bytes appended after GIF trailer (entropy {ent})',
                })
                texts = _extract_text_from_bytes(payload, min_length=4)
                for t in texts:
                    findings.append({
                        'type': 'post_eof_text', 'format': 'GIF', 'text': t,
                        'description': f'Readable text in post-trailer payload: "{t}"',
                    })

    return findings


# ── Metadata Engine ───────────────────────────────────────────

def check_metadata_hidden_data(img, data):
    """Examine image metadata fields for hidden or suspicious content."""
    findings = []
    for key, value in img.info.items():
        if isinstance(value, bytes):
            text = value.decode('utf-8', errors='replace')
        else:
            text = str(value)
        if key.lower() in ('text', 'tex', 'ztxt', 'itxt', 'comment', 'description'):
            texts_found = _extract_text_from_bytes(text.encode('utf-8', errors='replace'), min_length=3)
            for t in texts_found:
                findings.append({
                    'type': 'metadata_text', 'field': key, 'content': t,
                    'description': f'Text chunk "{key}" contains "{t}"',
                })
        raw_len = len(value) if isinstance(value, (bytes, str)) else 0
        if raw_len > 500:
            findings.append({
                'type': 'large_metadata', 'field': key, 'size': raw_len,
                'description': f'Metadata field "{key}" is {raw_len} bytes',
            })
    exif_data = img.info.get('exif')
    if exif_data:
        findings.append({
            'type': 'exif_present', 'size': len(exif_data),
            'description': f'EXIF data present ({len(exif_data)} bytes)',
        })
        if len(exif_data) > 2000:
            findings.append({
                'type': 'large_exif', 'size': len(exif_data),
                'description': f'Oversized EXIF: {len(exif_data)} bytes (may hide data)',
            })
    return findings


# ── Spatial Engine ────────────────────────────────────────────

def extract_lsb_texts(img, max_pixels=500000):
    """Multi-plane LSB extraction: LSB1, LSB2, alpha channel, and combined RGB."""
    if img.mode not in ('RGB', 'RGBA'):
        try:
            img = img.convert('RGB')
        except Exception:
            return []
    pixels = list(img.getdata())
    if len(pixels) > max_pixels:
        pixels = pixels[:max_pixels]
    findings = []

    for ch_name, ch_idx in [('R', 0), ('G', 1), ('B', 2)]:
        bits = [p[ch_idx] & 1 for p in pixels]
        message = _bits_to_bytes(bits)
        texts = _extract_text_from_bytes(message)
        for t in texts:
            findings.append({'channel': ch_name, 'text': t, 'confidence': 'high', 'byte_offset': message.find(t.encode())})

    for ch_name, ch_idx in [('R_bit1', 0), ('G_bit1', 1), ('B_bit1', 2)]:
        bits = [(p[ch_idx] >> 1) & 1 for p in pixels]
        message = _bits_to_bytes(bits)
        texts = _extract_text_from_bytes(message, min_length=4)
        for t in texts:
            findings.append({'channel': ch_name, 'text': t, 'confidence': 'medium', 'byte_offset': message.find(t.encode())})

    if img.mode == 'RGBA':
        bits = [p[3] & 1 for p in pixels]
        message = _bits_to_bytes(bits)
        texts = _extract_text_from_bytes(message, min_length=4)
        for t in texts:
            findings.append({'channel': 'Alpha', 'text': t, 'confidence': 'high', 'byte_offset': message.find(t.encode())})

    bits = []
    for p in pixels:
        for ch in range(min(3, len(p))):
            bits.append(p[ch] & 1)
    message = _bits_to_bytes(bits)
    texts = _extract_text_from_bytes(message)
    for t in texts:
        findings.append({'channel': 'RGB', 'text': t, 'confidence': 'high', 'byte_offset': message.find(t.encode())})

    return findings


# ── Statistical Engine (legacy) ────────────────────────────────

def check_steganography(img, data):
    """Spatial + statistical steganography analysis on a PIL-opened image."""
    raw_pixels = img.tobytes()
    sample = raw_pixels
    if len(sample) > STEG_MAX_SAMPLES:
        step = len(sample) // STEG_MAX_SAMPLES
        sample = sample[::step]
    hist = [0] * 256
    zero_lsb = 0
    bit0_eq_bit1 = 0
    for b in sample:
        hist[b] += 1
        if b & 1 == 0:
            zero_lsb += 1
        if (b & 1) == ((b >> 1) & 1):
            bit0_eq_bit1 += 1
    chi_sq = 0.0
    degrees = 0
    for k in range(128):
        total = hist[2*k] + hist[2*k+1]
        if total > 0:
            expected = total / 2.0
            chi_sq += (hist[2*k] - expected) ** 2 / expected
            degrees += 1
    chi_sq /= max(degrees, 1)
    lsb_zero_ratio = zero_lsb / len(sample)
    lsb_skew = abs(lsb_zero_ratio - 0.5)
    bp_corr = bit0_eq_bit1 / len(sample)
    reasons = []
    if chi_sq < STEG_CHI_SQUARE_THRESHOLD:
        reasons.append('pairs_too_similar')
    if bp_corr < 0.52:
        reasons.append('bitplane_decorrelated')
    if lsb_skew > STEG_LSB_SKEW_THRESHOLD and bp_corr < 0.55:
        reasons.append('lsb_skewed')
    extracted = extract_lsb_texts(img)
    if extracted:
        reasons.append('message_extracted')
    metadata_findings = check_metadata_hidden_data(img, data)
    for mf in metadata_findings:
        if mf['type'] in ('metadata_text',):
            reasons.append('metadata_hidden_text')
        if mf['type'] in ('large_metadata', 'large_exif'):
            reasons.append('oversized_metadata')
    reasons = list(dict.fromkeys(reasons))
    flagged = len(reasons) > 0
    return {
        'flagged': flagged,
        'chi_square_score': round(chi_sq, 4),
        'lsb_zero_ratio': round(lsb_zero_ratio, 4),
        'bitplane_correlation': round(bp_corr, 4),
        'samples_analyzed': len(sample),
        'reasons': reasons,
        'extracted_messages': extracted,
        'structural_payloads': [],
        'metadata_findings': metadata_findings,
    }


# ── Full Detection Pipeline ───────────────────────────────────

def detect_stego_on_bytes(data, filename):
    """Run all three steganography engines on raw file bytes."""
    extension = get_extension(filename)
    mime = detect_mime(data)
    if mime is None or not mime.startswith('image/'):
        return {'flagged': False, 'extracted_messages': [], 'structural_payloads': [], 'metadata_findings': [], 'reasons': []}

    structural = check_structural_payloads(data)
    reasons = []
    if structural:
        reasons.append('structural_payload')
        for sf in structural:
            if sf['type'] == 'post_eof_text':
                reasons.append('post_eof_text')

    extracted = []
    metadata_findings = []
    try:
        img = Image.open(io.BytesIO(data))
        img.verify()
        img = Image.open(io.BytesIO(data))
        stego = check_steganography(img, data)
        extracted = stego.get('extracted_messages', [])
        metadata_findings = stego.get('metadata_findings', [])
        for r in stego.get('reasons', []):
            if r not in reasons:
                reasons.append(r)
    except Exception:
        pass

    flagged = len(reasons) > 0
    return {
        'flagged': flagged,
        'reasons': reasons,
        'extracted_messages': extracted,
        'structural_payloads': structural,
        'metadata_findings': metadata_findings,
    }


def add_stego_headers(resp, stego):
    """Add steganography detection results as response headers."""
    resp.headers['X-Steganography-Flagged'] = 'true' if stego.get('flagged') else 'false'
    reasons = stego.get('reasons', [])
    resp.headers['X-Steganography-Reasons'] = ','.join(reasons)
    msgs = stego.get('extracted_messages', [])
    if msgs:
        encoded = base64.b64encode(json.dumps(msgs).encode()).decode()
        if len(encoded) < 6000:
            resp.headers['X-Steganography-Messages-B64'] = encoded
    structural = stego.get('structural_payloads', [])
    if structural:
        count = len([s for s in structural if s['type'] == 'post_eof_payload'])
        texts = [s['text'] for s in structural if s['type'] == 'post_eof_text']
        summary = {'payload_count': count, 'texts': texts}
        encoded = base64.b64encode(json.dumps(summary).encode()).decode()
        if len(encoded) < 2000:
            resp.headers['X-Steganography-Structural-B64'] = encoded
    metadata = stego.get('metadata_findings', [])
    if metadata:
        summary = [{'field': m['field'], 'type': m['type'], 'size': m.get('size', 0), 'content': m.get('content', '')[:100]} for m in metadata]
        encoded = base64.b64encode(json.dumps(summary).encode()).decode()
        if len(encoded) < 2000:
            resp.headers['X-Steganography-Metadata-B64'] = encoded
    return resp
