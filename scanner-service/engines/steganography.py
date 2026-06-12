import io
import json
import base64
import math
import struct
from collections import Counter

from PIL import Image

from .config import STEG_CHI_SQUARE_THRESHOLD, STEG_LSB_SKEW_THRESHOLD, STEG_MAX_SAMPLES
from .helpers import get_extension, detect_mime, shannon_entropy, _extract_text_from_bytes, _bits_to_bytes

PNG_IEND_MARKER = b'\x00\x00\x00\x00IEND\xae\x42\x60\x82'
JPEG_EOI_MARKER = b'\xff\xd9'
GIF_TRAILER = b'\x3b'

MIN_TEXT_LEN = 4


# ── Enhanced text extractors ──────────────────────────────────

def _extract_all_texts(data_bytes):
    """Extract printable ASCII, UTF-8 sequences, and hex-encoded strings."""
    results = []
    results.extend(_extract_text_from_bytes(data_bytes, min_length=MIN_TEXT_LEN))
    results.extend(_find_utf8_sequences(data_bytes))
    results.extend(_find_hex_encoded(data_bytes))
    results.extend(_find_base64_like(data_bytes))
    return list(dict.fromkeys(results))


def _find_utf8_sequences(data_bytes):
    """Find valid multi-byte UTF-8 character sequences."""
    texts = []
    i = 0
    current = []
    while i < len(data_bytes):
        b = data_bytes[i]
        if b < 0x80:
            if current:
                try:
                    texts.append(bytes(current).decode('utf-8'))
                except Exception:
                    pass
                current = []
            i += 1
            continue
        n_bytes = 0
        if b & 0xe0 == 0xc0: n_bytes = 2
        elif b & 0xf0 == 0xe0: n_bytes = 3
        elif b & 0xf8 == 0xf0: n_bytes = 4
        else:
            if current:
                try:
                    texts.append(bytes(current).decode('utf-8'))
                except Exception:
                    pass
                current = []
            i += 1
            continue
        if i + n_bytes > len(data_bytes):
            break
        seq = data_bytes[i:i + n_bytes]
        try:
            seq.decode('utf-8')
            current.append(b)
        except Exception:
            if current:
                try:
                    texts.append(bytes(current).decode('utf-8'))
                except Exception:
                    pass
                current = []
        i += 1
    if current:
        try:
            texts.append(bytes(current).decode('utf-8'))
        except Exception:
            pass
    return [t for t in texts if len(t) >= MIN_TEXT_LEN and not t.isascii()]


def _find_hex_encoded(data_bytes):
    """Find hex-encoded strings (e.g. '48656c6c6f' -> 'Hello')."""
    texts = []
    hex_chars = b'0123456789abcdefABCDEF'
    i = 0
    while i < len(data_bytes):
        if data_bytes[i] in hex_chars and i + 1 < len(data_bytes) and data_bytes[i + 1] in hex_chars:
            start = i
            while i < len(data_bytes) and data_bytes[i] in hex_chars:
                i += 1
            hex_str = data_bytes[start:i].decode('ascii', errors='replace')
            if len(hex_str) >= 8 and len(hex_str) % 2 == 0:
                try:
                    decoded = bytes.fromhex(hex_str)
                    if all(32 <= b <= 126 for b in decoded):
                        texts.append(decoded.decode('ascii'))
                except Exception:
                    pass
        else:
            i += 1
    return texts


def _find_base64_like(data_bytes):
    """Detect Base64-encoded strings (alphanumeric + / + = padding)."""
    import re as _re
    try:
        text = data_bytes.decode('ascii', errors='replace')
    except Exception:
        return []
    patterns = _re.findall(rb'[A-Za-z0-9+/]{20,}=*', data_bytes)
    results = []
    for p in patterns:
        s = p.decode('ascii')
        try:
            decoded = base64.b64decode(s)
            decoded_str = decoded.decode('utf-8', errors='replace')
            printable_count = sum(1 for c in decoded_str if c.isprintable())
            if printable_count > len(decoded_str) * 0.7 and len(decoded_str) >= 4:
                results.append(f'[Base64 decoded] {decoded_str[:200]}')
        except Exception:
            pass
    return results


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
                texts = _extract_all_texts(payload)
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
                texts = _extract_all_texts(payload)
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
                texts = _extract_all_texts(payload)
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
            texts_found = _extract_all_texts(text.encode('utf-8', errors='replace'))
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
        exif_texts = _extract_all_texts(exif_data)
        for t in exif_texts:
            findings.append({
                'type': 'exif_text', 'content': t,
                'description': f'Text found in EXIF: "{t}"',
            })
    return findings


# ── Spatial Engine — Strong multi-plane LSB ───────────────────

def _get_pixel_array(img, max_pixels=50000):
    """Get flattened pixel array with adaptive sampling."""
    if img.mode not in ('RGB', 'RGBA', 'P', 'L', 'PA'):
        try:
            img = img.convert('RGB')
        except Exception:
            return None, 0
    if img.mode == 'P':
        img = img.convert('RGB')
    elif img.mode in ('L', 'LA'):
        img = img.convert('RGB')
    elif img.mode == 'PA':
        img = img.convert('RGBA')

    pixels = list(img.getdata())
    total = len(pixels)
    if total > max_pixels:
        step = max(2, total // max_pixels)
        pixels = pixels[::step]
    return pixels, len(pixels)


def _extract_lsb_plane(pixels, ch_idx, bit_pos):
    """Extract a specific bit plane from a color channel."""
    bits = []
    for p in pixels:
        if ch_idx < len(p):
            bits.append((p[ch_idx] >> bit_pos) & 1)
        else:
            bits.append(0)
    return bits


def _score_text_quality(text):
    """Score text by length and character diversity (higher = more likely real message)."""
    if not text:
        return 0
    upper = sum(1 for c in text if c.isupper())
    lower = sum(1 for c in text if c.islower())
    digits = sum(1 for c in text if c.isdigit())
    special = sum(1 for c in text if c in '_{}!@#$%^&*()-=+[]|;:,.<>?/~` ')
    entropy = 0
    if len(text) > 1:
        counts = Counter(text.lower())
        for c in counts:
            p = counts[c] / len(text)
            entropy -= p * math.log2(p)
    score = len(text) * 0.5
    if upper > 0 and lower > 0: score += 3
    if digits > 0: score += 2
    if special > 0: score += 2
    if entropy > 2.5: score += 3
    if text.isupper() and len(text) > 3: score += 2
    if 'flag' in text.lower() or 'secret' in text.lower() or 'hidden' in text.lower():
        score += 10
    return score


def _extract_lsb_message(pixels, ch_idx, bit_pos, channel_name, min_len=4):
    """Extract message from a specific channel+bit-plane and score results."""
    bits = _extract_lsb_plane(pixels, ch_idx, bit_pos)
    message = _bits_to_bytes(bits)
    texts = _extract_all_texts(message)
    findings = []
    for t in texts:
        score = _score_text_quality(t)
        if score >= 5:
            findings.append({
                'channel': channel_name,
                'bit_plane': bit_pos,
                'text': t,
                'confidence': 'high' if score >= 15 else 'medium' if score >= 8 else 'low',
                'quality_score': round(score, 1),
                'byte_offset': message.find(t.encode()) if isinstance(t, str) else message.find(t),
            })
    return findings, bits


def extract_lsb_texts_strong(img, max_pixels=100000):
    """Strong multi-plane LSB analysis across all color channels and bit planes.
    Analyzes bit planes 0-2 (LSB-1, LSB-2, LSB-3) for each channel,
    plus combined RGB and alpha. Uses grid-based region analysis."""
    pix_data, num_pixels = _get_pixel_array(img, max_pixels)
    if pix_data is None:
        return [], {}

    findings = []
    channels_to_check = [('R', 0), ('G', 1), ('B', 2)]
    if img.mode == 'RGBA':
        channels_to_check.append(('Alpha', 3))

    # Multi-bit-plane analysis (bit 0, 1, 2 for each channel)
    for ch_name, ch_idx in channels_to_check:
        for bit in range(3):
            ch_label = f'{ch_name}_bit{bit}' if bit > 0 else ch_name
            f, _ = _extract_lsb_message(pix_data, ch_idx, bit, ch_label, min_len=4 if bit > 0 else MIN_TEXT_LEN)
            findings.extend(f)

    # Combined RGB interleaved for each bit plane
    for bit in range(2):
        interleaved_bits = []
        for p in pix_data:
            for ch in range(min(3, len(p))):
                interleaved_bits.append((p[ch] >> bit) & 1)
        interleaved_msg = _bits_to_bytes(interleaved_bits)
        texts = _extract_all_texts(interleaved_msg)
        for t in texts:
            score = _score_text_quality(t)
            if score >= 5:
                findings.append({
                    'channel': 'RGB',
                    'bit_plane': bit,
                    'text': t,
                    'confidence': 'high' if score >= 15 else 'medium' if score >= 8 else 'low',
                    'quality_score': round(score, 1),
                    'byte_offset': interleaved_msg.find(t.encode()),
                })

    return findings


# ── Per-channel Chi-square Test ───────────────────────────────

def per_channel_chi_square(pixels):
    """Chi-square test per color channel (much more sensitive than global)."""
    results = {}
    num_channels = min(3, len(pixels[0])) if pixels else 3
    for ch in range(num_channels):
        ch_name = ['R', 'G', 'B'][ch]
        hist = [0] * 256
        for p in pixels:
            if ch < len(p):
                hist[p[ch]] += 1
        chi_sq = 0.0
        degrees = 0
        for k in range(128):
            total = hist[2 * k] + hist[2 * k + 1]
            if total > 0:
                expected = total / 2.0
                chi_sq += (hist[2 * k] - expected) ** 2 / expected
                degrees += 1
        chi_sq /= max(degrees, 1)
        results[ch_name] = round(chi_sq, 4)
    return results


# ── Bit-plane Correlation Analysis ────────────────────────────

def bitplane_correlation_analysis(pixels):
    """Analyze correlation between bit planes 0 and 1 for each channel.
    LSB stego decorrelates adjacent bit planes significantly."""
    chan_names = ['R', 'G', 'B']
    results = {}
    for ch_idx, ch_name in enumerate(chan_names):
        bits_0 = _extract_lsb_plane(pixels, ch_idx, 0)
        bits_1 = _extract_lsb_plane(pixels, ch_idx, 1)
        if len(bits_0) != len(bits_1):
            continue
        matches = sum(1 for a, b in zip(bits_0, bits_1) if a == b)
        ratio = matches / max(len(bits_0), 1)
        results[ch_name] = round(ratio, 4)
    return results


# ── Color Pair Analysis (detect PVD-style stego) ──────────────

def pixel_difference_histogram(pixels):
    """Analyze differences between adjacent pixel values.
    Stego embedding disrupts the natural distribution of pixel differences."""
    diffs = []
    for i in range(1, len(pixels)):
        p0 = pixels[i - 1]
        p1 = pixels[i]
        for ch in range(min(3, len(p0), len(p1))):
            diffs.append(abs(p0[ch] - p1[ch]))
    if not diffs:
        return 0, 0
    hist = Counter(diffs)
    smoothness = 0
    max_key = max(hist.keys()) if hist else 0
    for d in range(max_key + 1):
        smoothness += hist.get(d, 0) == 0
    smoothness_ratio = smoothness / max(max_key + 1, 1)
    zero_ratio = hist.get(0, 0) / len(diffs)
    return round(smoothness_ratio, 4), round(zero_ratio, 4)


# ── RS Analysis (simplified) ──────────────────────────────────

def rs_analysis(pixels, channel=0):
    """Simplified Regular-Singular analysis for LSB detection.
    Uses discrimination function f = sum of absolute differences of adjacent pixels."""
    if len(pixels) < 100:
        return 0.5
    regular = 0
    singular = 0
    step = max(1, len(pixels) // 5000)
    for i in range(0, len(pixels) - 1, step):
        p0 = pixels[i]
        p1 = pixels[i + 1]
        if channel >= len(p0) or channel >= len(p1):
            continue
        orig = abs(p0[channel] - p1[channel])
        flipped0 = abs((p0[channel] ^ 1) - p1[channel])
        flipped1 = abs(p0[channel] - (p1[channel] ^ 1))
        flipped_both = abs((p0[channel] ^ 1) - (p1[channel] ^ 1))
        if flipped_both > orig:
            regular += 1
        elif flipped_both < orig:
            singular += 1
    total = regular + singular
    if total == 0:
        return 0.5
    return round(regular / total, 4)


# ── Strong Statistical Analysis ───────────────────────────────

def strong_statistical_analysis(pixels):
    """Comprehensive statistical analysis combining multiple tests."""
    total_pixels = len(pixels)
    if total_pixels == 0:
        return {
            'flagged': False, 'chi_square_scores': {'R': 0, 'G': 0, 'B': 0},
            'bitplane_correlations': {'R': 0, 'G': 0, 'B': 0},
            'lsb_zero_ratios': {'R': 0, 'G': 0, 'B': 0},
            'pvd_smoothness': 0, 'pvd_zero_ratio': 0,
            'rs_ratios': {'R': 0.5, 'G': 0.5, 'B': 0.5},
            'samples_analyzed': total_pixels,
            'reasons': [],
        }

    # Per-channel chi-square
    chi_scores = per_channel_chi_square(pixels)

    # Per-channel bit-plane correlation
    bp_corrs = bitplane_correlation_analysis(pixels)

    # Per-channel LSB zero ratios
    zero_ratios = {}
    for ch_idx, ch_name in enumerate(['R', 'G', 'B']):
        bits = _extract_lsb_plane(pixels, ch_idx, 0)
        zero_ratio = sum(bits) / max(len(bits), 1)
        zero_ratios[ch_name] = round(zero_ratio, 4)

    # Pixel difference histogram
    pvd_smooth, pvd_zero = pixel_difference_histogram(pixels)

    # RS analysis per channel
    rs_ratios = {}
    for ch_idx, ch_name in enumerate(['R', 'G', 'B']):
        rs_ratios[ch_name] = rs_analysis(pixels, ch_idx)

    # Flagging logic
    reasons = []

    # Chi-square: any channel suspicious?
    for ch, score in chi_scores.items():
        if score < STEG_CHI_SQUARE_THRESHOLD:
            reasons.append(f'pairs_too_similar_{ch}')
            reasons.append('pairs_too_similar')

    # Bit-plane decorrelation per channel
    for ch, corr in bp_corrs.items():
        if corr < 0.52:
            reasons.append(f'bitplane_decorrelated_{ch}')
            reasons.append('bitplane_decorrelated')

    # LSB zero skew per channel
    for ch, ratio in zero_ratios.items():
        skew = abs(ratio - 0.5)
        bp_corr = bp_corrs.get(ch, 0.5)
        if skew > STEG_LSB_SKEW_THRESHOLD and bp_corr < 0.55:
            reasons.append(f'lsb_skewed_{ch}')
            reasons.append('lsb_skewed')

    # PVD analysis
    if pvd_smooth > 0.15:
        reasons.append('pvd_anomaly')

    # RS analysis
    rs_anomalies = 0
    for ch, ratio in rs_ratios.items():
        if abs(ratio - 0.5) > 0.15:
            rs_anomalies += 1
    if rs_anomalies >= 2:
        reasons.append('rs_anomaly')

    reasons = list(dict.fromkeys(reasons))

    return {
        'flagged': len(reasons) > 0,
        'chi_square_scores': chi_scores,
        'bitplane_correlations': bp_corrs,
        'lsb_zero_ratios': zero_ratios,
        'pvd_smoothness': pvd_smooth,
        'pvd_zero_ratio': pvd_zero,
        'rs_ratios': rs_ratios,
        'samples_analyzed': total_pixels,
        'reasons': reasons,
    }


# ── Main Detection Entry Point ────────────────────────────────

def check_steganography(img, data):
    """Full steganography analysis combining spatial, statistical, and metadata engines."""
    pix_data, num_pixels = _get_pixel_array(img, 100000)
    pixels = pix_data or []

    stats = strong_statistical_analysis(pixels)

    extracted = extract_lsb_texts_strong(img)
    if extracted:
        for f in extracted:
            reason_str = f'message_extracted_{f["channel"]}'
            if reason_str not in stats['reasons']:
                stats['reasons'].append(reason_str)
            if 'message_extracted' not in stats['reasons']:
                stats['reasons'].append('message_extracted')

    metadata_findings = check_metadata_hidden_data(img, data)
    for mf in metadata_findings:
        if mf['type'] in ('metadata_text',):
            if 'metadata_hidden_text' not in stats['reasons']:
                stats['reasons'].append('metadata_hidden_text')
        if mf['type'] in ('large_metadata', 'large_exif'):
            if 'oversized_metadata' not in stats['reasons']:
                stats['reasons'].append('oversized_metadata')

    stats['flagged'] = len(stats['reasons']) > 0
    stats['extracted_messages'] = extracted
    stats['structural_payloads'] = []
    stats['metadata_findings'] = metadata_findings

    return stats


def detect_stego_on_bytes(data, filename):
    """Run all three steganography engines on raw file bytes.
    Returns comprehensive results including all extracted messages."""
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
                if 'post_eof_text' not in reasons:
                    reasons.append('post_eof_text')

    extracted = []
    metadata_findings = []
    stats_defaults = {
        'chi_square_scores': {'R': 0, 'G': 0, 'B': 0},
        'bitplane_correlations': {'R': 0, 'G': 0, 'B': 0},
        'lsb_zero_ratios': {'R': 0, 'G': 0, 'B': 0},
        'pvd_smoothness': 0, 'pvd_zero_ratio': 0,
        'rs_ratios': {'R': 0.5, 'G': 0.5, 'B': 0.5},
        'samples_analyzed': 0,
    }
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
        stats_defaults = {
            'chi_square_scores': stego.get('chi_square_scores', stats_defaults['chi_square_scores']),
            'bitplane_correlations': stego.get('bitplane_correlations', stats_defaults['bitplane_correlations']),
            'lsb_zero_ratios': stego.get('lsb_zero_ratios', stats_defaults['lsb_zero_ratios']),
            'pvd_smoothness': stego.get('pvd_smoothness', 0),
            'pvd_zero_ratio': stego.get('pvd_zero_ratio', 0),
            'rs_ratios': stego.get('rs_ratios', stats_defaults['rs_ratios']),
            'samples_analyzed': stego.get('samples_analyzed', 0),
        }
    except Exception:
        pass

    flagged = len(reasons) > 0
    return {
        'flagged': flagged,
        'reasons': reasons,
        'extracted_messages': extracted,
        'structural_payloads': structural,
        'metadata_findings': metadata_findings,
        'chi_square_scores': stats_defaults['chi_square_scores'],
        'bitplane_correlations': stats_defaults['bitplane_correlations'],
        'lsb_zero_ratios': stats_defaults['lsb_zero_ratios'],
        'pvd_smoothness': stats_defaults['pvd_smoothness'],
        'pvd_zero_ratio': stats_defaults['pvd_zero_ratio'],
        'rs_ratios': stats_defaults['rs_ratios'],
        'samples_analyzed': stats_defaults['samples_analyzed'],
    }


# ── Header Injection ──────────────────────────────────────────

def add_stego_headers(resp, stego):
    """Add steganography detection results as response headers."""
    resp.headers['X-Steganography-Flagged'] = 'true' if stego.get('flagged') else 'false'
    reasons = stego.get('reasons', [])
    resp.headers['X-Steganography-Reasons'] = ','.join(reasons)
    msgs = stego.get('extracted_messages', [])
    if msgs:
        encoded = base64.b64encode(json.dumps(msgs).encode()).decode()
        if len(encoded) < 8000:
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


# ── Process Pool for CPU-bound Stego Detection ─────────────

import concurrent.futures
import atexit

_stego_pool = concurrent.futures.ProcessPoolExecutor(max_workers=4)


@atexit.register
def _close_stego_pool():
    _stego_pool.shutdown(wait=False)


def quick_stego_check(data):
    """Fast (~5-15ms) heuristic check on raw image bytes.
    Uses a multi-channel statistical scan with quick LSB sample."""
    try:
        img = Image.open(io.BytesIO(data))
        img.verify()
        img = Image.open(io.BytesIO(data))
    except Exception:
        return True, ['unable_to_verify']

    pix_data, _ = _get_pixel_array(img, 5000)
    if pix_data is None:
        return True, ['unable_to_read_pixels']
    pixels = pix_data

    # Quick per-channel chi-square
    zero_lsb_total = 0
    total_samples = 0
    bit0_eq_bit1 = 0
    for p in pixels:
        for ch in range(min(3, len(p))):
            total_samples += 1
            if p[ch] & 1 == 0:
                zero_lsb_total += 1
            if (p[ch] & 1) == ((p[ch] >> 1) & 1):
                bit0_eq_bit1 += 1
    if total_samples == 0:
        return False, []
    lsb_zero_ratio = zero_lsb_total / total_samples
    lsb_skew = abs(lsb_zero_ratio - 0.5)
    bp_corr = bit0_eq_bit1 / total_samples
    reasons = []
    if bp_corr < 0.52:
        reasons.append('bitplane_decorrelated')
    if lsb_skew > STEG_LSB_SKEW_THRESHOLD and bp_corr < 0.55:
        reasons.append('lsb_skewed')

    # Quick multi-channel LSB text sample across bit planes 0 and 1
    if img.mode in ('RGB', 'RGBA'):
        pix_list = list(img.getdata())[:500]
        found = False
        for ch_idx, ch_name in [(0, 'R'), (1, 'G'), (2, 'B')]:
            if found: break
            for bit in range(2):
                if found: break
                bits = [((p[ch_idx] >> bit) & 1) for p in pix_list if ch_idx < len(p)]
                message = _bits_to_bytes(bits)
                texts = _extract_all_texts(message)
                if texts:
                    reasons.append('lsb_text_found')
                    found = True

    return (len(reasons) > 0, reasons)


def detect_stego_on_bytes_async(data, filename, timeout=30):
    """Offload CPU-bound stego detection to a separate process.
    Uses a fast inline heuristic first; only submits to ProcessPool if suspicious.
    Always runs structural engine inline (fast, no PIL needed)."""
    structural = check_structural_payloads(data)
    flagged, reasons = quick_stego_check(data)
    if structural:
        for sf in structural:
            if sf['type'] == 'post_eof_text':
                if 'post_eof_text' not in reasons:
                    reasons.append('post_eof_text')
        flagged = True
    if not flagged:
        return {
            'flagged': False, 'reasons': [],
            'extracted_messages': [],
            'structural_payloads': structural,
            'metadata_findings': [],
            'chi_square_scores': {'R': 0, 'G': 0, 'B': 0},
            'bitplane_correlations': {'R': 0, 'G': 0, 'B': 0},
            'lsb_zero_ratios': {'R': 0, 'G': 0, 'B': 0},
            'pvd_smoothness': 0, 'pvd_zero_ratio': 0,
            'rs_ratios': {'R': 0.5, 'G': 0.5, 'B': 0.5},
            'samples_analyzed': 0,
        }
    future = _stego_pool.submit(detect_stego_on_bytes, data, filename)
    return future.result(timeout=timeout)
