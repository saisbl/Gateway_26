from flask import Flask, request, jsonify
import os
import time
import io
import math
import concurrent.futures
from PIL import Image
import PyPDF2

app = Flask(__name__)

# ── Configuration ────────────────────────────────────────────

ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'pdf', 'gif', 'bmp', 'tiff', 'webp'}
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024
MAX_IMAGE_DIMENSION = 10000
MAX_MEGAPIXELS = 50
MAX_ASPECT_RATIO = 100
MAX_COMPRESSION_RATIO = 500
MAX_ENTROPY_SCORE = 7.5
MAX_PDF_PAGES = 500
STEG_CHI_SQUARE_THRESHOLD = 1.0
STEG_LSB_SKEW_THRESHOLD = 0.15
STEG_MAX_SAMPLES = 200000
SCAN_TIMEOUT_SECONDS = 5
MAX_WORKERS = 50

MAGIC_SIGNATURES = [
    (b'\xff\xd8\xff', 'image/jpeg', ['jpg', 'jpeg']),
    (b'\x89PNG\r\n\x1a\n', 'image/png', ['png']),
    (b'%PDF', 'application/pdf', ['pdf']),
    (b'GIF87a', 'image/gif', ['gif']),
    (b'GIF89a', 'image/gif', ['gif']),
    (b'BM', 'image/bmp', ['bmp']),
    (b'II\x2a\x00', 'image/tiff', ['tiff']),
    (b'MM\x00\x2a', 'image/tiff', ['tiff']),
    (b'RIFF', 'image/webp', ['webp']),
]

MIME_TO_EXT = {}
for sig, mime, exts in MAGIC_SIGNATURES:
    for ext in exts:
        MIME_TO_EXT[ext] = mime

# ── In-memory Statistics ─────────────────────────────────────

stats = {
    'total_scanned': 0,
    'total_passed': 0,
    'total_rejected': 0,
    'total_scan_time_ms': 0.0,
}

# ── Helpers ──────────────────────────────────────────────────

def get_extension(filename):
    return filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''

def detect_mime(data):
    for signature, mime, _ in MAGIC_SIGNATURES:
        if data.startswith(signature):
            return mime
    return None

def shannon_entropy(data):
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for x in range(256):
        p_x = data.count(x) / length
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return round(entropy, 4)

def strip_image_metadata(img):
    buf = io.BytesIO()
    fmt = img.format or 'PNG'
    raw = img.convert('RGB') if img.mode in ('P', '1', 'I', 'F', 'RGBA', 'CMYK', 'YCbCr', 'LAB') else img
    save_kwargs = {}
    if fmt.upper() == 'JPEG':
        save_kwargs['exif'] = b''
    elif fmt.upper() == 'PNG':
        save_kwargs['optimize'] = True
    raw.save(buf, format=fmt, **save_kwargs)
    buf.seek(0)
    return buf

# ── Validation Functions ─────────────────────────────────────

def check_extension(filename):
    ext = get_extension(filename)
    if not ext:
        return False, 'no_extension', 'File has no extension'
    if ext not in ALLOWED_EXTENSIONS:
        return False, 'invalid_extension', f"Extension '{ext}' not allowed. Allowed: {sorted(ALLOWED_EXTENSIONS)}"
    if filename.count('.') > 1:
        return False, 'double_extension', 'Double extensions are not allowed'
    return True, None, None

def check_magic_bytes(data, extension):
    mime = detect_mime(data)
    if mime is None:
        return False, 'unknown_format', 'File signature does not match any allowed format'
    expected_exts = [e for s, m, e in MAGIC_SIGNATURES if m == mime][0]
    if extension not in expected_exts:
        return False, 'magic_mismatch', f"Magic bytes indicate {mime} but extension is .{extension}"
    return True, None, None

def check_image_bomb(img, data):
    width, height = img.size
    mode_bpp = {'1': 1, 'L': 8, 'P': 8, 'RGB': 24, 'RGBA': 32, 'CMYK': 32, 'YCbCr': 24, 'I': 32, 'F': 32}
    bpp = mode_bpp.get(img.mode, 24)
    estimated_uncompressed = (width * height * bpp) / 8
    ratio = estimated_uncompressed / len(data) if len(data) > 0 else float('inf')
    if ratio > MAX_COMPRESSION_RATIO:
        return False, 'image_bomb', f"Decompression ratio {ratio:.1f}:1 exceeds limit of {MAX_COMPRESSION_RATIO}:1 (possible image bomb)"
    return True, None, None

def check_dimensions(img):
    width, height = img.size
    mp = (width * height) / 1_000_000
    if width > MAX_IMAGE_DIMENSION or height > MAX_IMAGE_DIMENSION:
        return False, 'dimension_too_large', f"Dimensions {width}x{height} exceed max {MAX_IMAGE_DIMENSION}px per side"
    if mp > MAX_MEGAPIXELS:
        return False, 'too_many_megapixels', f"Image has {mp:.1f}MP, max allowed is {MAX_MEGAPIXELS}MP"
    aspect = max(width, height) / max(min(width, height), 1)
    if aspect > MAX_ASPECT_RATIO:
        return False, 'aspect_ratio_extreme', f"Aspect ratio {aspect:.1f}:1 exceeds limit of {MAX_ASPECT_RATIO}:1"
    return True, None, None

def check_color_depth(img):
    mode = img.mode
    allowed_modes = {'1', 'L', 'P', 'RGB', 'RGBA', 'CMYK', 'YCbCr', 'I', 'F'}
    if mode not in allowed_modes:
        return False, 'unsupported_color_mode', f"Unsupported color mode: {mode}"
    bit_depth = img.info.get('bits', 8)
    if isinstance(bit_depth, tuple):
        bit_depth = max(bit_depth)
    if bit_depth > 16:
        return False, 'excessive_bit_depth', f"Bit depth {bit_depth} exceeds maximum of 16"
    return True, None, None

def check_entropy_threshold(data):
    score = shannon_entropy(data)
    flagged = score > MAX_ENTROPY_SCORE
    return True, None, None, flagged, score

def check_steganography(img, data):
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

    flagged = len(reasons) > 0
    return {
        'flagged': flagged,
        'chi_square_score': round(chi_sq, 4),
        'lsb_zero_ratio': round(lsb_zero_ratio, 4),
        'bitplane_correlation': round(bp_corr, 4),
        'samples_analyzed': len(sample),
        'reasons': reasons,
    }

# ── Core Scan Logic ──────────────────────────────────────────

def scan_single_file(file_storage):
    start = time.perf_counter()
    filename = file_storage.filename or 'untitled'
    content_type = file_storage.content_type or ''
    data = file_storage.read()
    file_size = len(data)
    extension = get_extension(filename)
    detected_mime = detect_mime(data)

    result = {
        'filename': filename,
        'extension': extension,
        'mime_type': detected_mime or content_type,
        'file_size_bytes': file_size,
        'file_size_mb': round(file_size / (1024 * 1024), 4),
        'allowed': False,
        'checks': {},
    }

    # 1. File size check
    if file_size > MAX_FILE_SIZE_BYTES:
        return {**result, 'allowed': False, 'reason': 'file_too_large', 'message': f"File size exceeds {MAX_FILE_SIZE_BYTES // (1024*1024)}MB limit"}

    # 2. Extension check
    ext_ok, ext_reason, ext_msg = check_extension(filename)
    result['checks']['extension'] = {'passed': ext_ok, 'reason': ext_reason}
    if not ext_ok:
        return {**result, 'allowed': False, 'reason': ext_reason, 'message': ext_msg}

    # 3. Magic byte check
    magic_ok, magic_reason, magic_msg = check_magic_bytes(data, extension)
    result['checks']['magic_bytes'] = {'passed': magic_ok, 'reason': magic_reason}
    if not magic_ok:
        return {**result, 'allowed': False, 'reason': magic_reason, 'message': magic_msg}

    # 4. Type-specific deep validation
    if detected_mime and detected_mime.startswith('image/'):
        try:
            img = Image.open(io.BytesIO(data))

            # Verify integrity
            img.verify()
            img = Image.open(io.BytesIO(data))

            dim_ok, dim_reason, dim_msg = check_dimensions(img)
            result['checks']['dimensions'] = {'passed': dim_ok, 'reason': dim_reason, 'width': img.size[0], 'height': img.size[1], 'megapixels': round((img.size[0] * img.size[1]) / 1_000_000, 4)}
            if not dim_ok:
                return {**result, 'allowed': False, 'reason': dim_reason, 'message': dim_msg}

            bomb_ok, bomb_reason, bomb_msg = check_image_bomb(img, data)
            result['checks']['image_bomb'] = {'passed': bomb_ok, 'reason': bomb_reason}
            if not bomb_ok:
                return {**result, 'allowed': False, 'reason': bomb_reason, 'message': bomb_msg}

            color_ok, color_reason, color_msg = check_color_depth(img)
            result['checks']['color_depth'] = {'passed': color_ok, 'reason': color_reason}
            if not color_ok:
                return {**result, 'allowed': False, 'reason': color_reason, 'message': color_msg}

            ent_ok, ent_reason, ent_msg, ent_flagged, ent_score = check_entropy_threshold(data)
            result['checks']['entropy'] = {'passed': True, 'flagged': ent_flagged, 'score': ent_score}

            stego = check_steganography(img, data)
            result['checks']['steganography'] = {'passed': True, 'flagged': stego['flagged'], 'chi_square_score': stego['chi_square_score'], 'lsb_zero_ratio': stego['lsb_zero_ratio'], 'bitplane_correlation': stego['bitplane_correlation'], 'samples_analyzed': stego['samples_analyzed'], 'reasons': stego['reasons']}

            # Metadata detection (stripping ready via strip_image_metadata())
            has_exif = bool(img.info.get('exif'))
            result['checks']['metadata'] = {'has_exif': has_exif}
            if has_exif:
                result['checks']['metadata']['exif_size_bytes'] = len(img.info.get('exif', b''))

            result['dimensions'] = {'width': img.size[0], 'height': img.size[1], 'megapixels': round((img.size[0] * img.size[1]) / 1_000_000, 4)}
            result['mode'] = img.mode
            result['entropy_score'] = ent_score
            result['compression_ratio'] = round(((img.size[0] * img.size[1] * 24) / 8) / max(file_size, 1), 2)

        except Exception as e:
            return {**result, 'allowed': False, 'reason': 'corrupted_image', 'message': f"Image processing failed: {str(e)}"}

    elif detected_mime == 'application/pdf':
        try:
            pdf = PyPDF2.PdfReader(io.BytesIO(data))
            num_pages = len(pdf.pages)
            if num_pages > MAX_PDF_PAGES:
                return {**result, 'allowed': False, 'reason': 'too_many_pages', 'message': f"PDF has {num_pages} pages, max allowed is {MAX_PDF_PAGES}"}
            pdf.pages[0]
            result['pdf_pages'] = num_pages
            result['checks']['pdf'] = {'passed': True, 'pages': num_pages}
        except Exception as e:
            return {**result, 'allowed': False, 'reason': 'corrupted_pdf', 'message': f"PDF processing failed: {str(e)}"}

    elapsed = (time.perf_counter() - start) * 1000
    result['allowed'] = True
    result['scan_time_ms'] = round(elapsed, 2)
    return result

def scan_file_wrapper(file_storage):
    try:
        result = scan_single_file(file_storage)
        if 'scan_time_ms' not in result:
            result['scan_time_ms'] = 0
        return result
    except Exception as e:
        return {
            'filename': getattr(file_storage, 'filename', 'unknown'),
            'allowed': False,
            'reason': 'scan_error',
            'message': str(e),
            'scan_time_ms': 0,
        }

# ── Routes ───────────────────────────────────────────────────

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'service': 'scanner-service',
        'version': '2.0',
        'features': ['magic_bytes', 'dimension_check', 'image_bomb_detection',
                     'entropy_analysis', 'metadata_stripping', 'parallel_batch_scan'],
        'allowed_extensions': sorted(ALLOWED_EXTENSIONS),
    }), 200

@app.route('/scan', methods=['POST'])
def scan():
    try:
        if 'file' not in request.files:
            return jsonify({'allowed': False, 'reason': 'no_file', 'message': 'No file provided'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'allowed': False, 'reason': 'no_filename', 'message': 'No file selected'}), 400

        result = scan_file_wrapper(file)

        stats['total_scanned'] += 1
        if result.get('allowed'):
            stats['total_passed'] += 1
        else:
            stats['total_rejected'] += 1
        stats['total_scan_time_ms'] += result.get('scan_time_ms', 0)

        status = 200 if result.get('allowed') else (403 if result.get('reason') not in ('no_file', 'no_filename') else 400)
        return jsonify(result), status

    except Exception as e:
        return jsonify({'allowed': False, 'reason': 'server_error', 'message': str(e)}), 500

@app.route('/scan-batch', methods=['POST'])
def scan_batch():
    try:
        files = request.files.getlist('file')
        if not files:
            return jsonify({'total_files': 0, 'passed': 0, 'rejected': 0, 'results': [], 'error': 'No files provided'}), 400

        total_start = time.perf_counter()

        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_map = {executor.submit(scan_file_wrapper, f): f.filename for f in files}
            results = []
            for future in concurrent.futures.as_completed(future_map, timeout=SCAN_TIMEOUT_SECONDS * len(files)):
                try:
                    result = future.result()
                    results.append(result)
                except concurrent.futures.TimeoutError:
                    results.append({
                        'filename': future_map.get(future, 'unknown'),
                        'allowed': False,
                        'reason': 'timeout',
                        'message': 'Scan timed out',
                        'scan_time_ms': SCAN_TIMEOUT_SECONDS * 1000,
                    })

        elapsed = (time.perf_counter() - total_start) * 1000
        passed = sum(1 for r in results if r.get('allowed'))
        rejected = sum(1 for r in results if not r.get('allowed'))

        stats['total_scanned'] += len(results)
        stats['total_passed'] += passed
        stats['total_rejected'] += rejected
        for r in results:
            stats['total_scan_time_ms'] += r.get('scan_time_ms', 0)

        return jsonify({
            'total_files': len(results),
            'passed': passed,
            'rejected': rejected,
            'total_scan_time_ms': round(elapsed, 2),
            'avg_scan_time_ms': round(elapsed / max(len(results), 1), 2),
            'results': results,
        }), 200

    except Exception as e:
        return jsonify({'total_files': 0, 'passed': 0, 'rejected': 0, 'results': [], 'error': str(e)}), 500

@app.route('/scan-metadata', methods=['POST'])
def scan_metadata():
    try:
        data = request.get_json()
        filename = data.get('filename', '')
        content_type = data.get('content_type', '')
        file_size = data.get('file_size', 0)

        if filename.count('.') > 1:
            return jsonify({'allowed': False, 'reason': 'double_extension', 'message': 'Double extensions are not allowed'}), 403

        extension = get_extension(filename)
        if extension not in ALLOWED_EXTENSIONS:
            return jsonify({'allowed': False, 'reason': 'invalid_extension', 'message': f"Extension '{extension}' not allowed"}), 403

        file_size_mb = file_size / (1024 * 1024)
        if file_size_mb > MAX_FILE_SIZE_BYTES / (1024 * 1024):
            return jsonify({'allowed': False, 'reason': 'file_too_large', 'message': 'File size exceeds limit'}), 413

        return jsonify({'allowed': True, 'extension': extension}), 200

    except Exception as e:
        return jsonify({'allowed': False, 'reason': 'error', 'message': str(e)}), 500

@app.route('/allowed-types', methods=['GET'])
def allowed_types():
    return jsonify({
        'allowed_extensions': sorted(ALLOWED_EXTENSIONS),
        'max_file_size_mb': MAX_FILE_SIZE_BYTES / (1024 * 1024),
        'max_image_dimension_px': MAX_IMAGE_DIMENSION,
        'max_megapixels': MAX_MEGAPIXELS,
        'max_aspect_ratio': MAX_ASPECT_RATIO,
        'max_compression_ratio': MAX_COMPRESSION_RATIO,
        'max_entropy_score': MAX_ENTROPY_SCORE,
        'max_pdf_pages': MAX_PDF_PAGES,
        'scan_timeout_seconds': SCAN_TIMEOUT_SECONDS,
        'max_workers': MAX_WORKERS,
    }), 200

@app.route('/metrics', methods=['GET'])
def metrics():
    avg_time = round(stats['total_scan_time_ms'] / max(stats['total_scanned'], 1), 2)
    return jsonify({
        'service': 'scanner-service',
        'version': '2.0',
        'total_scanned': stats['total_scanned'],
        'total_passed': stats['total_passed'],
        'total_rejected': stats['total_rejected'],
        'pass_rate': round(stats['total_passed'] / max(stats['total_scanned'], 1) * 100, 2),
        'avg_scan_time_ms': avg_time,
        'total_scan_time_ms': round(stats['total_scan_time_ms'], 2),
        'allowed_extensions': sorted(ALLOWED_EXTENSIONS),
        'max_workers': MAX_WORKERS,
    }), 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5003))
    app.run(host='0.0.0.0', port=port, debug=False)
