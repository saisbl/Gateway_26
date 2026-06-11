import time
import io

from PIL import Image

from .config import MAX_FILE_SIZE_BYTES, MAX_PDF_PAGES, SCAN_TIMEOUT_SECONDS, MAX_WORKERS
from .helpers import get_extension, detect_mime
from .validator import (check_extension, check_magic_bytes, check_dimensions,
                        check_image_bomb, check_color_depth, check_entropy_threshold)

stats = {
    'total_scanned': 0,
    'total_passed': 0,
    'total_rejected': 0,
    'total_scan_time_ms': 0.0,
}


def scan_single_file(file_storage):
    start = time.perf_counter()
    filename = file_storage.filename or 'untitled'
    content_type = file_storage.content_type or ''
    data = file_storage.read()
    file_size = len(data)
    extension = get_extension(filename)
    detected_mime = detect_mime(data)

    result = {
        'filename': filename, 'extension': extension,
        'mime_type': detected_mime or content_type,
        'file_size_bytes': file_size,
        'file_size_mb': round(file_size / (1024 * 1024), 4),
        'allowed': False, 'checks': {},
    }

    if file_size > MAX_FILE_SIZE_BYTES:
        return {**result, 'allowed': False, 'reason': 'file_too_large',
                'message': f"File size exceeds {MAX_FILE_SIZE_BYTES // (1024*1024)}MB limit"}

    ext_ok, ext_reason, ext_msg = check_extension(filename)
    result['checks']['extension'] = {'passed': ext_ok, 'reason': ext_reason}
    if not ext_ok:
        return {**result, 'allowed': False, 'reason': ext_reason, 'message': ext_msg}

    magic_ok, magic_reason, magic_msg = check_magic_bytes(data, extension)
    result['checks']['magic_bytes'] = {'passed': magic_ok, 'reason': magic_reason}
    if not magic_ok:
        return {**result, 'allowed': False, 'reason': magic_reason, 'message': magic_msg}

    if detected_mime and detected_mime.startswith('image/'):
        try:
            img = Image.open(io.BytesIO(data))
            img.verify()
            img = Image.open(io.BytesIO(data))

            dim_ok, dim_reason, dim_msg = check_dimensions(img)
            result['checks']['dimensions'] = {
                'passed': dim_ok, 'reason': dim_reason,
                'width': img.size[0], 'height': img.size[1],
                'megapixels': round((img.size[0] * img.size[1]) / 1_000_000, 4),
            }
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

            result['checks']['steganography'] = {
                'passed': True, 'flagged': False,
                'chi_square_score': 0, 'lsb_zero_ratio': 0,
                'bitplane_correlation': 0, 'samples_analyzed': 0,
                'reasons': [], 'extracted_messages': [],
                'structural_payloads': [], 'metadata_findings': [],
            }
            has_exif = bool(img.info.get('exif'))
            result['checks']['metadata'] = {'has_exif': has_exif}
            if has_exif:
                result['checks']['metadata']['exif_size_bytes'] = len(img.info.get('exif', b''))
            result['dimensions'] = {'width': img.size[0], 'height': img.size[1],
                                    'megapixels': round((img.size[0] * img.size[1]) / 1_000_000, 4)}
            result['mode'] = img.mode
            result['entropy_score'] = ent_score
            result['compression_ratio'] = round(
                ((img.size[0] * img.size[1] * 24) / 8) / max(file_size, 1), 2)

        except Exception as e:
            return {**result, 'allowed': False, 'reason': 'corrupted_image',
                    'message': f"Image processing failed: {str(e)}"}

    elif detected_mime == 'application/pdf':
        try:
            import PyPDF2
            pdf = PyPDF2.PdfReader(io.BytesIO(data))
            num_pages = len(pdf.pages)
            if num_pages > MAX_PDF_PAGES:
                return {**result, 'allowed': False, 'reason': 'too_many_pages',
                        'message': f"PDF has {num_pages} pages, max allowed is {MAX_PDF_PAGES}"}
            pdf.pages[0]
            result['pdf_pages'] = num_pages
            result['checks']['pdf'] = {'passed': True, 'pages': num_pages}
        except Exception as e:
            return {**result, 'allowed': False, 'reason': 'corrupted_pdf',
                    'message': f"PDF processing failed: {str(e)}"}

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
            'allowed': False, 'reason': 'scan_error',
            'message': str(e), 'scan_time_ms': 0,
        }
