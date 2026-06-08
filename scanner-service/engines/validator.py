import io

from PIL import Image
import PyPDF2

from .config import (ALLOWED_EXTENSIONS, MAX_COMPRESSION_RATIO, MAX_IMAGE_DIMENSION,
                     MAX_MEGAPIXELS, MAX_ASPECT_RATIO, MAX_ENTROPY_SCORE, MAX_PDF_PAGES)
from .helpers import get_extension, detect_mime, shannon_entropy


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
    from .config import MAGIC_SIGNATURES
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


def validate_image(data, extension):
    """Run all image validation checks. Returns (result_dict, is_valid)."""
    img = Image.open(io.BytesIO(data))
    img.verify()
    img = Image.open(io.BytesIO(data))
    dim_ok, dim_reason, dim_msg = check_dimensions(img)
    if not dim_ok:
        return {'passed': False, 'reason': dim_reason, 'message': dim_msg}, False
    bomb_ok, bomb_reason, bomb_msg = check_image_bomb(img, data)
    if not bomb_ok:
        return {'passed': False, 'reason': bomb_reason, 'message': bomb_msg}, False
    color_ok, color_reason, color_msg = check_color_depth(img)
    if not color_ok:
        return {'passed': False, 'reason': color_reason, 'message': color_msg}, False
    return img, True


def validate_pdf(data):
    pdf = PyPDF2.PdfReader(io.BytesIO(data))
    num_pages = len(pdf.pages)
    if num_pages > MAX_PDF_PAGES:
        return {'passed': False, 'reason': 'too_many_pages', 'message': f"PDF has {num_pages} pages, max allowed is {MAX_PDF_PAGES}"}, False
    pdf.pages[0]
    return num_pages, True
