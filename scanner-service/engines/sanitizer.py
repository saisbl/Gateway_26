import io

from PIL import Image
import PyPDF2

from .helpers import detect_mime, get_extension
from .config import MAX_PDF_PAGES


def strip_image_metadata(img):
    buf = io.BytesIO()
    fmt = img.format or 'PNG'

    # OWASP: normalise to 8-bit RGB/RGBA
    has_alpha = img.mode == 'RGBA' or (img.mode == 'P' and 'transparency' in img.info)
    if fmt.upper() in ('JPEG', 'MPO'):
        raw = img.convert('RGB')
    elif has_alpha:
        raw = img.convert('RGBA')
    else:
        raw = img.convert('RGB')

    save_kwargs = {}
    if fmt.upper() in ('JPEG', 'MPO'):
        save_kwargs['exif'] = b''
        save_kwargs['optimize'] = True
    elif fmt.upper() == 'PNG':
        save_kwargs['optimize'] = True
    elif fmt.upper() == 'WEBP':
        save_kwargs['lossless'] = False
    raw.save(buf, format=fmt, **save_kwargs)
    buf.seek(0)
    return buf


def sanitize_bytes(data, filename):
    """Strip metadata, normalize format, return cleaned bytes or raise."""
    extension = get_extension(filename)
    mime = detect_mime(data)
    if mime is None:
        raise ValueError('Unknown file format')

    if mime.startswith('image/'):
        try:
            img = Image.open(io.BytesIO(data))
            img.verify()
            img = Image.open(io.BytesIO(data))
            sanitized = strip_image_metadata(img)
            return sanitized.read()
        except Exception:
            return data

    elif mime == 'application/pdf':
        pdf = PyPDF2.PdfReader(io.BytesIO(data))
        if len(pdf.pages) > MAX_PDF_PAGES:
            raise ValueError(f'PDF exceeds {MAX_PDF_PAGES} pages')
        return data

    raise ValueError(f'Unsupported MIME type: {mime}')
