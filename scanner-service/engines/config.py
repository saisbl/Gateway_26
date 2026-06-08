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
STEG_MAX_SAMPLES = 50000
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
