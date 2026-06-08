import math

from .config import MAGIC_SIGNATURES


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


def _extract_text_from_bytes(data_bytes, min_length=5):
    current = bytearray()
    results = []
    for b in data_bytes:
        if 32 <= b <= 126:
            current.append(b)
        else:
            if len(current) >= min_length:
                results.append(bytes(current).decode('ascii'))
            current = bytearray()
    if len(current) >= min_length:
        results.append(bytes(current).decode('ascii'))
    return results


def _bits_to_bytes(bits):
    result = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        result.append(byte)
    return bytes(result)
