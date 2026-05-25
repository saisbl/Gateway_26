from flask import Flask, request, jsonify
import os
from PIL import Image
import PyPDF2
import io

app = Flask(__name__)

# Configuration
ALLOWED_EXTENSIONS = ['jpg', 'jpeg', 'png', 'pdf']
MAX_FILE_SIZE_MB = 10
MAX_IMAGE_DIMENSION = 10000  # pixels
MAX_PDF_PAGES = 100

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "status": "healthy",
        "service": "scanner-service"
    }), 200

@app.route('/scan', methods=['POST'])
def scan_file():
    """
    Scan endpoint performs deep file validation:
    - Real MIME type detection using magic bytes
    - File extension validation
    - Content-type verification
    - Image dimension checks
    - PDF page count validation
    - Malformed file detection
    """
    try:
        # Check if file is present
        if 'file' not in request.files:
            return jsonify({
                "allowed": False,
                "reason": "no_file",
                "message": "No file provided"
            }), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({
                "allowed": False,
                "reason": "no_filename",
                "message": "No file selected"
            }), 400
        
        filename = file.filename
        content_type = file.content_type
        
        # Read file content
        file_content = file.read()
        file_size = len(file_content)
        
        # Check file size
        file_size_mb = file_size / (1024 * 1024)
        if file_size_mb > MAX_FILE_SIZE_MB:
            return jsonify({
                "allowed": False,
                "reason": "file_too_large",
                "message": f"File size {file_size_mb:.2f}MB exceeds limit of {MAX_FILE_SIZE_MB}MB"
            }), 413
        
        # Detect MIME type using basic magic byte detection (simplified for Windows)
        detected_mime = None
        if file_content.startswith(b'\xff\xd8\xff'):
            detected_mime = 'image/jpeg'
        elif file_content.startswith(b'\x89PNG\r\n\x1a\n'):
            detected_mime = 'image/png'
        elif file_content.startswith(b'%PDF'):
            detected_mime = 'application/pdf'
        else:
            detected_mime = content_type  # Fallback to provided content-type
        
        # Check for double extensions
        if filename.count('.') > 1:
            return jsonify({
                "allowed": False,
                "reason": "double_extension",
                "message": "Double extensions are not allowed"
            }), 403
        
        # Get file extension
        extension = filename.split('.')[-1].lower() if '.' in filename else ''
        
        # Validate extension
        if extension not in ALLOWED_EXTENSIONS:
            return jsonify({
                "allowed": False,
                "reason": "invalid_extension",
                "message": f"Extension '{extension}' not allowed. Allowed: {ALLOWED_EXTENSIONS}"
            }), 403
        
        # Validate MIME type matches extension
        expected_mimes = {
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg',
            'png': 'image/png',
            'pdf': 'application/pdf'
        }
        
        expected_mime = expected_mimes.get(extension)
        if expected_mime and detected_mime != expected_mime:
            return jsonify({
                "allowed": False,
                "reason": "mime_mismatch",
                "message": f"Detected MIME type '{detected_mime}' does not match extension '{extension}' (expected '{expected_mime}')"
            }), 403
        
        # Perform deep validation based on file type
        if extension in ['jpg', 'jpeg', 'png']:
            # Image validation
            try:
                img = Image.open(io.BytesIO(file_content))
                width, height = img.size
                
                if width > MAX_IMAGE_DIMENSION or height > MAX_IMAGE_DIMENSION:
                    return jsonify({
                        "allowed": False,
                        "reason": "image_too_large",
                        "message": f"Image dimensions {width}x{height} exceed maximum of {MAX_IMAGE_DIMENSION}px"
                    }), 403
                
                # Verify image is not corrupted
                img.verify()
                
            except Exception as e:
                return jsonify({
                    "allowed": False,
                    "reason": "corrupted_image",
                    "message": f"Image file is corrupted or invalid: {str(e)}"
                }), 403
        
        elif extension == 'pdf':
            # PDF validation
            try:
                pdf_reader = PyPDF2.PdfReader(io.BytesIO(file_content))
                num_pages = len(pdf_reader.pages)
                
                if num_pages > MAX_PDF_PAGES:
                    return jsonify({
                        "allowed": False,
                        "reason": "too_many_pages",
                        "message": f"PDF has {num_pages} pages, maximum allowed is {MAX_PDF_PAGES}"
                    }), 403
                
                # Verify PDF is not corrupted
                pdf_reader.pages[0]
                
            except Exception as e:
                return jsonify({
                    "allowed": False,
                    "reason": "corrupted_pdf",
                    "message": f"PDF file is corrupted or invalid: {str(e)}"
                }), 403
        
        # All checks passed
        return jsonify({
            "allowed": True,
            "filename": filename,
            "extension": extension,
            "mime_type": detected_mime,
            "file_size_bytes": file_size,
            "file_size_mb": round(file_size_mb, 2)
        }), 200
        
    except Exception as e:
        return jsonify({
            "allowed": False,
            "reason": "scan_error",
            "message": f"Error during scan: {str(e)}"
        }), 500

@app.route('/scan-metadata', methods=['POST'])
def scan_metadata():
    """
    Lightweight scan that only checks metadata without reading full file
    """
    try:
        data = request.get_json()
        
        filename = data.get('filename', '')
        content_type = data.get('content_type', '')
        file_size = data.get('file_size', 0)
        
        # Check for double extensions
        if filename.count('.') > 1:
            return jsonify({
                "allowed": False,
                "reason": "double_extension",
                "message": "Double extensions are not allowed"
            }), 403
        
        # Validate extension
        extension = filename.split('.')[-1].lower() if '.' in filename else ''
        if extension not in ALLOWED_EXTENSIONS:
            return jsonify({
                "allowed": False,
                "reason": "invalid_extension",
                "message": f"Extension '{extension}' not allowed"
            }), 403
        
        # Check file size
        file_size_mb = file_size / (1024 * 1024)
        if file_size_mb > MAX_FILE_SIZE_MB:
            return jsonify({
                "allowed": False,
                "reason": "file_too_large",
                "message": f"File size exceeds limit"
            }), 413
        
        return jsonify({
            "allowed": True,
            "extension": extension
        }), 200
        
    except Exception as e:
        return jsonify({
            "allowed": False,
            "reason": "error",
            "message": str(e)
        }), 500

@app.route('/metrics', methods=['GET'])
def metrics():
    return jsonify({
        "service": "scanner-service",
        "scans_performed": 0,
        "allowed_extensions": ALLOWED_EXTENSIONS
    }), 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5003))
    app.run(host='0.0.0.0', port=port, debug=False)
