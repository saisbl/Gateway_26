# Demo Test Files

This directory contains test files for demonstrating the gateway's security features.

## Files

- **valid-image.png**: A small valid PNG image (100x100 pixels) - should be accepted
- **large-file.jpg**: An oversized JPG image (>10MB) - should be rejected due to size
- **fake-image.jpg.exe**: A file with double extension - should be rejected
- **malformed.jpg**: A file with invalid magic bytes - should be rejected
- **valid-document.pdf**: A valid PDF document - should be accepted

## Generating Files

Run the generation script to create these files:

```bash
cd demo-files
python generate_test_files.py
```

Note: The script requires Pillow (PIL) for image generation. Install with:
```bash
pip install Pillow reportlab
```

## Manual Creation

If you prefer to create files manually:

### Valid PNG
```bash
# Create a simple 1x1 pixel PNG
echo -n $'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\xcf\xc0\x00\x00\x00\x03\x00\x01\x00\x00\x00\x00IEND\xaeB`\x82' > valid-image.png
```

### Fake Executable
```bash
echo "This is an executable" > fake-image.jpg.exe
```

### Malformed File
```bash
echo -n $'\x00\x01\x02\x03' > malformed.jpg
```
