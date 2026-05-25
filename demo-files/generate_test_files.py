"""
Script to generate test files for the gateway demo.
Run this script to create valid, oversized, and fake files for testing.
"""
from PIL import Image
import os

def create_valid_png():
    """Create a small valid PNG image"""
    img = Image.new('RGB', (100, 100), color='blue')
    img.save('demo-files/valid-image.png')
    print("Created valid-image.png (small PNG)")

def create_oversized_jpg():
    """Create an oversized JPG image (>10MB)"""
    # Create a large image
    img = Image.new('RGB', (4000, 4000), color='red')
    img.save('demo-files/large-file.jpg', quality=95)
    print("Created large-file.jpg (oversized JPG)")

def create_fake_executable():
    """Create a fake image file (executable with image extension)"""
    # Create a simple text file but name it as an image
    with open('demo-files/fake-image.jpg.exe', 'w') as f:
        f.write("This is actually an executable file, not an image!")
    print("Created fake-image.jpg.exe (fake file)")

def create_valid_pdf():
    """Create a simple valid PDF"""
    from reportlab.pdfgen import canvas
    c = canvas.Canvas("demo-files/valid-document.pdf")
    c.drawString(100, 750, "This is a valid PDF document")
    c.save()
    print("Created valid-document.pdf (valid PDF)")

def create_malformed_file():
    """Create a malformed file"""
    with open('demo-files/malformed.jpg', 'wb') as f:
        f.write(b'\x00\x01\x02\x03\x04\x05')  # Invalid magic bytes
    print("Created malformed.jpg (malformed file)")

if __name__ == '__main__':
    os.makedirs('demo-files', exist_ok=True)
    
    print("Generating test files...")
    create_valid_png()
    create_oversized_jpg()
    create_fake_executable()
    
    # These require additional libraries, skip if not available
    try:
        create_valid_pdf()
    except ImportError:
        print("Skipping PDF generation (reportlab not installed)")
    
    create_malformed_file()
    print("\nTest files generated successfully!")
