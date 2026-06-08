import os
import uuid
import hashlib
import shutil


def sha256_file(filepath):
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def save_uploaded_files(files, upload_folder):
    session_id = str(uuid.uuid4())
    session_dir = os.path.join(upload_folder, session_id)
    os.makedirs(session_dir, exist_ok=True)
    saved = []
    for f in files:
        if not f.filename:
            continue
        filepath = os.path.join(session_dir, f.filename)
        f.save(filepath)
        saved.append({
            'filename': f.filename,
            'filepath': filepath,
            'file_size': os.path.getsize(filepath),
            'file_hash': sha256_file(filepath),
        })
    return session_id, session_dir, saved


def cleanup_session(session_dir):
    if os.path.exists(session_dir):
        shutil.rmtree(session_dir, ignore_errors=True)
