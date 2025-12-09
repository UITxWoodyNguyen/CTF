# Mapping từ hash của hàm call_once → ký tự tương ứng
hash_to_char = {
    "h32497efb348ffe3c": "H",   # 0x48
    "h827ece763c8c7e2e": "T",   # 0x54
    "h784eba9476a4f0f4": "B",   # 0x42
    "hc26775751c1be756": "{",   # 0x7B
    "hc599f6727ca8db95": "d",   # 0x64
    "h40d00bd196c3c783": "0",   # 0x30
    "h4e1d94269d5dab9f": "n",   # 0x6E
    "h1e50475f0ef4e3b2": "t",   # 0x74
    "h28c42c5fb55e3f9f": "_",   # 0x5F
    "h08f069e45c38c91b": "p",   # 0x70
    "h70ddab66eb3eaf7e": "4",   # 0x34
    "h5935cc8a67508b36": "1",   # 0x31
    "h2ed86dfdd0fc9ca5": "c",   # 0x63
    "h076f93abc7994a2b": "h",   # 0x68  ← SỬA TỪ ! THÀNH h
    "ha0a2d91800448694": "e",   # 0x65
    "hd3a717188d9c9564": "3",   # 0x33
    "h4aee5a63c69b281c": "r",   # 0x72
    "h3dae80a6281f81f5": "o",   # 0x6F
    "he29dc24b9b003076": "}",   # 0x7D
}

# Thứ tự các hàm được gọi trong check_flag (31 vị trí)
func_order = [
    "h32497efb348ffe3c",  # 0  - H
    "h827ece763c8c7e2e",  # 1  - T
    "h784eba9476a4f0f4",  # 2  - B
    "hc26775751c1be756",  # 3  - {
    "hc599f6727ca8db95",  # 4  - d
    "h40d00bd196c3c783",  # 5  - 0
    "h4e1d94269d5dab9f",  # 6  - n
    "h1e50475f0ef4e3b2",  # 7  - t
    "h28c42c5fb55e3f9f",  # 8  - _
    "h08f069e45c38c91b",  # 9  - p
    "h70ddab66eb3eaf7e",  # 10 - 4
    "h4e1d94269d5dab9f",  # 11 - n
    "h5935cc8a67508b36",  # 12 - 1
    "h2ed86dfdd0fc9ca5",  # 13 - c
    "h28c42c5fb55e3f9f",  # 14 - _
    "h2ed86dfdd0fc9ca5",  # 15 - c
    "h70ddab66eb3eaf7e",  # 16 - 4
    "h1e50475f0ef4e3b2",  # 17 - t
    "h2ed86dfdd0fc9ca5",  # 18 - c
    "h076f93abc7994a2b",  # 19 - h  ← SỬA
    "h28c42c5fb55e3f9f",  # 20 - _
    "h1e50475f0ef4e3b2",  # 21 - t
    "h076f93abc7994a2b",  # 22 - h  ← SỬA
    "ha0a2d91800448694",  # 23 - e
    "h28c42c5fb55e3f9f",  # 24 - _
    "hd3a717188d9c9564",  # 25 - 3
    "h4aee5a63c69b281c",  # 26 - r
    "h4aee5a63c69b281c",  # 27 - r
    "h3dae80a6281f81f5",  # 28 - o
    "h4aee5a63c69b281c",  # 29 - r
    "he29dc24b9b003076",  # 30 - }
]

# Ghép flag
flag = ""
for i, func_hash in enumerate(func_order):
    char = hash_to_char[func_hash]
    flag += char
    print(f"[{i:2d}] {func_hash} -> '{char}'")

print("\n" + "="*50)
print(f"🚩 FLAG: {flag}")
print("="*50)
