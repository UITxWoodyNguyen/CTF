# Linear101 - WannaGame Championship 2025

## 1. Description

Đây là một bài CTF về **Cryptography** sử dụng **Max-Plus Algebra** (Đại số Max-Plus).

### Source code server:

```python
import random
import os

n = 128
random.seed("Wanna Win?")

def encrypt(A, x):
    b = [0] * n
    for i in range(n):
        for j in range(n):
            b[i] = max(b[i], A[i][j] + x[j])
    return b

def game():
    for round in range(64):
        try:
            print(f"Round {round+1}/64")
            A = [random.randbytes(n) for _ in range(n)]
            x = os.urandom(128)
            b = encrypt(A, x)

            print(f"{b = }")
            sol = bytes.fromhex(input("x = "))
            if len(sol) != n:
                return False
            
            if encrypt(A, sol) != b:
                print("Wrong!")
                return False
        except:
            return False
    return True

if game():
    print(open("flag.txt", "r").read())
else:
    print("You lose...")
```

### Luồng hoạt động:
1. Server tạo **64 vòng chơi**
2. Mỗi vòng:
   - Tạo ma trận `A` kích thước **128x128** (dùng `random.randbytes`)
   - Tạo vector bí mật `x` có **128 bytes** (dùng `os.urandom`)
   - Tính `b = encrypt(A, x)` và gửi `b` cho client
   - Client phải gửi lại một `sol` sao cho `encrypt(A, sol) == b`
3. Nếu qua được 64 vòng → nhận Flag

---

## 2. Lỗ hổng (Vulnerability)

### 🔑 Lỗ hổng 1: Seed cố định
```python
random.seed("Wanna Win?")
```
Server dùng **seed cố định** cho `random`. Điều này có nghĩa:
- Ta có thể **tái tạo hoàn toàn** ma trận `A` ở phía client
- Chỉ cần gọi `random.seed("Wanna Win?")` và `random.randbytes(n)` theo đúng thứ tự

### 🔑 Lỗ hổng 2: Không yêu cầu tìm đúng x gốc
Server chỉ kiểm tra:
```python
if encrypt(A, sol) != b:
    return False
```
→ Ta **không cần tìm đúng `x` ban đầu**, chỉ cần tìm **bất kỳ `sol` nào** thỏa mãn `encrypt(A, sol) == b`

---

## 3. Phân tích toán học: Max-Plus Algebra

### Công thức mã hóa:
$$b[i] = \max_{j=0}^{n-1}(A[i][j] + x[j])$$

Với mỗi `i`, giá trị `b[i]` là **giá trị lớn nhất** trong tất cả các tổng `A[i][j] + x[j]`.

### Cách giải ngược:

Từ công thức trên, ta có:
$$b[i] \geq A[i][j] + x[j] \quad \forall i, j$$

Suy ra:
$$x[j] \leq b[i] - A[i][j] \quad \forall i$$

Do đó, giá trị **lớn nhất có thể** của `x[j]` là:
$$x[j] = \min_{i=0}^{n-1}(b[i] - A[i][j])$$

### Tại sao công thức này đúng?

1. **Điều kiện đủ**: Với `x[j] = min(b[i] - A[i][j])`, ta đảm bảo:
   - `A[i][j] + x[j] ≤ b[i]` với mọi `i, j`
   - Nên `max(A[i][j] + x[j]) ≤ b[i]`

2. **Điều kiện cần**: Với mỗi `i`, tồn tại ít nhất một `j*` sao cho `b[i] = A[i][j*] + x[j*]`
   - Khi `x[j]` đạt giá trị lớn nhất có thể, đẳng thức xảy ra

---

## 4. Exploit Script

```python
from pwn import *
import random
import ast

HOST = 'challenge.cnsc.com.vn'
PORT = 31419

def solve():
    try:
        r = remote(HOST, PORT)
    except:
        print("Lỗi kết nối! Hãy kiểm tra lại IP và Port.")
        return

    # Đồng bộ Random Seed với server
    random.seed("Wanna Win?")
    n = 128

    print("Đang kết nối và giải 64 vòng...")

    for round_num in range(1, 65):
        try:
            # Tái tạo ma trận A (đồng bộ với server)
            A = [random.randbytes(n) for _ in range(n)]

            # Đọc dữ liệu từ Server
            r.recvuntil(b'/64')
            r.recvuntil(b'b = ')
            b_str = r.recvline().strip().decode()
            b = ast.literal_eval(b_str)

            # Giải: x[j] = min(b[i] - A[i][j]) với mọi i
            sol = []
            for j in range(n):
                min_diff = float('inf')
                for i in range(n):
                    diff = b[i] - A[i][j]
                    if diff < min_diff:
                        min_diff = diff
                
                val = max(0, min(255, int(min_diff)))
                sol.append(val)

            # Gửi kết quả
            sol_bytes = bytes(sol)
            r.sendline(sol_bytes.hex().encode())
            
            print(f"Round {round_num}/64: Done")

        except Exception as e:
            print(f"Lỗi tại vòng {round_num}: {e}")
            r.close()
            return

    print("\n" + "="*30)
    print("Đang chờ Flag...")
    print(r.recvall().decode())
    print("="*30)

if __name__ == "__main__":
    solve()
```

---

## 5. Giải thích các bước exploit

| Bước | Mô tả |
|------|-------|
| 1 | Đồng bộ `random.seed("Wanna Win?")` giống server |
| 2 | Mỗi vòng: tái tạo ma trận `A` bằng `random.randbytes(n)` |
| 3 | Nhận vector `b` từ server |
| 4 | Tính `x[j] = min(b[i] - A[i][j])` cho mỗi `j` |
| 5 | Clamp giá trị về `[0, 255]` (vì x là bytes) |
| 6 | Gửi solution dạng hex |

---

**Flag:** `W1{...}` (sau khi chạy exploit thành công)
