# Crypto Challenges Writeups - PascalCTF

## 1. XorD

> **50 points** - Filippo Boschi <@pllossi>
>
> *I just discovered bitwise operators, so I guess 1 XOR 1 = 1?*

### Đề cho gì?

Đề bài cho source code `xord.py` mã hóa flag bằng XOR với random key, và file `output.txt` chứa ciphertext dạng hex.

```python
import os
import random

def xor(a, b):
    return bytes([a ^ b])

flag = os.getenv('FLAG', 'pascalCTF{REDACTED}')
encripted_flag = b''
random.seed(1337)

for i in range(len(flag)):
    random_key = random.randint(0, 255)
    encripted_flag += xor(ord(flag[i]), random_key)

with open('output.txt', 'w') as f:
    f.write(encripted_flag.hex())
```

Output ciphertext:
```
cb35d9a7d9f18b3cfc4ce8b852edfaa2e83dcd4fb44a35909ff3395a2656e1756f3b505bf53b949335ceec1b70e0
```

### Nhận xét gì?

Điểm yếu ở đây rất rõ ràng: **random seed cố định là 1337**. Khi biết seed, ta có thể reproduce lại toàn bộ chuỗi random number được sử dụng làm key. Vì Python's random module sử dụng Mersenne Twister PRNG, cùng seed sẽ cho ra cùng sequence.

### Hướng giải

Đơn giản là khởi tạo lại random với cùng seed 1337, sau đó XOR lại từng byte của ciphertext với các random key tương ứng:

```python
import random

enc_hex = "cb35d9a7d9f18b3cfc4ce8b852edfaa2e83dcd4fb44a35909ff3395a2656e1756f3b505bf53b949335ceec1b70e0"
enc_bytes = bytes.fromhex(enc_hex)
random.seed(1337)

flag = ''
for b in enc_bytes:
    random_key = random.randint(0, 255)
    flag += chr(b ^ random_key)
print(flag)
```

### Kết luận

Lỗi ở đây là **sử dụng seed cố định cho PRNG** trong mã hóa. Random số trong cryptography phải sử dụng CSPRNG (Cryptographically Secure PRNG) như `os.urandom()` hoặc module `secrets`, không bao giờ dùng `random` module với seed cố định.

**Flag:** `pascalCTF{r4nd0m_1s_n0t_s0_r4nd0m_4ft3r_4ll}`

---

## 2. Ice Cramer

> **50 points** - Alan Davide Bovo <@AlBovo>
>
> *Elia's swamped with algebra but craving a new ice-cream flavor, help him crack these equations so he can trade books for a cone!*
>
> `nc cramer.ctf.pascalctf.it 5002`

### Đề cho gì?

Đề bài cho source code `main.py` sinh ra một hệ phương trình tuyến tính từ các ký tự trong flag:

```python
import os
from random import randint

def generate_variable():
    flag = os.getenv("FLAG", "pascalCTF{REDACTED}")
    flag = flag.replace("pascalCTF{", "").replace("}", "")
    x = [ord(i) for i in flag]
    return x

def generate_system(values):
    for _ in values:
        eq = []
        sol = 0
        for i in range(len(values)):
            k = randint(-100, 100)
            eq.append(f"{k}*x_{i}")
            sol += k * values[i]

        streq = " + ".join(eq) + " = " + str(sol)
        print(streq)


def main():
    x = generate_variable()
    generate_system(x)
    print("\nSolve the system of equations to find the flag!")

if __name__ == "__main__":
    main()
```

Khi connect tới server, ta nhận được một hệ n phương trình n ẩn dạng:
```
k1*x_0 + k2*x_1 + ... + kn*x_{n-1} = result
...
```

### Nhận xét gì?

Flag được chuyển thành list các ASCII values `[ord(c) for c in flag]` làm các ẩn số `x_0, x_1, ..., x_{n-1}`. Server sinh ra một hệ phương trình tuyến tính với coefficients ngẫu nhiên từ -100 đến 100. Đây là bài toán giải hệ phương trình tuyến tính cơ bản, có thể giải bằng quy tắc Cramer hoặc numpy.

### Hướng giải

Connect tới server, parse các phương trình, xây dựng ma trận hệ số A và vector kết quả b, sau đó giải hệ Ax = b:

```python
import socket
import re
import numpy as np

HOST = 'cramer.ctf.pascalctf.it'
PORT = 5002

s = socket.create_connection((HOST, PORT))

recv = b''
while True:
    data = s.recv(4096)
    if not data:
        break
    recv += data
    if b'Solve the system of equations' in recv:
        break

text = recv.decode()

# Extract equations
lines = [line for line in text.splitlines() if '*x_' in line]

# Parse equations
coefs = []
results = []
for line in lines:
    left, right = line.split('=')
    right = int(right.strip())
    terms = left.strip().split('+')
    row = []
    for term in terms:
        m = re.match(r'([\-\d]+)\*x_(\d+)', term.strip())
        row.append(int(m.group(1)))
    coefs.append(row)
    results.append(right)

# Solve the system
A = np.array(coefs)
b = np.array(results)
x = np.linalg.solve(A, b)

# Convert to flag
flag = ''.join(chr(int(round(i))) for i in x)
print('pascalCTF{' + flag + '}')
```

### Kết luận

Đây là bài toán **đại số tuyến tính** cơ bản. Lỗi ở đây là sử dụng hệ phương trình tuyến tính để "ẩn" flag - với n phương trình độc lập tuyến tính cho n ẩn, luôn có nghiệm duy nhất. Bất kỳ ai biết linear algebra đều có thể giải.

**Flag:** `pascalCTF{cr4m3r_rul3s_th3_m4th_w0rld}`

---

## 3. Linux Penguin

> **147 points** - Alan Davide Bovo <@AlBovo>
>
> *I've just installed Arch Linux and I couldn't be any happier :)*
>
> `nc penguin.ctf.pascalctf.it 5003`

### Đề cho gì?

Đề bài cho source code `penguin.py` sử dụng AES-ECB để encrypt words:

```python
from Crypto.Cipher import AES
import random
import os

key = os.urandom(16)
cipher = AES.new(key, AES.MODE_ECB)

words = [
    "biocompatibility", "biodegradability", "characterization", "contraindication",
    "counterbalancing", "counterintuitive", "decentralization", "disproportionate",
    "electrochemistry", "electromagnetism", "environmentalist", "internationality",
    "internationalism", "institutionalize", "microlithography", "microphotography",
    "misappropriation", "mischaracterized", "miscommunication", "misunderstanding",
    "photolithography", "phonocardiograph", "psychophysiology", "rationalizations",
    "representational", "responsibilities", "transcontinental", "unconstitutional"
]

def encrypt_words(wordst: list[str]) -> list[str]:
    encrypted_words = []
    for word in wordst:
        padded_word = word.ljust(16)
        encrypted = cipher.encrypt(padded_word.encode()).hex()
        encrypted_words.append(encrypted)
    return encrypted_words

def main():
    selected_words = random.choices(words, k=5)
    ciphertext = ' '.join(encrypt_words(selected_words))
    
    for i in range(7):
        print("Give me 4 words to encrypt:")
        user_words = [input(f"Word {j+1}: ").strip() for j in range(4)]
        encrypted_words = encrypt_words(user_words)
        print(f"Encrypted words: {' '.join(encrypted_words)}")

    print("Can you now guess what are these encrypted words?")
    print(f"Ciphertext: {ciphertext}")

    for i in range(5):
        guess = input(f"Guess the word {i+1}: ")
        if guess not in selected_words:
            print("Wrong guess.")
            return
        selected_words.remove(guess)

    print_flag()
```

### Nhận xét gì?

AES-ECB có một điểm yếu quan trọng: **cùng plaintext với cùng key sẽ luôn cho ra cùng ciphertext**. Server cho ta 7 lượt encrypt, mỗi lượt 4 words = 28 encryptions. Ta có đúng 28 words trong wordlist, nên có thể encrypt tất cả và build mapping table.

### Hướng giải

1. Trong 7 lượt, gửi tất cả 28 words trong wordlist (mỗi lượt 4 words)
2. Build dictionary mapping: ciphertext → plaintext
3. Khi nhận 5 challenge ciphertexts, tra dictionary để tìm ra 5 words tương ứng

```python
from pwn import *

HOST = 'penguin.ctf.pascalctf.it'
PORT = 5003

words = [
    "biocompatibility", "biodegradability", # ... all 28 words
]

r = remote(HOST, PORT)

# Build cipher -> word mapping by encrypting all 28 words
cipher_to_word = {}
for round_num in range(7):
    batch = words[round_num*4:(round_num+1)*4]
    for w in batch:
        r.recvuntil(b": ")
        r.sendline(w.encode())
    
    r.recvuntil(b"Encrypted words: ")
    encs = r.recvline().decode().strip().split()
    
    for w, c in zip(batch, encs):
        cipher_to_word[c] = w

# Get challenge ciphertexts
r.recvuntil(b"Ciphertext: ")
challenge_cts = r.recvline().decode().strip().split()

# Map to words and submit guesses
for c in challenge_cts:
    r.recvuntil(b": ")
    r.sendline(cipher_to_word[c].encode())

r.interactive()
```

### Kết luận

Lỗi ở đây là **sử dụng AES-ECB mode**. ECB không có IV/nonce nên deterministic - cùng plaintext cho cùng ciphertext. Đây là lý do tại sao ECB không nên được sử dụng trong thực tế. Nên sử dụng CBC, CTR, hoặc GCM mode với IV ngẫu nhiên.

**Flag:** `pascalCTF{3cb_m0d3_1s_n0t_s3cur3}`

---

## 4. Curve Ball

> **286 points** - Alan Davide Bovo <@AlBovo>
>
> *Our casino's new cryptographic gambling system uses elliptic curves for provably fair betting.*
>
> *We're so confident in our implementation that we even give you an oracle to verify points!*
>
> `nc curve.ctf.pascalctf.it 5004`

### Đề cho gì?

Đề bài cho source code `curve.py` implement một Elliptic Curve Diffie-Hellman challenge:

```python
from Crypto.Util.number import bytes_to_long, inverse
import os

p = 1844669347765474229
a = 0
b = 1
n = 1844669347765474230
Gx = 27
Gy = 728430165157041631

FLAG = os.environ.get('FLAG', 'pascalCTF{REDACTED}')

class Point:
    # ... standard EC point addition and scalar multiplication

def main():
    secret = bytes_to_long(os.urandom(8)) % n
    G = Point(Gx, Gy)
    Q = secret * G
    
    print(f"y^2 = x^3 + 1 (mod {p})")
    print(f"n = {n}")
    print(f"G = ({Gx}, {Gy})")
    print(f"Q = ({Q.x}, {Q.y})")
    
    # Menu: 1. Guess secret, 2. Compute k*P, 3. Exit
```

Nhiệm vụ: cho biết G và Q = secret * G, tìm secret.

### Nhận xét gì?

Đây là bài toán Elliptic Curve Discrete Logarithm Problem (ECDLP). Thông thường ECDLP rất khó, nhưng nhìn vào order n:

```
n = 1844669347765474230 = 2 × 3² × 5 × 7 × 11 × 13 × 17 × 19 × 23 × 29 × 31 × 37 × 41 × 43 × 47
```

Order n là **smooth number** (tích của nhiều prime nhỏ)! Điều này cho phép áp dụng **Pohlig-Hellman algorithm** để giải ECDLP trong thời gian polynomial.

### Hướng giải

Pohlig-Hellman algorithm:
1. Factor n thành các prime powers: n = p₁^e₁ × p₂^e₂ × ... × pₖ^eₖ
2. Với mỗi prime power pᵢ^eᵢ:
   - Tính G' = (n/pᵢ^eᵢ) × G và Q' = (n/pᵢ^eᵢ) × Q
   - Brute force tìm secret mod pᵢ^eᵢ (chỉ cần thử tối đa pᵢ^eᵢ giá trị)
3. Dùng Chinese Remainder Theorem (CRT) để kết hợp các kết quả

```python
from pwn import *
from Crypto.Util.number import inverse

p = 1844669347765474229
n = 1844669347765474230
Gx, Gy = 27, 728430165157041631

factors = {2: 1, 3: 2, 5: 1, 7: 1, 11: 1, 13: 1, 17: 1, 19: 1, 
           23: 1, 29: 1, 31: 1, 37: 1, 41: 1, 43: 1, 47: 1}

r = remote('curve.ctf.pascalctf.it', 5004)

# Parse Q from server
r.recvuntil(b'Q = (')
Q_data = r.recvuntil(b')').decode().strip(')')
Qx, Qy = map(int, Q_data.split(', '))

G = Point(Gx, Gy)
Q = Point(Qx, Qy)

# Pohlig-Hellman
remainders, moduli = [], []
for q, e in factors.items():
    q_e = q ** e
    cofactor = n // q_e
    G_prime = cofactor * G
    Q_prime = cofactor * Q
    
    # Brute force (q^e is small, max 47)
    for i in range(q_e):
        if (i * G_prime) == Q_prime:
            remainders.append(i)
            moduli.append(q_e)
            break

# CRT
secret = crt(remainders, moduli)

# Submit guess
r.recvuntil(b'> ')
r.sendline(b'1')
r.recvuntil(b'secret (hex): ')
r.sendline(hex(secret).encode())
r.interactive()
```

### Kết luận

Lỗi ở đây là **chọn curve với smooth order**. Khi order của curve là smooth (có nhiều factor nhỏ), Pohlig-Hellman algorithm có thể giải ECDLP hiệu quả. Trong thực tế, cần chọn curve có order là prime hoặc có large prime factor để đảm bảo an toàn.

**Flag:** `pascalCTF{sm00th_curv3s_4r3_n0t_s4f3}`

---

## Tổng kết

| Challenge | Vulnerability | Attack |
|-----------|--------------|--------|
| XOR'd | Fixed PRNG seed | Reproduce random sequence |
| Ice | Linear system | Solve with numpy/Cramer |
| Penguin | AES-ECB determinism | Build ciphertext mapping |
| Curve Ball | Smooth curve order | Pohlig-Hellman + CRT |

### Bài học về Cryptography:
1. **Không dùng random module** cho crypto - dùng `secrets` hoặc `os.urandom()`
2. **Không dùng ECB mode** - dùng CBC/CTR/GCM với random IV
3. **Chọn curve parameters cẩn thận** - order phải có large prime factor
4. **Linear algebra không phải là cryptography** - hệ phương trình tuyến tính dễ giải
