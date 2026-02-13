# Roulette - Crypto CTF Challenge Writeup

## Thông tin challenge

- **Tên:** Roulette
- **Thể loại:** Crypto
- **Server:** `nc chall.0xfun.org 45386`
- **Flag:** `0xfun{m3rs3nn3_tw1st3r_unr4v3l3d}`

## Phân tích source code

```python
import random

class MersenneOracle:
    def __init__(self):
        self.mt = random.Random()
        self.seed = random.randint(0, 2**32 - 1)
        self.mt.seed(self.seed)

    def spin(self):
        raw = self.mt.getrandbits(32)
        obfuscated = raw ^ 0xCAFEBABE
        return obfuscated
```

### Phân tích:
1. Server sử dụng **Mersenne Twister (MT19937)** - thuật toán sinh số ngẫu nhiên mặc định của Python
2. Mỗi lần `spin`, server trả về giá trị `raw ^ 0xCAFEBABE`
3. Server có 2 lệnh: `spin` (lấy số ngẫu nhiên) và `predict` (dự đoán 10 số tiếp theo)

## Lỗ hổng

**Mersenne Twister có thể bị clone hoàn toàn nếu biết 624 outputs liên tiếp.**

MT19937 có state gồm 624 số 32-bit. Sau khi quan sát 624 outputs, ta có thể:
1. **Reverse tempering** để lấy lại state gốc
2. **Clone state** vào một MT instance mới
3. **Dự đoán** tất cả các số tiếp theo

## Giải pháp

### Bước 1: Thu thập 624 outputs

```python
outputs = []
for i in range(624):
    s.send(b'spin\n')
    data = s.recv(1024)
    obfuscated = int(data.strip())
    raw = obfuscated ^ 0xCAFEBABE  # Reverse XOR
    outputs.append(raw)
```

### Bước 2: Untemper function

MT19937 áp dụng **tempering** trước khi output:
```
y ^= y >> 11
y ^= (y << 7) & 0x9D2C5680
y ^= (y << 15) & 0xEFC60000
y ^= y >> 18
```

Ta cần reverse lại:

```python
def untemper(y):
    # Undo y ^= y >> 18
    y ^= y >> 18
    
    # Undo y ^= (y << 15) & 0xEFC60000
    y ^= (y << 15) & 0xEFC60000
    
    # Undo y ^= (y << 7) & 0x9D2C5680
    for i in range(7):
        y ^= ((y << 7) & 0x9D2C5680)
    
    # Undo y ^= y >> 11
    for i in range(3):
        y ^= y >> 11
    
    return y & 0xFFFFFFFF
```

### Bước 3: Clone MT state

```python
def clone_mt(outputs):
    state = [untemper(o) for o in outputs[:624]]
    state.append(624)  # index = 624 sau khi generate 624 số
    return (3, tuple(state), None)

mt = random.Random()
mt.setstate(clone_mt(outputs))
```

### Bước 4: Dự đoán 10 số tiếp theo

```python
predictions = []
for _ in range(10):
    next_raw = mt.getrandbits(32)
    predictions.append(next_raw)

# Gửi predictions
prediction_str = ' '.join(map(str, predictions))
s.send(f'{prediction_str}\n'.encode())
```

## Full exploit

```python
#!/usr/bin/env python3
import socket
import random

def untemper(y):
    y ^= y >> 18
    y ^= (y << 15) & 0xEFC60000
    for i in range(7):
        y ^= ((y << 7) & 0x9D2C5680)
    for i in range(3):
        y ^= y >> 11
    return y & 0xFFFFFFFF

def clone_mt(outputs):
    state = [untemper(o) for o in outputs[:624]]
    state.append(624)
    return (3, tuple(state), None)

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('chall.0xfun.org', 45386))
    s.settimeout(10)
    s.recv(1024)
    
    # Thu thập 624 outputs
    outputs = []
    for i in range(624):
        s.send(b'spin\n')
        data = b''
        while b'\n' not in data:
            data += s.recv(1024)
        line = data.split(b'\n')[0].strip().decode()
        if '>' in line:
            line = line.replace('>', '').strip()
        obfuscated = int(line)
        raw = obfuscated ^ 0xCAFEBABE
        outputs.append(raw)
    
    # Clone MT state
    mt = random.Random()
    mt.setstate(clone_mt(outputs))
    
    # Dự đoán 10 số tiếp theo
    predictions = [mt.getrandbits(32) for _ in range(10)]
    
    # Gửi predict
    s.send(b'predict\n')
    s.recv(1024)
    
    prediction_str = ' '.join(map(str, predictions))
    s.send(prediction_str.encode() + b'\n')
    
    print(s.recv(4096).decode())
    s.close()

if __name__ == "__main__":
    main()
```

## Kết quả

```
PERFECT! You've untwisted the Mersenne Oracle!
0xfun{m3rs3nn3_tw1st3r_unr4v3l3d}
```

## Kiến thức học được

1. **Mersenne Twister không an toàn cho cryptography** - Chỉ cần 624 outputs là có thể clone hoàn toàn
2. **Tempering có thể reverse** - Các phép XOR và shift đều có thể đảo ngược
3. **Không dùng `random` cho security** - Nên dùng `secrets` hoặc `os.urandom()` thay thế

## Tham khảo

- [Mersenne Twister - Wikipedia](https://en.wikipedia.org/wiki/Mersenne_Twister)
- [Cracking Random Number Generators](https://jazzy.id.au/2010/09/22/cracking_random_number_generators_part_3.html)
