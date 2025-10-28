# EVEN RSA CAN BE BROKEN???

### Information
- Category: Cryptography
- Points: 
- Level: Easy

### Description
We are given an encrypted flag and it need to be decrypted with just N and e. Moreover, we can connect with the problem via `nc verbal-sleep.picoctf.net <port>`.

This is the source code (or encryption code) of this problem:
```
from sys import exit
from Crypto.Util.number import bytes_to_long, inverse
from setup import get_primes

e = 65537

def gen_key(k):
    """
    Generates RSA key with k bits
    """
    p,q = get_primes(k//2)
    N = p*q
    d = inverse(e, (p-1)*(q-1))

    return ((N,e), d)

def encrypt(pubkey, m):
    N,e = pubkey
    return pow(bytes_to_long(m.encode('utf-8')), e, N)

def main(flag):
    pubkey, _privkey = gen_key(1024)
    encrypted = encrypt(pubkey, flag) 
    return (pubkey[0], encrypted)

if __name__ == "__main__":
    flag = open('flag.txt', 'r').read()
    flag = flag.strip()
    N, cypher  = main(flag)
    print("N:", N)
    print("e:", e)
    print("cyphertext:", cypher)
    exit()
```

### Hint
- How much do we trust randomness?
- Notice anything interesting about N?
- Try comparing N across multiple requests

## Solution
**General Purpose**

The script finds the prime factors *p* and *q* of *N* using the Pollard-Rho algorithm, computes *d = e⁻¹ (mod φ(N))*, then decrypts *m = cᵈ mod N* and converts the integer *m* back into bytes/text.

---
**is_probable_prime(n)**
* Checks divisibility by a few small primes first.
* Performs the Miller–Rabin primality test (with default iterations) to ensure *n* is very likely prime.
---
**pollards_rho(n)** and **factor(n)**
* `pollards_rho` uses the Pollard’s Rho algorithm with the polynomial *x² + c* to find a non-trivial factor.
* `factor` is recursive: if *n* is prime, return `[n]`; otherwise, recursively factorize *n* into `factor(d)` and `factor(n // d)`.
---
**egcd(a, b)** and **modinv(a, m)**
* `egcd` returns *(g, x, y)* such that *a·x + b·y = g = gcd(a, b)*.
* `modinv` uses `egcd` to compute the modular inverse; if *gcd ≠ 1*, the inverse does not exist.
---
**int_to_bytes(i)**
* Converts an integer into bytes in big-endian format with the minimal necessary length.
---
**RSA Steps and Decryption Process**
1. Once *p* and *q* are found: compute *φ = (p − 1)·(q − 1)*.
2. Compute *d = modinv(e, φ)*.
3. Decrypt with *m = pow(c, d, N)* to recover the plaintext integer.
4. Convert *m* to bytes and decode as UTF-8 (if possible).
---
## Here is the source code to decrypt:
```
# python
import random
import math
import sys

# Provided values
N = 13766651721596981183700741297150369230560689069128230324035953820292272595787831642980286580900189101899655207185461323724166161033755321783245900457593642
e = 65537
c = 12650574523295862466968262296002829716074883118225376801952835632693254994614585073790631068974000423096213782792321774836192460558640712764393359893582681

def is_probable_prime(n, k=8):
    if n < 2:
        return False
    small_primes = [2,3,5,7,11,13,17,19,23,29,31,37,41]
    for p in small_primes:
        if n % p == 0:
            return n == p
    # write n-1 as d*2^s
    s = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        composite = True
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                composite = False
                break
        if composite:
            return False
    return True

def pollards_rho(n):
    if n % 2 == 0:
        return 2
    if is_probable_prime(n):
        return n
    while True:
        x = random.randrange(2, n - 1)
        y = x
        c = random.randrange(1, n - 1)
        d = 1
        while d == 1:
            x = (x*x + c) % n
            y = (y*y + c) % n
            y = (y*y + c) % n
            d = math.gcd(abs(x - y), n)
            if d == n:
                break
        if d > 1 and d < n:
            return d

def factor(n):
    if n == 1:
        return []
    if is_probable_prime(n):
        return [n]
    d = pollards_rho(n)
    if d == n:
        return [n]
    left = factor(d)
    right = factor(n // d)
    return left + right

def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return (g, x, y)

def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("modular inverse does not exist")
    return x % m

def int_to_bytes(i):
    if i == 0:
        return b'\x00'
    length = (i.bit_length() + 7) // 8
    return i.to_bytes(length, 'big')

def main():
    primes = sorted(factor(N))
    if len(primes) != 2:
        print("Warning: expected 2 prime factors, got:", primes, file=sys.stderr)
    p, q = primes[0], primes[1]
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)
    m = pow(c, d, N)
    plaintext = int_to_bytes(m)
    try:
        print(plaintext.decode('utf-8'))
    except:
        print(plaintext)

if __name__ == "__main__":
    main()
```
