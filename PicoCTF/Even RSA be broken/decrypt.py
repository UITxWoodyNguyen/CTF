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
