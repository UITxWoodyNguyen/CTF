#!/usr/bin/env python3
from pwn import *
from Crypto.Util.number import inverse
import math

# Curve parameters
p = 1844669347765474229
a = 0
b = 1
n = 1844669347765474230
Gx = 27
Gy = 728430165157041631

# Local elliptic curve implementation for local computation
class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y
    
    def __eq__(self, other):
        if other is None:
            return self.x is None
        return self.x == other.x and self.y == other.y
    
    def __add__(self, other):
        if self.x is None:
            return other
        if other.x is None:
            return self
        if self.x == other.x and self.y == (-other.y % p):
            return Point(None, None)
        if self.x == other.x:
            s = (3 * self.x**2 + a) * inverse(2 * self.y, p) % p
        else:
            s = (other.y - self.y) * inverse(other.x - self.x, p) % p
        x3 = (s*s - self.x - other.x) % p
        y3 = (s * (self.x - x3) - self.y) % p
        return Point(x3, y3)
    
    def __rmul__(self, scalar):
        result = Point(None, None)
        addend = self
        while scalar:
            if scalar & 1:
                result = result + addend
            addend = addend + addend
            scalar >>= 1
        return result
    
    def __repr__(self):
        if self.x is None:
            return "O"
        return f"({self.x}, {self.y})"

def tuple_to_point(t):
    if t is None:
        return Point(None, None)
    return Point(t[0], t[1])

# Connect to the server
# r = process(['python3', 'curve.py'])
r = remote('curve.ctf.pascalctf.it', 5004)

# Parse the initial output
r.recvuntil(b'Q = (')
Q_data = r.recvuntil(b')').decode().strip(')')
Qx, Qy = map(int, Q_data.split(', '))
print(f"[*] G = ({Gx}, {Gy})")
print(f"[*] Q = ({Qx}, {Qy})")

G = Point(Gx, Gy)
Q = Point(Qx, Qy)

def guess_secret(secret_hex):
    """Submit a guess for the secret"""
    r.recvuntil(b'> ')
    r.sendline(b'1')
    r.recvuntil(b'secret (hex): ')
    r.sendline(secret_hex.encode())
    return r.recvline().decode()

# Factor n
factors = {2: 1, 3: 2, 5: 1, 7: 1, 11: 1, 13: 1, 17: 1, 19: 1, 23: 1, 29: 1, 31: 1, 37: 1, 41: 1, 43: 1, 47: 1}

def pohlig_hellman_local():
    """Solve discrete log using Pohlig-Hellman locally (no oracle needed!)"""
    remainders = []
    moduli = []
    
    for q, e in factors.items():
        q_e = q ** e
        print(f"[*] Solving for prime power {q}^{e} = {q_e}")
        
        # Compute G' = (n / q^e) * G and Q' = (n / q^e) * Q
        cofactor = n // q_e
        
        G_prime = cofactor * G
        Q_prime = cofactor * Q
        
        if Q_prime.x is None:
            remainders.append(0)
            moduli.append(q_e)
            print(f"    secret ≡ 0 (mod {q_e})")
            continue
        
        # Brute force for small q^e (all our primes are <= 47)
        secret_mod = None
        for i in range(q_e):
            test = i * G_prime
            if test.x == Q_prime.x and test.y == Q_prime.y:
                secret_mod = i
                break
        
        if secret_mod is not None:
            remainders.append(secret_mod)
            moduli.append(q_e)
            print(f"    secret ≡ {secret_mod} (mod {q_e})")
        else:
            print(f"    Failed to find secret mod {q_e}")
            return None
    
    # Use CRT to combine
    secret = crt(remainders, moduli)
    return secret

def crt(remainders, moduli):
    """Chinese Remainder Theorem"""
    M = 1
    for m in moduli:
        M *= m
    
    result = 0
    for rem, m in zip(remainders, moduli):
        Mi = M // m
        yi = inverse(Mi, m)
        result += rem * Mi * yi
    
    return result % M

print("[*] Starting Pohlig-Hellman attack (local computation)...")
secret = pohlig_hellman_local()
print(f"[+] Found secret: {secret}")
print(f"[+] Secret in hex: {hex(secret)}")

# Verify locally
verify = secret * G
print(f"[*] Verification: secret * G = ({verify.x}, {verify.y})")
print(f"[*] Expected Q = ({Q.x}, {Q.y})")
print(f"[*] Match: {verify.x == Q.x and verify.y == Q.y}")

# Submit the guess
result = guess_secret(hex(secret))
print(result)

# Check if we got the flag
r.interactive()
