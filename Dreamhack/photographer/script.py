import sys
import ctypes

def load_libc():
    # Attempt to load standard Linux C library to replicate srand/rand
    libs = ['libc.so.6', '/lib/x86_64-linux-gnu/libc.so.6', '/lib/i386-linux-gnu/libc.so.6']
    for l in libs:
        try:
            return ctypes.CDLL(l)
        except OSError:
            continue
    print("[-] Error: Could not load libc.so.6. Please run this on Linux.")
    sys.exit(1)

def ror(val, n):
    """Rotate Right (8-bit)"""
    n &= 7
    return ((val >> n) | (val << (8 - n))) & 0xFF

def rol(val, n):
    """Rotate Left (8-bit)"""
    n &= 7
    return ((val << n) | (val >> (8 - n))) & 0xFF

def decrypt():
    input_filename = "flag.bmp.enc"
    output_filename = "flag.bmp"

    # Load libc and seed RNG
    libc = load_libc()
    seed = 48879
    libc.srand(seed)
    print(f"[+] Seeding RNG with {seed}")

    try:
        with open(input_filename, "rb") as f:
            data = bytearray(f.read())
    except FileNotFoundError:
        print(f"[-] Error: Could not find {input_filename}")
        return

    print(f"[+] Decrypting {len(data)} bytes...")

    # Process byte by byte
    for i in range(len(data)):
        # Important: rand() is called exactly once per iteration in the original code,
        # regardless of the case. We must match this state update.
        r = libc.rand()
        
        enc_byte = data[i]
        dec_byte = 0
        
        idx = i % 3

        if idx == 0:
            # Enc Logic: 
            # v7 = ror(old, 7)
            # v9 = rol((v7 + r), 4)
            
            # Dec Logic:
            # 1. Inverse outer rotate (ROL 4 -> ROR 4)
            tmp = ror(enc_byte, 4)
            # 2. Inverse addition (Sub r)
            tmp = (tmp - r) & 0xFF
            # 3. Inverse inner rotate (ROR 7 -> ROL 7)
            dec_byte = rol(tmp, 7)

        elif idx == 1:
            # Enc Logic:
            # n7 = r % 8
            # new = ror(old, n7)
            
            # Dec Logic:
            # Inverse ROR is ROL
            n7 = r % 8
            dec_byte = rol(enc_byte, n7)

        elif idx == 2:
            # Enc Logic:
            # new = (old ^ r) - 24
            
            # Dec Logic:
            # 1. Inverse subtraction (Add 24)
            tmp = (enc_byte + 24) & 0xFF
            # 2. Inverse XOR (XOR r) - only low 8 bits of r matter for the byte
            dec_byte = tmp ^ (r & 0xFF)

        data[i] = dec_byte

    with open(output_filename, "wb") as f:
        f.write(data)

    print(f"[+] Done! Output saved to {output_filename}")

if __name__ == "__main__":
    decrypt()