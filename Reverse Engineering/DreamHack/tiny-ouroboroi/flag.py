def invert_bits(bits):
    return [0 if b else 1 for b in bits]

def rotate_bits(bits, n):
    n = n % 8
    return bits[n:] + bits[:n]

def bits_to_byte(bits):
    val = 0
    for b in bits:
        val = (val << 1) | b
    return val

def byte_to_bits(c):
    return [(c >> (7 - i)) & 1 for i in range(8)]

def encode_char(ch, idx):
    bits = byte_to_bits(ch)
    bits = rotate_bits(bits, idx)
    if idx % 2 == 1:
        bits = invert_bits(bits)
    return bits_to_byte(bits)

with open("output.bin", "rb") as f:
    data = f.read()
    recovered = ""
    for idx, out_byte in enumerate(data):
        found = False
        for c in range(32, 127):  # printable ASCII
            if encode_char(c, idx) == out_byte:
                recovered += chr(c)
                found = True
                break
        if not found:
            recovered += '?'
    print("Recovered input:", recovered)
