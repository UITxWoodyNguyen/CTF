# Your input (local_58 extracted earlier)
data = b'\xe1\xa7\x1e\xf8u#{a\xb9\x9d\xfcZ[\xdfi\xd2\xfe\x1b\xed\xf4\xedg\xf4'

# 1. Build full bitstring (use all bytes)
bitstream = "".join(format(b, "08b") for b in data)

# 2. We only need first 27 * 7 = 189 bits
needed_bits = bitstream[:27 * 7]

# 3. Split into 27 chunks of 7 bits
chunks = [needed_bits[i:i+7] for i in range(0, len(needed_bits), 7)]

# 4. Convert each 7-bit value to ASCII
password = "".join(chr(int(chunk, 2)) for chunk in chunks)

print("27 chunks of 7 bits:")
for i, c in enumerate(chunks):
    print(i, c, "->", chr(int(c, 2)))

print("\nReconstructed 27-byte password:")
print(password)
