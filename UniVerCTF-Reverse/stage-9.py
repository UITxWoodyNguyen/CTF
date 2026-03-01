key = 0x2a
for s, e in islands:
    block = data[s:e+1]
    dec   = bytes(b ^ key for b in block)
    if all(32 <= c < 127 for c in dec):
        print(hex(s), "->", dec.decode())
# Output: 0xa1b2 -> "1n_v01D_"