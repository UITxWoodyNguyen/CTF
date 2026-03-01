stage9_text = b'1n_v01D_'
key10 = sum(stage9_text) % 256     # = 0x?? (computed at runtime)

for s, e in islands:
    if s == 0xa1b2:                 # skip the Stage 9 island
        continue
    block = data[s:e+1]
    dec   = bytes(b ^ key10 for b in block)
    if all(32 <= c < 127 for c in dec):
        print(hex(s), "->", dec.decode())
# Output: 0xe3c4 -> "iN_ZEN}"