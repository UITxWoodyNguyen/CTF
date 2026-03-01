import json

with open("uvt_crackme_work/stage2/starfield_pings/pings.txt") as f:
    data = json.load(f)

even_map = bytes.fromhex(data["even"])   # even-indexed encoded bytes
odd_map  = bytes.fromhex(data["odd"])    # odd-indexed encoded bytes (reversed)

# Undo: reverse odd_map, then XOR each byte back
odd_decoded  = bytes(b ^ 0x13 for b in reversed(odd_map))
even_decoded = bytes(b ^ 0x52 for b in even_map)

# Interleave: even[0], odd[0], even[1], odd[1], ...
fragment = []
for a, b in zip(even_decoded, odd_decoded):
    fragment.append(a)
    fragment.append(b)
print(bytes(fragment).decode())   # => "uR_pR0b3Z_xTND-"