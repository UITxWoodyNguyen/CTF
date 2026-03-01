import json, base64

results = []
with open("uvt_crackme_work/stage2/logs/system.log") as f:
    for line in f:
        entry = json.loads(line.strip())
        k     = entry["k"]                        # one-byte key
        frag  = bytes.fromhex(entry["fragx"])     # raw fragment bytes
        dec   = bytes(b ^ k for b in frag)        # XOR each byte with k
        results.append(dec)

combined = b"".join(results)
# Add padding if needed and base64-decode
padding = (4 - len(combined) % 4) % 4
decoded = base64.b64decode(combined + b"=" * padding)
print(decoded.decode())    # => "I_h1D3_in_l0Gz_"