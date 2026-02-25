BINARY = "./challenge"

def get_output(key_bytes: bytes) -> bytes:
    """Run with hex-encoded key, return flag bytes after sentinel."""
    hex_str = key_bytes.hex()
    with open("/tmp/crack_lic.txt", "w") as f:
        f.write(f"LICENSE-{hex_str}\n")
    env = os.environ.copy()
    env["PRINT_FLAG_CHAR"] = "1"
    r = subprocess.run([BINARY, "/tmp/crack_lic.txt"],
                       capture_output=True, timeout=10, env=env)
    marker = b"The flag lies here somewhere...\n"
    idx = r.stdout.find(marker)
    if idx >= 0:
        return r.stdout[idx + len(marker):].rstrip()
    return b""

# Baseline: all-zero key → raw encrypted bytes
enc = get_output(bytes(10))

# Test key: "ABCDEFGHIJ" (0x41..0x4A)
test_key = bytes([0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A])
out_test = get_output(test_key)

all_match = True
for i in range(len(enc)):
    expected = enc[i] ^ test_key[i % 10]
    actual   = out_test[i]
    if expected != actual:
        all_match = False
        print(f"  MISMATCH pos {i}")

if all_match:
    print("  ✓ XOR confirmed at ALL 46 positions!")