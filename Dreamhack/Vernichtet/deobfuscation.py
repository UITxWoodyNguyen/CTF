#!/usr/bin/env python3
# deobfuscate.py - Patch anti-disassembly patterns

with open('main', 'rb') as f:
    data = bytearray(f.read())

# Pattern: eb ff c1 ff c9
# - eb ff    = jmp short $-1 (nhảy vào byte ff)
# - ff c1    = inc ecx
# - ff c9    = dec ecx
# Thực tế chỉ là NOP vì inc rồi dec lại
pattern = bytes([0xeb, 0xff, 0xc1, 0xff, 0xc9])
nops = bytes([0x90, 0x90, 0x90, 0x90, 0x90])

i = 0
count = 0
while i < len(data) - 4:
    if data[i:i+5] == pattern:
        data[i:i+5] = nops
        count += 1
        i += 5
    else:
        i += 1

print(f"Patched {count} patterns")

with open('main_deobf', 'wb') as f:
    f.write(data)

print("Written main_deobf")