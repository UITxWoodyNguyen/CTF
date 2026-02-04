import re

with open("bytecode.bin", "r") as file:
    bytecode = file.readlines()

def parse_byte(line):
    byte = re.search(r'\bdb\s+([0-9A-Fa-fh]+)', line).group(1)

    if byte.lower().endswith("h"):
        return hex(int(byte[:-1], 16))

    return hex(int(byte))

for line in bytecode:
    byte = parse_byte(line)
    print(byte)