import re

with open("bytecode.bin", "r") as file:
    bytecode = file.readlines()

opcodes = {
    0x00: ("nop", 0),
    0x01: ("halt", 0),
    0x10: ("dup", 0),
    0x11: ("pop", 0),
    0x12: ("add", 0),
    0x13: ("sub", 0),
    0x14: ("swap", 0),
    0x20: ("push_r", 0),
    0x21: ("pop_r", 0),
    0x30: ("jmp", 0),
    0x31: ("jz", 0),
    0x32: ("jnz", 0),
    0x33: ("jneg", 0),
    0x34: ("jle", 0),
    0x80: ("push_b", 1),
    0x81: ("push_w", 2),
    0xC0: ("getc", 0),
    0xC1: ("putc", 0),
}

def parse_byte(line):
    byte = re.search(r'\bdb\s+([0-9A-Fa-fh]+)', line).group(1)

    if byte.lower().endswith("h"):
        return int(byte[:-1], 16)

    return int(byte)

bytecodes = []

for line in bytecode:
    bytecodes.append(parse_byte(line))

cnt = 0
output = []
output.append("Address\tOpcode\tInstruction\t\tOperand")

while cnt < len(bytecodes):
    opcode = bytecodes[cnt]
    name, operand_size = opcodes.get(opcode)
    operand = ""
    operand_int = 0

    if operand_size == 1:
        operand_int = bytecodes[cnt + 1]
        operand = f"0x{operand_int:02X}"
    elif operand_size == 2:
        low = bytecodes[cnt + 1]
        high = bytecodes[cnt + 2]
        operand_int = low | (high << 8) # little endian
        operand = f"0x{operand_int:04X}"

    if 32 <= operand_int <= 126:
        operand = f"{operand}\t'{chr(operand_int)}'"
    elif operand_int == 0x0A:
        operand = f"{operand}\t'\\n'"

    output.append(f"0x{cnt:04X}\t0x{opcode:02X}\t{name}\t\t\t{operand}")

    cnt += 1 + operand_size

output = "\n".join(output)

with open("disassembled.asm", "w") as file:
    file.write(output)