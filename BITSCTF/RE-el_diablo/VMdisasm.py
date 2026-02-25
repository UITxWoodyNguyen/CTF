from capstone import Cs, CS_ARCH_X86, CS_MODE_64

md = Cs(CS_ARCH_X86, CS_MODE_64)
with open("/tmp/diablo_dump/seg_7ffff7ff3000_7ffff7ff9000_r-xp.bin", "rb") as f:
    code = f.read()

CODE_BASE = 0x7ffff7ff3000

# Disassemble from main() at 0x7ffff7ff3fcf
offset = 0x7ffff7ff3fcf - CODE_BASE
for insn in md.disasm(code[offset:offset+512], 0x7ffff7ff3fcf):
    print(f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")