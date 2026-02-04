import re
import json

# --- Part 1: Disassembler Logic (Unchanged) ---
# (Code is identical to your last version, so it's omitted for brevity)
# Opcodes mapping: {opcode: (mnemonic, operand_size_in_bytes)}
OPCODES = {
    0x00: ("nop", 0), 0x01: ("halt", 0), 0x10: ("dup", 0),
    0x11: ("pop", 0), 0x12: ("add", 0), 0x13: ("sub", 0),
    0x14: ("swap", 0), 0x20: ("push_r", 0), 0x21: ("pop_r", 0),
    0x30: ("jmp", 0), 0x31: ("jz", 0), 0x32: ("jnz", 0),
    0x33: ("jneg", 0), 0x34: ("jle", 0), 0x80: ("push_b", 1),
    0x81: ("push_w", 2), 0xC0: ("getc", 0), 0xC1: ("putc", 0),
}

def load_bytecode(filepath="output.log"):
    """Loads the raw bytecode from a binary file."""
    try:
        with open(filepath, "rb") as f:
            bytecode = list(f.read())
            print(bytecode)
            # --- ADDED SANITY CHECK ---
            expected_start = [0x81, 0x75, 0x00, 0x80, 0x0a]
            if bytecode[:5] != expected_start:
                print("="*60)
                print("FATAL ERROR: 'bytecode.bin' does not seem to be the correct raw binary file.")
                print(f"Expected starting bytes: {expected_start}")
                print(f"Actual starting bytes:   {bytecode[:5]}")
                print("Please re-dump the file from IDA as a raw binary.")
                print("="*60)
                exit(1)
            return bytecode
    except FileNotFoundError:
        print(f"Error: Bytecode file not found at '{filepath}'")
        print("Please dump the bytecode from IDA to a file named 'bytecode.bin'.")
        exit(1)

def disassemble_with_trace(bytecodes, trace):
    trace_map = {}
    for step in trace:
        addr = step['address']
        if addr not in trace_map:
            trace_map[addr] = []
        trace_map[addr].append(step)
    execution_counters = {addr: 0 for addr in trace_map}
    output_lines = []
    output_lines.append("Address\tOpcode\tInstruction\tOperand\t\t; ANNOTATION (Execution Trace)")
    output_lines.append("="*100)
    ip = 0
    while ip < len(bytecodes):
        opcode = bytecodes[ip]
        if opcode not in OPCODES:
            output_lines.append(f"; 0x{ip:04X}\t{opcode:02X}\tdb 0x{opcode:02X}")
            ip += 1
            continue
        name, operand_size = OPCODES[opcode]
        operand_str = ""
        operand_int = 0
        if operand_size == 1:
            operand_int = bytecodes[ip + 1]
            operand_str = f"0x{operand_int:02X}"
        elif operand_size == 2:
            low = bytecodes[ip + 1]
            high = bytecodes[ip + 2]
            operand_int = low | (high << 8)
            operand_str = f"0x{operand_int:04X}"
        if 32 <= operand_int <= 126:
            operand_str += f"\t'{chr(operand_int)}'"
        annotation = ""
        prefix = "; "
        if ip in trace_map:
            prefix = "  "
            exec_index = execution_counters[ip]
            if exec_index < len(trace_map[ip]):
                trace_entry = trace_map[ip][exec_index]
                pre_stack = trace_entry['pre_stack']
                post_stack = trace_entry['post_stack']
                if pre_stack != post_stack:
                    annotation = f"; Stack: {pre_stack} -> {post_stack}"
                else:
                    annotation = f"; Stack: {pre_stack} (no change)"
                if trace_entry['comment']:
                    annotation += f" | {trace_entry['comment']}"
                execution_counters[ip] += 1
        line = f"{prefix}0x{ip:04X}\t{opcode:02X}\t{name:<10}\t{operand_str:<12}\t{annotation}"
        output_lines.append(line)
        ip += 1 + operand_size
    output_content = "\n".join(output_lines)
    with open("annotated_disassembly.asm", "w") as f:
        f.write(output_content)
    print("Annotated disassembly saved to 'annotated_disassembly.asm'")

# --- Part 2: Instrumented VM Emulator (Final Robust Version) ---

class VMEmulator:
    def __init__(self, bytecode):
        self.bytecode = bytecode
        self.reset()

    def reset(self):
        self.data_stack = []
        self.return_stack = []
        self.ip = 0
        self.user_input = ""
        self.user_input_index = 0
        self.trace = []
        self.output = []
        self.halted = False

    def _log_step(self, pre_stack, comment=""):
        post_stack = self.data_stack.copy()
        opcode = self.bytecode[self.ip]
        self.trace.append({
            "address": self.ip,
            "opcode": opcode,
            "pre_stack": pre_stack,
            "post_stack": post_stack,
            "comment": comment
        })
    
    def _handle_error(self, message):
        print(f"\n[EMULATOR ERROR] at IP 0x{self.ip:04X}: {message}")
        self.halted = True

    def run(self, user_input_str):
        self.reset()
        self.user_input = user_input_str
        
        max_steps = 20000
        for _ in range(max_steps):
            if self.halted or self.ip >= len(self.bytecode):
                break

            pre_stack_snapshot = self.data_stack.copy()
            opcode = self.bytecode[self.ip]
            comment = ""
            original_ip = self.ip

            try:
                if opcode == 0x01:
                    comment = "HALT"
                    self.halted = True
                elif opcode == 0x10: # dup
                    if not self.data_stack: raise IndexError("dup on empty stack")
                    self.data_stack.append(self.data_stack[-1])
                    self.ip += 1
                elif opcode == 0x11: # pop
                    self.data_stack.pop()
                    self.ip += 1
                elif opcode == 0x12: # add
                    val2, val1 = self.data_stack.pop(), self.data_stack.pop()
                    self.data_stack.append(val1 + val2)
                    self.ip += 1
                elif opcode == 0x13: # sub
                    val2, val1 = self.data_stack.pop(), self.data_stack.pop()
                    self.data_stack.append(val1 - val2)
                    self.ip += 1
                elif opcode == 0x14: # swap
                    val2, val1 = self.data_stack.pop(), self.data_stack.pop()
                    self.data_stack.append(val2); self.data_stack.append(val1)
                    self.ip += 1
                elif opcode == 0x20: # push_r
                    self.return_stack.append(self.data_stack.pop())
                    self.ip += 1
                elif opcode == 0x21: # pop_r
                    if not self.return_stack: raise IndexError("pop_r on empty return stack")
                    self.data_stack.append(self.return_stack.pop())
                    self.ip += 1
                elif opcode == 0x30: # jmp
                    addr = self.data_stack.pop()
                    self.ip = addr
                elif opcode == 0x31: # jz
                    addr, val = self.data_stack.pop(), self.data_stack.pop()
                    if val == 0: self.ip = addr
                    else: self.ip += 1
                elif opcode == 0x32: # jnz
                    addr, val = self.data_stack.pop(), self.data_stack.pop()
                    if val != 0: self.ip = addr
                    else: self.ip += 1
                elif opcode == 0x33: # jneg
                    addr, val = self.data_stack.pop(), self.data_stack.pop()
                    if val < 0: self.ip = addr
                    else: self.ip += 1
                elif opcode == 0x34: # jle
                    addr, val = self.data_stack.pop(), self.data_stack.pop()
                    if val <= 0: self.ip = addr
                    else: self.ip += 1
                elif opcode == 0x80: # push_b
                    self.data_stack.append(self.bytecode[self.ip + 1])
                    self.ip += 2
                elif opcode == 0x81: # push_w
                    low, high = self.bytecode[self.ip + 1], self.bytecode[self.ip + 2]
                    self.data_stack.append(low | (high << 8))
                    self.ip += 3
                elif opcode == 0xC0: # getc
                    if self.user_input_index < len(self.user_input):
                        char_code = ord(self.user_input[self.user_input_index])
                        self.data_stack.append(char_code)
                        comment = f"Read '{self.user_input[self.user_input_index]}'"
                        self.user_input_index += 1
                    else:
                        self.data_stack.append(-1)
                        comment = "Read EOF"
                    self.ip += 1
                elif opcode == 0xC1: # putc
                    # The real VM pops a 16-bit word but only uses the low 8 bits for putc
                    val = self.data_stack.pop()
                    char_code = val & 0xFF 
                    char = chr(char_code)
                    self.output.append(char)
                    comment = f"Print '{repr(char)[1:-1]}'"
                    self.ip += 1
                else: # NOP or unknown
                    self.ip += 1
            except IndexError:
                op_name = OPCODES.get(opcode, ("unknown", 0))[0]
                self._handle_error(f"Opcode 0x{opcode:02X} ({op_name}) failed. Not enough items on stack.")

            self._log_step(pre_stack_snapshot, comment)
            if self.halted: break

        print("\n--- VM Execution Summary ---")
        print(f"Input provided: '{user_input_str}'")
        print(f"Execution stopped at address 0x{original_ip:04X}")
        print(f"Final data stack: {self.data_stack}")
        print(f"Program output:\n{''.join(self.output)}")
        print("--------------------------\n")

        return self.trace

# --- Part 3: Main Execution Block (Unchanged) ---
if __name__ == "__main__":
    bytecodes = load_bytecode("bytecode.bin")
    print(f"Successfully loaded {len(bytecodes)} bytes of bytecode.")
    user_input = input("Enter the sequence of moves to trace (e.g., rdrd): ")
    emulator = VMEmulator(bytecodes)
    execution_trace = emulator.run(user_input)
    print(f"Emulator finished. Generated a trace with {len(execution_trace)} steps.")
    disassemble_with_trace(bytecodes, execution_trace)