import json

class VMDisassembler:
    """Disassembler for the Matrix VM bytecode"""
    
    # Opcode definitions based on sub_1350.c
    OPCODES = {
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
    
    def __init__(self, bytecode_path):
        """Initialize disassembler with bytecode file"""
        with open(bytecode_path, 'r') as f:
            self.bytecode_lines = f.readlines()
        
        self.bytecode = []
        self.instructions = []
        self.pc = 0
        
        self._parse_bytecode()
    
    def _parse_bytecode(self):
        """Parse bytecode from hex format"""
        for line in self.bytecode_lines:
            line = line.strip()
            if not line:
                continue
            # Remove 0x prefix if present
            if line.startswith('0x'):
                line = line[2:]
            # Convert hex to int
            self.bytecode.append(int(line, 16))
    
    def _get_opcode_name(self, opcode):
        """Get opcode name and operand size"""
        if opcode in self.OPCODES:
            return self.OPCODES[opcode]
        return ("UNKNOWN", 0)
    
    def disassemble(self):
        """Disassemble the entire bytecode"""
        self.pc = 0
        
        while self.pc < len(self.bytecode):
            opcode = self.bytecode[self.pc]
            addr = self.pc
            opcode_name, operand_size = self._get_opcode_name(opcode)
            
            operand = None
            operand_str = ""
            
            if operand_size == 1:
                # 1-byte operand
                if self.pc + 1 < len(self.bytecode):
                    operand = self.bytecode[self.pc + 1]
                    operand_str = f"0x{operand:02X}"
                    self.pc += 2
                else:
                    self.pc += 1
            elif operand_size == 2:
                # 2-byte operand (little-endian)
                if self.pc + 2 < len(self.bytecode):
                    low = self.bytecode[self.pc + 1]
                    high = self.bytecode[self.pc + 2]
                    operand = low | (high << 8)
                    operand_str = f"0x{operand:04X}"
                    self.pc += 3
                else:
                    self.pc += 1
            else:
                self.pc += 1
            
            # Special handling for PUSH_BYTE/PUSH_WORD with ASCII characters
            display_operand = operand_str
            if operand is not None and opcode_name in ["push_b", "push_w"]:
                if 32 <= operand <= 126:  # Printable ASCII
                    display_operand = f"0x{operand:02X} '{chr(operand)}'"
                elif operand == 0x0A:
                    display_operand = f"0x{operand:02X} '\\n'"
                elif operand == 0x00:
                    display_operand = f"0x{operand:02X} (null)"
            
            self.instructions.append({
                'addr': addr,
                'opcode': opcode,
                'name': opcode_name,
                'operand': operand,
                'operand_str': display_operand
            })
        
        return self.instructions
    
    def print_disassembly(self, output_file=None):
        """Print disassembly in readable format"""
        output_lines = []
        
        output_lines.append("=" * 80)
        output_lines.append("MATRIX VM BYTECODE DISASSEMBLY")
        output_lines.append("=" * 80)
        output_lines.append(f"{'Address':<10} {'Opcode':<8} {'Instruction':<20} {'Operand':<20}")
        output_lines.append("-" * 80)
        
        for instr in self.instructions:
            addr_str = f"0x{instr['addr']:04X}:{instr['addr']:<6}"
            opcode_str = f"0x{instr['opcode']:02X}"
            name_str = instr['name']
            operand_str = instr['operand_str']
            
            line = f"{addr_str:<10} {opcode_str:<8} {name_str:<20} {operand_str:<20}"
            output_lines.append(line)
        
        output_lines.append("-" * 80)
        output_lines.append(f"Total instructions: {len(self.instructions)}")
        output_lines.append(f"Total bytes: {len(self.bytecode)}")
        output_lines.append("=" * 80)
        
        # Print to console
        for line in output_lines:
            print(line)
        
        # Save to file if specified
        if output_file:
            with open(output_file, 'w') as f:
                f.write("\n".join(output_lines))
            print(f"\nDisassembly saved to: {output_file}")
    
    def find_jump_targets(self):
        """Find all jump targets for analysis"""
        jump_targets = set()
        
        for instr in self.instructions:
            if instr['name'] in ['jmp', 'jz', 'jnz', 'jneg', 'jle']:
                # These instructions pop a target address from stack
                pass  # Would need stack simulation to determine actual targets
        
        return jump_targets
    
    def get_string_constants(self):
        """Extract string constants from push_b instructions"""
        strings = []
        current_string = []
        current_addr = 0
        
        for instr in self.instructions:
            if instr['name'] == 'push_b' and instr['operand'] is not None:
                char_code = instr['operand']
                if 32 <= char_code <= 126 or char_code in [0x0A, 0x09]:
                    if not current_string:
                        current_addr = instr['addr']
                    current_string.append(chr(char_code))
                else:
                    if current_string:
                        strings.append({
                            'addr': current_addr,
                            'value': ''.join(current_string)
                        })
                        current_string = []
        
        if current_string:
            strings.append({
                'addr': current_addr,
                'value': ''.join(current_string)
            })
        
        return strings
    
    def analyze(self):
        """Print analysis of bytecode"""
        print("\n" + "=" * 80)
        print("BYTECODE ANALYSIS")
        print("=" * 80)
        
        # String constants
        strings = self.get_string_constants()
        print(f"\nString Constants Found: {len(strings)}")
        for s in strings:
            print(f"  0x{s['addr']:04X}: {repr(s['value'])}")
        
        # Opcode frequency
        opcode_freq = {}
        for instr in self.instructions:
            name = instr['name']
            opcode_freq[name] = opcode_freq.get(name, 0) + 1
        
        print(f"\nOpcode Frequency:")
        for name, count in sorted(opcode_freq.items(), key=lambda x: x[1], reverse=True):
            print(f"  {name:<20}: {count:4d}")
        
        # Jump instructions
        jump_instrs = [i for i in self.instructions if i['name'] in ['jmp', 'jz', 'jnz', 'jneg', 'jle']]
        print(f"\nJump Instructions: {len(jump_instrs)}")
        for instr in jump_instrs[:10]:  # Show first 10
            print(f"  0x{instr['addr']:04X}: {instr['name']}")
        
        print("=" * 80)


if __name__ == "__main__":
    bytecode_file = r"c:\Users\ANH VU~\Downloads\matrix\output.log"
    output_file = r"c:\Users\ANH VU~\Downloads\matrix\disassembled.asm"
    
    try:
        disassembler = VMDisassembler(bytecode_file)
        disassembler.disassemble()
        disassembler.print_disassembly(output_file)
        disassembler.analyze()
        
    except FileNotFoundError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()