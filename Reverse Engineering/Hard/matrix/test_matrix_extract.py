import re

with open("disassembled.asm", "r") as file:
    disassembled = file.read()

# Constants derived from bytecode analysis
MAZE_WIDTH = 16
MAZE_HEIGHT = 16
MAZE_START_ADDR = 0x0174
CELL_SIZE_BYTES = 4 # Each maze cell is represented by 4 bytes of code

# Addresses for specific game logic jumps
WALL_JUMP_ADDR = 0x00FB
EXIT_JUMP_ADDR = 0x0585
FORCE_UP_JUMP_ADDR = 0x0574
FORCE_DOWN_JUMP_ADDR = 0x057F

# Player's starting coordinates
START_X, START_Y = 1, 1

def parse_disassembly(data):
    """
    Parses the disassembly text into a dictionary mapping addresses to instructions.
    
    Returns:
        A dict where keys are integer memory addresses and values are tuples
        of (instruction_name, operand_string).
    """
    instructions = {}
    
    # --- MODIFICATION START ---
    # The original regex was:
    # r"^(0x[0-9a-fA-F]+):\d+\s+0x[0-9a-fA-F]+\s+([A-Z_]+)\s*(.*)$"
    # This was changed to:
    # 1. Remove `:\d+` which looked for a colon and numbers after the address.
    # 2. Change `[A-Z_]+` to `[a-z_]+` to match lowercase instruction names.
    line_regex = re.compile(r"^(0x[0-9a-fA-F]+)\s+0x[0-9a-fA-F]+\s+([a-z_]+)\s*(.*)$")
    # --- MODIFICATION END ---
    
    for line in data.strip().split('\n'):
        match = line_regex.match(line)
        if match:
            addr_str, instruction, operand = match.groups()
            addr = int(addr_str, 16)
            # Clean up the operand to get just the hex value if it exists
            op_match = re.search(r"0x[0-9a-fA-F]+", operand)
            operand_val = op_match.group(0) if op_match else None
            instructions[addr] = (instruction, operand_val)
            
    return instructions

def extract_maze(instructions):
    """
    Reconstructs the maze by interpreting the bytecode patterns.
    """
    # Initialize an empty maze grid
    maze = [[' ' for _ in range(MAZE_WIDTH)] for _ in range(MAZE_HEIGHT)]

    for y in range(MAZE_HEIGHT):
        for x in range(MAZE_WIDTH):
            # Calculate the memory address for the current (x, y) cell
            addr = MAZE_START_ADDR + (y * MAZE_WIDTH + x) * CELL_SIZE_BYTES

            if addr not in instructions:
                maze[y][x] = '?' # Mark unknown areas
                continue

            instruction, operand = instructions[addr]
            
            # The game logic uses the instruction at the start of each 4-byte
            # cell to determine the cell type.
            if instruction == 'push_w' and operand:
                operand_addr = int(operand, 16)
                if operand_addr == WALL_JUMP_ADDR:
                    maze[y][x] = '#' # Wall
                elif operand_addr == EXIT_JUMP_ADDR:
                    maze[y][x] = 'E' # Exit
                elif operand_addr == FORCE_UP_JUMP_ADDR:
                    maze[y][x] = '-' # Forced move Up
                elif operand_addr == FORCE_DOWN_JUMP_ADDR:
                    maze[y][x] = '+' # Forced move Down
                else:
                    maze[y][x] = '?' # Unknown PUSH_WORD jump
            elif instruction == 'jmp':
                maze[y][x] = '.' # Open Path
            else:
                maze[y][x] = '?' # Unknown instruction at cell start

    # Manually place the player's starting position
    if 0 <= START_Y < MAZE_HEIGHT and 0 <= START_X < MAZE_WIDTH:
        maze[START_Y][START_X] = 'S'

    return maze

def print_maze(maze):
    """
    Prints the maze grid to the console.
    """
    print("=" * (MAZE_WIDTH + 2))
    print(" Extracted 16x16 Maze ")
    print("=" * (MAZE_WIDTH + 2))
    for row in maze:
        print("".join(row))
    print("-" * (MAZE_WIDTH + 2))
    print("S: Start | E: Exit | #: Wall | .: Path")
    print("+: Force Down | -: Force Up") # Corrected legend based on addresses
    print("-" * (MAZE_WIDTH + 2))

if __name__ == "__main__":
    print("Parsing MATRIX VM disassembly...")
    parsed_code = parse_disassembly(disassembled)
    
    print("Extracting maze from code-as-data section...")
    the_maze = extract_maze(parsed_code)
    
    print("\nExtraction complete. Here is the map:\n")
    print_maze(the_maze)