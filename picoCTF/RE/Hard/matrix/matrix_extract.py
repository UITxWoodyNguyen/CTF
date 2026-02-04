import re

with open("disassembled.asm", "r") as file:
    disassembled = file.readlines()

map_width = 16
map_height = 16
map_base_address = 0x0174
map_jump_entry_size = 4

wall = 0x00FB
exit = 0x0585
trap = 0x0574
health = 0x057F

start_x, start_y = 1, 1

# get the instructions

instructions = {}
line_regex = re.compile(r"^(0x[0-9a-fA-F]+)\s+0x[0-9a-fA-F]+\s+([a-z_]+)\s*(.*)$")

for line in disassembled:
    match = line_regex.match(line)
    if match:
        address_string, instruction, operand = match.groups()
        address = int(address_string, 16)

        operand_match = re.search(r"0x[0-9a-fA-F]+", operand)
        operand = int(operand_match.group(0), 16) if operand_match else None

        instructions[address] = (instruction, operand)

# get the map

map = [[' ' for _ in range(map_width)] for _ in range(map_height)]
for y in range(map_height):
    for x in range(map_width):
        address = map_base_address + (y * map_width + x) * map_jump_entry_size
        instruction, operand = instructions[address]

        if instruction == 'push_w' and operand:
            if operand == wall:
                map[y][x] = '#'
            elif operand == exit:
                map[y][x] = 'E'
            elif operand == health:
                map[y][x] = '+'
            elif operand == trap:
                map[y][x] = '-'
        elif instruction == 'jmp': # nop instruction does nothing, thats why it jumps to it :D
            map[y][x] = '.'

map[start_x][start_y] = 'S'

# print the map

for row in map:
    print("".join(row))