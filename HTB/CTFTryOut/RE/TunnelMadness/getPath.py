from pwn import *
from collections import deque

# Maze config
MAZE_VA = 0x20E0
CELL_SIZE = 16
SIZE = 20  # 20x20x20 maze

def get_cell_offset(z, y, x):
    """offset = (z*400 + y*20 + x) * 16"""
    return (z * 400 + y * 20 + x) * 16

def get_cell_data(data, base, z, y, x):
    offset = base + get_cell_offset(z, y, x)
    if offset + 16 > len(data):
        return None
    cell = data[offset:offset+16]
    return {
        'field_0': u32(cell[0:4]),
        'field_4': u32(cell[4:8]),
        'field_8': u32(cell[8:12]),
        'type': u32(cell[12:16])
    }

def can_move(data, base, z, y, x):
    """Kiểm tra có thể di chuyển đến cell không"""
    if not (0 <= z < SIZE and 0 <= y < SIZE and 0 <= x < SIZE):
        return False
    cell = get_cell_data(data, base, z, y, x)
    if cell is None:
        return False
    # type == 2 là wall, không đi được
    return cell['type'] != 2

def main():
    binary_path = './tunnel'
    
    print("[*] Loading binary...")
    elf = ELF(binary_path, checksec=False)
    
    with open(binary_path, 'rb') as f:
        raw = f.read()
    
    # Tìm file offset của maze
    base_offset = None
    for section in elf.sections:
        sec_start = section.header.sh_addr
        sec_end = sec_start + section.header.sh_size
        if sec_start <= MAZE_VA < sec_end:
            base_offset = section.header.sh_offset + (MAZE_VA - sec_start)
            print(f"[+] Section: {section.name}")
            print(f"[+] Maze file offset: {hex(base_offset)}")
            break
    
    if base_offset is None:
        base_offset = MAZE_VA
        print(f"[*] Using VA as offset: {hex(base_offset)}")
    
    # Tìm goal (type = 3)
    print("\n[*] Searching for GOAL (type=3)...")
    goal = None
    
    for z in range(SIZE):
        for y in range(SIZE):
            for x in range(SIZE):
                cell = get_cell_data(raw, base_offset, z, y, x)
                if cell and cell['type'] == 3:
                    goal = (z, y, x)
                    print(f"[+] GOAL at: z={z}, y={y}, x={x}")
                    print(f"    Cell data: {cell}")
                    break
            if goal:
                break
        if goal:
            break
    
    if not goal:
        print("[!] Goal not found!")
        return None
    
    # Start cell
    print("\n[*] Start cell (0,0,0):")
    start_cell = get_cell_data(raw, base_offset, 0, 0, 0)
    print(f"    {start_cell}")
    
    # BFS
    directions = [
        (0, -1, 0, 'B'),   # Back:    y-1
        (0, 1, 0, 'F'),    # Forward: y+1
        (-1, 0, 0, 'L'),   # Left:    z-1
        (1, 0, 0, 'R'),    # Right:   z+1
        (0, 0, -1, 'D'),   # Down:    x-1
        (0, 0, 1, 'U'),    # Up:      x+1
    ]
    
    print("\n[*] Finding path with BFS...")
    
    start = (0, 0, 0)
    queue = deque([(start, "")])
    visited = {start}
    
    while queue:
        (z, y, x), path = queue.popleft()
        
        if (z, y, x) == goal:
            print(f"\n[+] PATH FOUND! ({len(path)} moves)")
            print(f"    {path}")
            
            # Auto save to path.txt
            with open('path.txt', 'w') as f:
                f.write(path)
            print(f"\n[+] Path saved to 'path.txt'")
            
            return path
        
        for dz, dy, dx, cmd in directions:
            nz, ny, nx = z + dz, y + dy, x + dx
            
            if (nz, ny, nx) in visited:
                continue
            
            if can_move(raw, base_offset, nz, ny, nx):
                visited.add((nz, ny, nx))
                queue.append(((nz, ny, nx), path + cmd))
    
    print("[!] No path found!")
    return None

if __name__ == "__main__":
    main()
