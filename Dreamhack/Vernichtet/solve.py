#!/usr/bin/env python3
"""
Vernich CTF Challenge Solver

This is a snake path puzzle with anti-disassembly obfuscation.
The binary has:
1. Size check: input file must be 225 bytes (0xe1)
2. First validation: table at 0x4020 has (col, row, expected) entries
3. Second validation: values 1-225 must form connected 8-way adjacent path

The solution uses backtracking to fill gaps in the path.
"""

def solve():
    # Read table from binary
    with open('main', 'rb') as f:
        f.seek(0x3020)  # Table at 0x4020 - 0x1000 (PIE offset)
        table_data = f.read(450)

    # Parse constraints from table
    exp_to_pos = {}
    pos_to_exp = {}
    for i in range(150):
        col = table_data[i*3]
        row = table_data[i*3 + 1]
        expected = table_data[i*3 + 2]
        if expected == 0:
            break
        pos = col + row * 15
        exp_to_pos[expected] = pos
        pos_to_exp[pos] = expected

    def get_neighbors(pos):
        """Get 8-way adjacent positions"""
        col = pos % 15
        row = pos // 15
        return [pos+dc+dr*15 for dc in [-1,0,1] for dr in [-1,0,1] 
                if (dc != 0 or dr != 0) and 0 <= col+dc < 15 and 0 <= row+dr < 15]

    # Find all gaps (missing values between defined ones)
    gaps = []
    sorted_vals = sorted(exp_to_pos.keys())
    for i in range(len(sorted_vals) - 1):
        v1, v2 = sorted_vals[i], sorted_vals[i+1]
        if v2 - v1 > 1:
            gaps.append((v1, v2, list(range(v1+1, v2))))

    print(f"Table has {len(pos_to_exp)} fixed values")
    print(f"Found {len(gaps)} gaps with {sum(len(g[2]) for g in gaps)} missing values")

    # Backtracking solver
    def solve_all_gaps(gap_idx, solution, filled):
        if gap_idx >= len(gaps):
            return True
        
        v1, v2, missing = gaps[gap_idx]
        p1 = exp_to_pos[v1]
        p2 = exp_to_pos[v2]
        
        def find_paths(current, end, steps_left, path):
            """Generator for all valid paths of exact length"""
            if steps_left == 1:
                if end in get_neighbors(current):
                    yield path
                return
            
            for npos in get_neighbors(current):
                if npos == end or npos in filled or npos in path:
                    continue
                yield from find_paths(npos, end, steps_left - 1, path + [npos])
        
        steps = len(missing) + 1
        for path in find_paths(p1, p2, steps, []):
            if len(path) != len(missing):
                continue
            
            # Try this path
            for i, p in enumerate(path):
                solution[p] = missing[i]
                filled.add(p)
            
            if solve_all_gaps(gap_idx + 1, solution, filled):
                return True
            
            # Backtrack
            for p in path:
                solution[p] = 0
                filled.remove(p)
        
        return False

    # Initialize with fixed values
    solution = [0] * 225
    filled = set()
    for pos, val in pos_to_exp.items():
        solution[pos] = val
        filled.add(pos)

    # Solve
    if solve_all_gaps(0, solution, filled):
        print("Solution found!")
        
        # Verify
        val_to_pos = {v: i for i, v in enumerate(solution)}
        errors = sum(1 for v in range(1, 225) 
                     if val_to_pos.get(v+1) not in get_neighbors(val_to_pos.get(v, -1)))
        print(f"Verification errors: {errors}")
        
        # Write solution
        with open('answer.bin', 'wb') as f:
            f.write(bytes(solution))
        print("Written answer.bin")
        print("\nRun: ./main answer.bin")
    else:
        print("No solution found!")

if __name__ == "__main__":
    solve()
