import collections

# The maze for this problem.
maze_string = """
################
#S....+#.#+..#.#
####-###.###.#.#
#..........#.#.#
##.#.#####.#.-.#
#..#.#+..#.#.#.#
#.##.###.#.#.#.#
#.#......#.#.#.#
#.#.######.#.#.#
#.#........#.#.#
#.###.######.#.#
#...#..-..#..#.#
#.###..#..#.#..#
#.#...###.#.#-##
#.#....#..-.#..#
##############E#
"""

def solve_maze_with_health(maze_str):
    """
    Solves the maze using BFS, where state is determined by position and health.
    Returns the optimal path as a list of coordinates, or None if no solution exists.
    """
    grid = [list(row) for row in maze_str.strip().split('\n')]
    height = len(grid)
    width = len(grid[0])

    # --- 1. Find the start and end positions ---
    start_pos, end_pos = None, None
    for r in range(height):
        for c in range(width):
            if grid[r][c] == 'S':
                start_pos = (r, c)
            elif grid[r][c] == 'E':
                end_pos = (r, c)
    
    # --- 2. Initialize the BFS ---
    # Starting health is 0
    initial_health = 0
    
    # State in the queue: (position, path_taken, current_health)
    queue = collections.deque([(start_pos, [start_pos], initial_health)])

    # Visited state optimization: store the max health achieved at each position.
    # visited[position] = max_health
    visited = {start_pos: initial_health}

    # --- 3. Run the BFS loop ---
    while queue:
        (r, c), path, health = queue.popleft()

        # --- Goal Condition ---
        if (r, c) == end_pos:
            return path

        # --- Explore Neighbors ---
        for dr, dc in [(-1, 0), (1, 0), (0, -1), (0, 1)]: # Up, Down, Left, Right
            nr, nc = r + dr, c + dc

            if not (0 <= nr < height and 0 <= nc < width):
                continue
            
            neighbor_char = grid[nr][nc]
            
            if neighbor_char == '#':
                continue

            # --- Calculate the new health for the neighbor state ---
            new_health = health
            if neighbor_char == '+':
                new_health += 1
            elif neighbor_char == '-':
                new_health -= 1

            # Rule: Health cannot drop below zero. This is an invalid move.
            if new_health < 0:
                continue
            
            new_pos = (nr, nc)
            
            # Optimization: If we've been here before with more or equal health,
            # this new path is not better. Prune it.
            if new_pos in visited and visited[new_pos] >= new_health:
                continue

            # This is a new best path to this position.
            # Record it and add it to the queue for exploration.
            visited[new_pos] = new_health
            new_path = path + [new_pos]
            queue.append((new_pos, new_path, new_health))
    
    return None # No solution found

def path_to_moves_string(path):
    """
    Converts a list of coordinates (the path) into a string of moves.
    """
    if not path or len(path) < 2:
        return ""
    
    moves = []
    move_map = {
        (-1, 0): 'u', (1, 0): 'd', (0, -1): 'l', (0, 1): 'r'
    }

    for i in range(1, len(path)):
        prev_r, prev_c = path[i-1]
        curr_r, curr_c = path[i]
        dr, dc = curr_r - prev_r, curr_c - prev_c
        moves.append(move_map.get((dr, dc), '?'))

    return "".join(moves)

if __name__ == "__main__":
    solution_path = solve_maze_with_health(maze_string)
    
    if solution_path:
        move_string = path_to_moves_string(solution_path)
        print(f"Solution found! Path length: {len(move_string)} steps.")
        print("\nMoves:")
        print(move_string)
    else:
        print("Could not find a valid path to the exit.")