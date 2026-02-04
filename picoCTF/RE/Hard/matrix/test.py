from test_emulator import VMEmulator
import sys

COMMANDS_FILE = r"c:\Users\ANH VU~\Downloads\matrix\matrix_commands.json"

MAZE_WIDTH = 16
MAZE_HEIGHT = 16
WALL_COMMAND_ADDRESS = 251  # 0xFB in hex
POSITION_CHECK_ADDRESS = 204 # 0xCC in hex

def probe_coordinate(x, y):
    """
    Tests a single (x, y) coordinate to see if it's a wall.
    Returns True if it's a wall, False otherwise.
    """
    try:
        emulator = VMEmulator(COMMANDS_FILE)

        # --- Corrected state setup ---
        # We need to place the coordinates onto the LOCAL STACK (rbx0x18)
        # as the VM would expect them to be there.
        # The VM's typical flow for a move likely involves:
        # 1. Loading coordinates from rbx0x18 onto rbx0x10
        # 2. Performing calculations.

        # We are going to simulate the state *before* the first move handler executes.
        # The player's position is established on the local stack.
        
        # Clear the local stack and re-initialize it with our test coordinates.
        # This is a more forceful way to set the state.
        emulator.rbx0x18 = [y, x, 0] # Y first, then X, then maybe a placeholder 0.
        emulator.rbx0x18_location = 2 # We've put 2 items (y, x) on the local stack.
        
        # The player's current position might also be on the main stack
        # at specific locations used by the move logic.
        # From the disassembly:
        # 0x00A0: PUSH_LOCAL (takes from rbx0x18 to rbx0x10)
        # 0x00A1: PUSH_LOCAL (takes from rbx0x18 to rbx0x10)
        # The rbx0x10_location seems to be managed by PUSH_LOCAL/POP_LOCAL.
        # When POSITION_CHECK_ADDRESS (0xCC) is called, it expects
        # the CURRENT player position to be available somewhere.
        # The disassembly shows that after loading from local stack, it's used in calculation.
        # Let's make sure the main stack has space initialized.
        emulator.rbx0x10_location = 4 # Reset main stack pointer if needed.
        # The critical values used in calculation might be at rbx0x10[0] and rbx0x10[1]
        # if they are pushed there by PUSH_LOCAL.

        # We set the program counter to the START of the move processing logic.
        emulator.current_command = POSITION_CHECK_ADDRESS # 0xCC

        # Run the VM for a limited number of steps.
        # The key is to detect if it ever hits the WALL_COMMAND_ADDRESS.
        for _ in range(50): # 50 steps should be ample
            if emulator.current_command == WALL_COMMAND_ADDRESS:
                return True # We hit a wall.
            
            if not emulator.execute():
                # If execute returns False, it means program halted or encountered an issue.
                # This might also indicate a "path" if it doesn't hit the wall command.
                break
        
        return False # No wall detected in 50 steps.

    except FileNotFoundError as e:
        print(f"\nError: Commands file not found - {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\nError during probe ({x}, {y}): {e}")
        # Consider what to do on error. If an error implies a wall, return True.
        # For now, let's assume errors mean it's not a valid path.
        return True


if __name__ == "__main__":
    print("Starting maze analysis by probing each coordinate...")
    
    maze_map = [[' ' for _ in range(MAZE_WIDTH)] for _ in range(MAZE_HEIGHT)]

    for y in range(MAZE_HEIGHT):
        for x in range(MAZE_WIDTH):
            sys.stdout.write(f"\rProbing coordinate ({x:2d}, {y:2d})...")
            sys.stdout.flush()

            if probe_coordinate(x, y):
                maze_map[y][x] = '#'
            else:
                maze_map[y][x] = '.'
    
    print("\n\nAnalysis complete. Reconstructed Maze:\n")
    
    for row in maze_map:
        print("".join(row))