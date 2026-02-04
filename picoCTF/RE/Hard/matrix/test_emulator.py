import json
import sys

class VMEmulator:
    def __init__(self, commands_json_path):
        """Initialize the VM with commands from JSON"""
        # Load the commands from the matrix_commands.json file
        with open(commands_json_path, "r") as f:
            commands_json = json.load(f)
        
        # Convert the addresses in hexadecimals from the json file to integers
        self.commands = {}
        for key, value in commands_json.items():
            int_key = int(key, 16)
            self.commands[int_key] = value
        
        # Base command address
        self.base_command = int("0x1020f0", 16)
        
        # The stack at `param_1[2]`
        self.rbx0x10 = [
            int('01', 16),
            int('01', 16),
            int('00', 16),
            int('72', 16)
        ]
        self.rbx0x10.extend([0 for _ in range(10020)])
        self.rbx0x10_location = 4
        
        # The stack at `param_1[3]`
        self.rbx0x18 = [
            int('00', 16),
            int('00', 16),
            int('00', 16),
        ]
        self.rbx0x18.extend([0 for _ in range(10020)])
        self.rbx0x18_location = 0
        
        # The current command
        self.current_command = 124
        
        # User input
        self.user_input = ""
        self.user_input_index = 0
    
    def command0x10(self):
        """DUP - Duplicate"""
        self.rbx0x10[self.rbx0x10_location] = self.rbx0x10[self.rbx0x10_location - 1]
        self.rbx0x10_location += 1
        self.current_command += 1
    
    def command0x11(self):
        """POP - Pop stack"""
        self.rbx0x10_location -= 1
        self.current_command += 1
    
    def command0x12(self):
        """ADD - Add top two values"""
        minus4 = self.rbx0x10[self.rbx0x10_location - 2]
        minus2 = self.rbx0x10[self.rbx0x10_location - 1]
        self.rbx0x10[self.rbx0x10_location - 2] = minus4 + minus2
        self.rbx0x10_location -= 1
        self.current_command += 1
    
    def command0x13(self):
        """SUB - Subtract top two values"""
        minus4 = self.rbx0x10[self.rbx0x10_location - 2]
        minus2 = self.rbx0x10[self.rbx0x10_location - 1]
        self.rbx0x10[self.rbx0x10_location - 2] = minus4 - minus2
        self.rbx0x10_location -= 1
        self.current_command += 1
    
    def command0x14(self):
        """SWAP - Swap top two values"""
        temp = self.rbx0x10[self.rbx0x10_location - 2]
        self.rbx0x10[self.rbx0x10_location - 2] = self.rbx0x10[self.rbx0x10_location - 1]
        self.rbx0x10[self.rbx0x10_location - 1] = temp
        self.current_command += 1
    
    def command0x20(self):
        """PUSH_LOCAL - Push from main stack to local stack"""
        self.rbx0x18[self.rbx0x18_location] = self.rbx0x10[self.rbx0x10_location - 1]
        self.rbx0x10_location -= 1
        self.rbx0x18_location += 1
        self.current_command += 1
    
    def command0x21(self):
        """POP_LOCAL - Pop from local stack to main stack"""
        self.rbx0x10[self.rbx0x10_location] = self.rbx0x18[self.rbx0x18_location - 1]
        self.rbx0x10_location += 1
        self.rbx0x18_location -= 1
        self.current_command += 1
    
    def command0x30(self):
        """LOAD_PC - Jump to address"""
        self.current_command = self.rbx0x10[self.rbx0x10_location - 1]
        self.rbx0x10_location -= 1
    
    def command0x31(self):
        """JZ - Jump if zero"""
        if self.rbx0x10[self.rbx0x10_location - 2] == 0:
            self.current_command = self.rbx0x10[self.rbx0x10_location - 1]
        else:
            self.current_command += 1
        self.rbx0x10_location -= 2
    
    def command0x32(self):
        """JNZ - Jump if not zero"""
        if self.rbx0x10[self.rbx0x10_location - 2] != 0:
            self.current_command = self.rbx0x10[self.rbx0x10_location - 1]
        else:
            self.current_command += 1
        self.rbx0x10_location -= 2
    
    def command0x33(self):
        """JL - Jump if less than"""
        if self.rbx0x10[self.rbx0x10_location - 2] < 0:
            self.current_command = self.rbx0x10[self.rbx0x10_location - 1]
        else:
            self.current_command += 1
        self.rbx0x10_location -= 2
    
    def command0x34(self):
        """JLE - Jump if less or equal"""
        if self.rbx0x10[self.rbx0x10_location - 2] < 1:
            self.current_command = self.rbx0x10[self.rbx0x10_location - 1]
        else:
            self.current_command += 1
        self.rbx0x10_location -= 2
    
    def command0x80(self):
        """PUSH_BYTE - Push 1-byte constant"""
        self.rbx0x10[self.rbx0x10_location] = int(
            self.commands[self.base_command + self.current_command + 1], 16
        )
        self.rbx0x10_location += 1
        self.current_command += 2
    
    def command0x81(self):
        """PUSH_WORD - Push 2-byte constant"""
        next_command = (
            self.commands[self.base_command + self.current_command + 2] +
            self.commands[self.base_command + self.current_command + 1]
        )
        self.rbx0x10[self.rbx0x10_location] = int(next_command, 16)
        self.rbx0x10_location += 1
        self.current_command += 3
    
    def execute(self):
        """Execute a single instruction"""
        # Handle input loop - at command 123
        if self.current_command == 123:
            self.user_input_index += 1
            self.rbx0x10_location = 4
            try:
                self.rbx0x10[3] = ord(self.user_input[self.user_input_index])
            except IndexError:
                return False
            self.current_command += 1
            return True
        
        # End of program at command 251 (0xFB in hex)
        if self.current_command == 251:
            return False
        
        # Check bounds
        if self.rbx0x10_location >= len(self.rbx0x10) or self.rbx0x18_location >= len(self.rbx0x18):
            return False
        
        try:
            command = self.commands[self.base_command + self.current_command]
        except KeyError:
            return False
        
        # Execute command
        if command == "00":
            self.current_command += 1
        elif command == "01":
            return False
        elif command == "10":
            self.command0x10()
        elif command == "11":
            self.command0x11()
        elif command == "12":
            self.command0x12()
        elif command == "13":
            self.command0x13()
        elif command == "14":
            self.command0x14()
        elif command == "20":
            self.command0x20()
        elif command == "21":
            self.command0x21()
        elif command == "30":
            self.command0x30()
        elif command == "31":
            self.command0x31()
        elif command == "32":
            self.command0x32()
        elif command == "33":
            self.command0x33()
        elif command == "34":
            self.command0x34()
        elif command == "80":
            self.command0x80()
        elif command == "81":
            self.command0x81()
        else:
            return False
        
        return True
    
    def run(self, user_input):
        """Run the VM with user input"""
        self.user_input = user_input
        self.user_input_index = 0
        self.rbx0x10[3] = ord(user_input[0]) if user_input else 0
        
        iterations = 0
        max_iterations = 1000000
        
        while iterations < max_iterations:
            if not self.execute():
                break
            iterations += 1
        
        # Build output message from stack
        output_msg = []
        for each in range(len(self.rbx0x10) - 1, -1, -1):
            if self.rbx0x10[each] != 0:
                output_msg.append(chr(self.rbx0x10[each]))
        
        output_text = "".join(output_msg)
        
        return {
            'iterations': iterations,
            'output': output_text,
            'success': "Congratulations" in output_text,
            'input': user_input
        }


if __name__ == "__main__":
    commands_file = r"c:\Users\ANH VU~\Downloads\matrix\matrix_commands.json"
    
    # Get user input
    user_input = input("Enter the password: ")
    
    try:
        emulator = VMEmulator(commands_file)
        result = emulator.run(user_input)
        
        print("\n" + "=" * 60)
        print("VM EXECUTION COMPLETE")
        print("=" * 60)
        print(f"Total Iterations: {result['iterations']:,}")
        print("=" * 60 + "\n")
        
        if result['success']:
            print("*" * 60)
            print("Congratulations... You have entered the correct password")
            print(f"Your input: {result['input']}")
            print("*" * 60)
        else:
            print("*" * 60)
            print("Failed... You have entered the wrong password")
            print(f"Your input: {result['input']}")
            print("*" * 60)
        
        print("\n")
        
    except FileNotFoundError as e:
        print(f"Error: Could not find file - {e}")
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()