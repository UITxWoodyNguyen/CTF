# Chronohack

### Information
* Category: Reverse Engineering
* Point:
* Level: Medium

### Description
Can you guess the exact token and unlock the hidden flag?
Our school relies on tokens to authenticate students. Unfortunately, someone leaked an important file for token generation. Guess the token to get the flag.
The access is granted through `nc verbal-sleep.picoctf.net 64315`.

### Hint
- https://www.epochconverter.com/
- https://learn.snyk.io/lesson/insecure-randomness/
- Time tokens generation
- Generate tokens for a range of seed values very close to the target time

### Solution

#### What we got ?
- They give us a `token_generator.py`:
```python
import random
import time

def get_random(length):
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    random.seed(int(time.time() * 1000))  # seeding with current time 
    s = ""
    for i in range(length):
        s += random.choice(alphabet)
    return s

def flag():
    with open('/flag.txt', 'r') as picoCTF:
        content = picoCTF.read()
        print(content)


def main():
    print("Welcome to the token generation challenge!")
    print("Can you guess the token?")
    token_length = 20  # the token length
    token = get_random(token_length) 
    print(token)

    try:
        n=0
        while n < 50:
            user_guess = input("\nEnter your guess for the token (or exit):").strip()
            n+=1
            if user_guess == "exit":
                print("Exiting the program...")
                break
            
            if user_guess == token:
                print("Congratulations! You found the correct token.")
                flag()
                break
            else:
                print("Sorry, your token does not match. Try again!")
            if n == 50:
                print("\nYou exhausted your attempts, Bye!")
    except KeyboardInterrupt:
        print("\nKeyboard interrupt detected. Exiting the program...")

if __name__ == "__main__":
    main()
```
- Overall, the program generates a random 20-character token using letters and digits. It seeds the random generator with the current time in milliseconds, meaning the token depends on the exact moment the program runs. The user gets up to 50 attempts to guess the token. If the guess matches the generated token, the program prints a secret flag from /flag.txt. If the user types "exit" or uses up all attempts, the program ends. Overall, it's a simple guessing challenge where success requires matching the exact random string.

#### How to get the flag ?
- Because of limitation (only 50 tries to get the flag), so we have to brute-force all tokens and auto re-connect to the server if the number of tries reach the limit.
```python
import socket
import time
import random
import sys

def get_random(length, seed):
    """Generate a random token with the given seed and length."""
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    random.seed(seed)
    return ''.join(random.choice(alphabet) for _ in range(length))

def connect_and_guess(start_seed_index, seeds, offsets, Ts, host, port, token_length, max_attempts):
    """Connect to the server and attempt to guess the token starting from start_seed_index."""
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
       
        client_socket.connect((host, port))
        print(f"Connected to {host}:{port}")

        
        response = client_socket.recv(4096).decode("utf-8")
        print("Server response:")
        print(response)
        T_welcome = int(time.time() * 1000)  

        
        if start_seed_index == 0:
            dummy_guess = "dummy"
            T_send = int(time.time() * 1000)
            client_socket.send((dummy_guess + "\n").encode("utf-8"))
            reply = client_socket.recv(4096).decode("utf-8")
            T_receive = int(time.time() * 1000)
            print("Dummy guess reply:")
            print(reply)
            RTT = T_receive - T_send
            one_way_delay = RTT / 2
            Ts[0] = T_welcome - one_way_delay  
            print(f"Estimated Ts: {Ts[0]}, RTT: {RTT}, Delay: {one_way_delay}")
        else:
            
            Ts[0] = T_welcome
            print(f"Reconnection Ts: {Ts[0]}")

        print(f"Testing seeds around Ts={Ts[0]} ms")
        print(f"Total seeds to try: {len(seeds)}")
        print(f"Starting at offset: {offsets[start_seed_index]} ms")
        print(f"Starting at seed: {seeds[start_seed_index]}")

       
        attempts_made = 0
        for i in range(start_seed_index, len(seeds)):
            if attempts_made >= max_attempts - (1 if start_seed_index == 0 else 0):
                print("Reached 50 attempt limit. Will reconnect.")
                return i  

            seed = seeds[i]
            offset = offsets[i]
            guess = get_random(token_length, seed)
            print(f"Attempt {attempts_made + 1}: Trying {guess} (Offset: {offset} ms)")
            client_socket.send((guess + "\n").encode("utf-8"))
            reply = client_socket.recv(4096).decode("utf-8")
            print("Server reply:")
            print(reply)
            attempts_made += 1

            if "Congratulations" in reply or "flag" in reply.lower():
                print("Success! The correct token was:", guess)
                client_socket.close()
                print("Connection closed")
                sys.exit(0) 

        return len(seeds) 

    except Exception as e:
        print(f"An error occurred: {e}")
        return start_seed_index  

    finally:
        client_socket.close()
        print("Connection closed")

def main():
    # Server details
    HOST = "verbal-sleep.picoctf.net"
    PORT =  #Change the port HERE
    token_length = 20
    max_attempts = 50
    range_start_ms = -50  # Start at Ts - 50 ms
    range_end_ms = 1000   # End at Ts + 1000 ms


    Ts = [0]  

  
    offsets = list(range(range_start_ms, range_end_ms + 1))  
    seeds = [0] * len(offsets)  
    print(f"Total seeds to try: {len(seeds)}")

    start_seed_index = 0
    while start_seed_index < len(seeds):
        
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client_socket.connect((HOST, PORT))
            response = client_socket.recv(4096).decode("utf-8")
            T_welcome = int(time.time() * 1000)
            client_socket.close()

           
            Ts[0] = T_welcome 
            seeds = [int(T_welcome + offset) for offset in offsets]
            print(f"Initial Ts for connection: {Ts[0]}")

            result = connect_and_guess(start_seed_index, seeds, offsets, Ts, HOST, PORT, token_length, max_attempts)
            if result == -1:
                break 
            start_seed_index = result  
            if start_seed_index < len(seeds):
                print(f"Reinitiating connection to try seeds starting from index {start_seed_index} (Offset: {offsets[start_seed_index]} ms)")
                time.sleep(1)  

        except Exception as e:
            print(f"Connection error: {e}")
            time.sleep(1)  

    if start_seed_index >= len(seeds):
        print("Exhausted all seeds without finding the correct token.")

if __name__ == "__main__":
    main()
```
- The script repeatedly connects to the server, captures the timestamp (`T_welcome`), and builds a list of possible seeds around that moment (from -50 ms to +1000 ms). For each possible seed, it regenerates the same random token locally using the `get_random()` function, then sends the guess to the server. Since the server allows 50 attempts per connection, the script reconnects and continues from where it left off. If any guess matches, the server prints the flag. The script automates this entire brute-force timing attack.
- Using this command to run the script:
```
python3 <file_name.py> <path_to_the_python_file> --window-before 50 --window-after 1000 --length 20
```
- Here is the result:
![Result](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Medium/Chronohack/image.png?raw=true)
