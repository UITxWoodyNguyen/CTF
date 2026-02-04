from pwn import *

# Config
LOCAL = False  # Đổi thành False để connect remote
HOST = "94.237.63.176"
PORT = 52434

def main():
    # Đọc path từ file
    try:
        with open('path.txt', 'r') as f:
            path = f.read().strip()
        print(f"[+] Loaded path ({len(path)} moves)")
    except FileNotFoundError:
        print("[!] path.txt not found! Run script.py first.")
        return
    
    # Connect
    if LOCAL:
        print("[*] Running locally...")
        p = process('./tunnel')
    else:
        print(f"[*] Connecting to {HOST}:{PORT}...")
        p = remote(HOST, PORT)
    
    # Send each direction
    print("[*] Solving maze...")
    for i, c in enumerate(path):
        p.sendlineafter(b"? ", c.encode())
        if (i + 1) % 50 == 0:
            print(f"    [{i+1}/{len(path)}] moves sent...")
    
    print(f"[+] All {len(path)} moves sent!")
    print("[*] Getting flag...\n")
    
    # Get output
    p.interactive()

if __name__ == "__main__":
    main()
