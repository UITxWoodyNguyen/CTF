from pwn import *
from collections import defaultdict

HOST = 'host3.dreamhack.games'
PORT = 19652

# context.log_level = 'debug'

def lfsr_next(seed):
    lsb = seed & 1
    seed >>= 1
    if lsb:
        seed ^= 0xB8
    return seed & 0xFF

def compute_board(stage):
    board = [0] * 256
    val = 0
    for i in range(16):
        for j in range(0, 16, 2):
            board[16 * i + j] = val
            board[16 * i + j + 1] = val
            val += 1

    seed = stage
    for _ in range(256):
        # FIXED: Read seed BEFORE lfsr_next, not after!
        r1 = seed & 0xF
        c1 = (seed >> 4) & 0xF
        seed = lfsr_next(seed)
        
        r2 = seed & 0xF
        c2 = (seed >> 4) & 0xF
        seed = lfsr_next(seed)
        
        idx1, idx2 = 16 * r1 + c1, 16 * r2 + c2
        board[idx1], board[idx2] = board[idx2], board[idx1]
    return board

def solve():
    io = remote(HOST, PORT)
    
    # Đọc Stage
    io.recvuntil(b'Stage ')
    stage = int(io.recvline().strip())
    print(f"[+] Stage: {stage}")
    
    # Tính board
    board = compute_board(stage)
    
    # Tìm pairs
    pairs = defaultdict(list)
    for i in range(256):
        pairs[board[i]].append(i)
    
    pair_list = list(pairs.values())
    print(f"[+] Found {len(pair_list)} pairs")
    
    # Gửi tất cả 128 cặp
    for idx, pos in enumerate(pair_list):
        r1, c1 = pos[0] // 16, pos[0] % 16
        r2, c2 = pos[1] // 16, pos[1] % 16
        
        # Đợi "pick:" và gửi tọa độ 1
        io.recvuntil(b'pick:')
        io.sendline(f"{r1} {c1}".encode())
        
        # Đợi "pick:" và gửi tọa độ 2  
        io.recvuntil(b'pick:')
        io.sendline(f"{r2} {c2}".encode())
        
        if (idx + 1) % 20 == 0:
            print(f"[*] Progress: {idx+1}/128")
    
    print("[+] All pairs sent!")
    
    # Nhận kết quả
    try:
        result = io.recvall(timeout=10).decode()
        print(result)
    except:
        print("[!] Timeout receiving result")
    
    io.close()

if __name__ == "__main__":
    solve()