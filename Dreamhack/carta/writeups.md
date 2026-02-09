# Carta
> Problem Link: https://dreamhack.io/wargame/challenges/2376

# Solution

## Analyzing
- Ta nhận được một file binary từ challenge. Thực hiện decompile bằng IDA và dịch lại, ta có thông tin như sau:

    - Đây là game ghép đôi thẻ bài (Memory Card Game) trên bảng 16x16 với tổng cộng 128 cặp bài. Player cần tìm tất cả các cặp trong **tối đa** 128 lượt.
    - Thực hiện kiểm tra `main()`, ta dễ dàng nhận xét flow của game như sau:
        ```c++
        /*
            ┌─────────────────────────────────────────┐
            │ 1. Khởi tạo I/O (tắt buffer)            │
            ├─────────────────────────────────────────┤
            │ 2. Đọc seed ngẫu nhiên từ /dev/urandom  │
            │    → In ra "Stage X"                    │
            ├─────────────────────────────────────────┤
            │ 3. setup_game():                        │
            │    a) Điền 128 cặp bài (0x00-0x7F)      │
            │    b) Xáo trộn 256 lần bằng LFSR        │
            ├─────────────────────────────────────────┤
            │ 4. Vòng lặp chính:                      │
            │    while (còn ô chưa khớp):             │
            │       - Nhập tọa độ lá 1 → hiện giá trị │
            │       - Nhập tọa độ lá 2 → hiện giá trị │
            │       - Nếu khớp → đánh dấu đã khớp     │
            │       - Tăng bộ đếm trial               │
            ├─────────────────────────────────────────┤
            │ 5. Kết thúc:                            │
            │    Nếu trials ≤ 128 → IN FLAG           │
            └─────────────────────────────────────────┘
        */

        int main(int argc, char **argv, char **envp) {
            init_system(); // Khởi tạo I/O

            // Lấy Stage ngẫu nhiên từ /dev/urandom (hạt giống shuffle)
            FILE* stream = fopen("/dev/urandom", "rb");
            if (!stream) return -1;
            do {
                fread(&byte_4060, 1, 1, stream); // byte_4060 là stage/seed cho LFSR
            } while (!byte_4060); // Đảm bảo Stage khác 0
            fclose(stream);
            byte_4060 = 12;

            puts("[carta]");
            printf("Stage %hhu\n", byte_4060); // In Stage để người chơi biết hạt giống

            setup_game(); // Khởi tạo bàn cờ và tráo bài

            // Print board
            for(int i=0; i<16; i++){
                for(int j=0; j<16; j++){
                    printf("%02x ", byte_4080[16*i + j]); // byte_4080: 16x16 board
                }
                printf("\n");
            }

            // Vòng lặp chính của trò chơi
            while (is_game_active()) {
                play_trial(++dword_4280); // Tăng bộ đếm trial và thực hiện lượt chơi
            }

            printf("Game Cleared! Trials: %d\n", dword_4280); // dword_4280: số lượt chơi

            // Điều kiện nhận Flag: Phải hoàn thành trò chơi trong 128 lượt hoặc ít hơn.
            // Vì có 128 cặp bài, 128 lượt nghĩa là mỗi lượt bạn đều phải chọn trúng 1 cặp.
            if (dword_4280 <= 128) {
                printf("Perfect Gamer! Get the Flag: ");
                char *lineptr = nullptr;
                size_t n = 0;
                FILE* flag_file = fopen("./flag", "r");
                if (flag_file) {
                    if (getline(&lineptr, &n, flag_file) != -1) {
                        printf("%s", lineptr);
                    }
                    free(lineptr);
                    fclose(flag_file);
                }
                putchar('\n');
            }

            return 0;
        }
        ```

    - Kiểm tra ngược lên step set up game, ta dễ dàng thấy game sử dụng thuật toán LFSR để tráo 128 lá bài (từ `0x00` đến `0x7f`). Mà thuật LFSR hoạt động với một `seed` cố định đã được leak trong `main`. Do đó, đây là lỗ hổng đầu tiên ta có thể khai thác:
        ```c++
        unsigned char lfsr_next() {
            unsigned char lsb = byte_4060 & 1; // Lấy bit cuối cùng
            byte_4060 >>= 1;                   // Dịch phải 1 bit
            if (lsb) {
                byte_4060 ^= 0xB8;             // Nếu bit cuối là 1, thực hiện XOR với đa thức 0xB8
            }
            return byte_4060;
        }

        for (int k = 0; k < 256; k++) {
            r1 = seed & 0xF;         // Đọc TRƯỚC khi gọi lfsr_next!
            c1 = (seed >> 4) & 0xF;
            seed = lfsr_next(seed);
            
            r2 = seed & 0xF;
            c2 = (seed >> 4) & 0xF;
            seed = lfsr_next(seed);
            
            swap(board[r1][c1], board[r2][c2]);
        }
        ```
    - Ta dễ dàng nhận thấy số lần thực hiện shuffle được cố định là 256 và công thức shuffle được giữ nguyên cho cả 256 lần.
- Thực hiện disassembly, ta xác định được thứ tự thực hiện các thao tác shuffle:
    ```asm
    13be:  movzbl 0x2c9b(%rip),%eax   # Đọc seed
    13c8:  and    $0xf,%eax            # r1 = seed & 0xF
    13d5:  shr    $0x4,%al             # c1 = seed >> 4
    13e3:  call   12ee                 # RỒI MỚI gọi lfsr_next()
    ```
- Từ đây, thứ tự chính xác là đọc toạ độ trước, sau đó mới gọi `lfsr()`.

## Reversing
- Từ các nhận xét và phân tích, ta có code reverse như sau:
    ```python
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
    ```
- Flag: `DH{N0_M155_R3QU1R3D:fH2ah/EJZH+6kJMBcPO7PA==}`