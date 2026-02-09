# dungeon-in-1983
> Problem link: https://dreamhack.io/wargame/challenges/1212

## Description
- Thử thách này về trò chơi **Dungeon Crawler**, người chơi cần đánh bại 10 con quái bằng cách tung phép qua 2 phím `A` và `B`. Chỉ số của quái được lấy random từ một seed ngẫu nhiên 64-bit. Nhiệm vụ của người chơi là cần cung cấp một string gồm `A` và `B` để win game.

## Analyzing
- Thực hiện decompile file trò chơi qua IDA và dịch lại, có thể thấy được những điều như sau:

    - `main()`:
        ```c++
        int main(int argc, char** argv) {
            const char* monsters[] = {
                "Basilisk", "Chimera", "Kraken", "Gorgon", "Wendigo",
                "Minotaur", "Leviathan", "Hydra", "Manticore", "Orc"
            };

            uint64_t random_seed;
            char input_buffer[200];
            FILE* urandom_ptr;

            setup_dungeon();

            urandom_ptr = fopen("/dev/urandom", "r");
            if (!urandom_ptr) {
                perror("fopen /dev/urandom");
                return -1;
            }

            printf("Welcome to the Dungeon!\n");
            printf("You have only two buttons: A and B.\n");
            printf("Each monster requires certain series of key combinations to be defeated!\n");

            for (int i = 0; i < 10; ++i) {
                if (fread(&random_seed, 8, 1, urandom_ptr) != 1) break;

                printf("[STAGE %2d]: %s\n", i + 1, monsters[i]);
                print_monster_stats(random_seed);

                printf("Cast your spell!: ");
                if (!fgets(input_buffer, sizeof(input_buffer), stdin)) break;

                // Strip newline
                size_t len = strlen(input_buffer);
                if (len > 0 && input_buffer[len - 1] == '\n') {
                    input_buffer[len - 1] = '\0';
                }

                if (!validate_spell(input_buffer, random_seed)) {
                    puts("You were defeated. Retreat!");
                    fclose(urandom_ptr);
                    return -1;
                }

                printf("%s defeated. STAGE %2d cleared!\n", monsters[i], i + 1);
            }

            fclose(urandom_ptr);

            // Final Stage: Flag output
            printf("It's dangerous to go alone! Take the flag: ");
            FILE* flag_file = fopen("./flag", "r");
            if (flag_file) {
                char *line = nullptr;
                size_t n = 0;
                if (getline(&line, &n, flag_file) != -1) {
                    printf("%s", line);
                }
                free(line);
                fclose(flag_file);
            } else {
                printf("CTF{fake_flag_for_testing}\n");
            }

            return 0;
        }
        ```

        - Game sẽ mở `/dev/urandom` để thực hiện random seed ngẫu nhiên.
        - Đối với mỗi quái:

            - `fread(&random_seed, 8, 1, urandom_ptr)`: Game thực hiện đọc 8 byte (64-bit) vào random_seed. Nếu thất bại, thoát vòng lặp.
            - `printf("[STAGE %2d]: %s\n", i + 1, monsters[i])`: In stage số và tên quái vật.
            - `print_monster_stats(random_seed)`: In chỉ số từ seed (HP, STR, v.v.).
            - `printf("Cast your spell!: ")`: Prompt nhập phép.
            - `fgets(input_buffer, sizeof(input_buffer), stdin)`: Đọc input vào buffer. Nếu thất bại (EOF), thoát.
            - Loại bỏ newline: Kiểm tra và thay '\n' bằng '\0' để chuỗi sạch.
            - `validate_spell(input_buffer, random_seed)`: Kiểm tra phép. Nếu sai, in "You were defeated" và thoát chương trình.
        - Sau khi win 10 round, game sẽ tự động mở file để in flag.
- Ta có được logic của game như sau: Setup → Mở urandom → Vòng lặp 10 stage (đọc seed → in info → đọc input → validate → thắng/thua) → In flag Cụ thể:
    
    - Step 1: **Thiết Lập**: Tắt buffering, đặt báo động 5 giây.
    - Step 2: **Tạo Quái Vật**: Đọc 10 seed ngẫu nhiên 64-bit từ `/dev/urandom`.
    - Step 3: **Cho Mỗi Quái Vật**:
        - In tên quái vật và chỉ số (HP, STR, AGI, VIT, INT, END, DEX) lấy từ seed.
        - Yêu cầu nhập phép.
        - Xác thực phép với seed đầy đủ.
    - Step 4: **Win game**: Sau khi đánh bại 10 quái vật, in flag từ `./flag`.
- Về các thao tác của game:

    - Lấy chỉ số: Các chỉ số được trích xuất từ seed 64-bit:
        ```c++
        void print_monster_stats(uint64_t seed) {
            printf("[INFO] HP: %5hu, STR: %5hhu, AGI: %5hhu, VIT: %5hhu, INT: %5hhu, END: %5hhu, DEX: %5hhu\n",
                HIWORD(seed),
                (unsigned char)BYTE_GET(seed, 0),
                (unsigned char)BYTE_GET(seed, 1),
                (unsigned char)BYTE_GET(seed, 2),
                (unsigned char)BYTE_GET(seed, 3),
                (unsigned char)BYTE_GET(seed, 4),
                (unsigned char)BYTE_GET(seed, 5));
        }
        ```
        
        - HP: 16 bit trên cùng (seed >> 48)
        - DEX: Bit 40-47
        - END: Bit 32-39
        - INT: Bit 24-31
        - VIT: Bit 16-23
        - AGI: Bit 8-15
        - STR: Bit 0-7

    - Xác thực (`validate_spell`):
        ```c++
        bool validate_spell(const char* s, uint64_t target) {
            uint64_t current_val = 0;
            bool a_pressed_last = false;
            bool spell_started = false;

            for (int i = 0; s[i] != '\0'; ++i) {
                if (s[i] == 'A') {
                    spell_started = true;
                    current_val += 1;
                    
                    if (a_pressed_last) {
                        puts("A button stucked! Retreat...");
                        exit(-1);
                    }
                    a_pressed_last = true;
                } 
                else if (s[i] == 'B') {
                    if (!spell_started) {
                        puts("Lore says the spell should start with A...");
                        exit(-1);
                    }
                    current_val *= 2;
                    a_pressed_last = false;
                } 
                else {
                    puts("Invalid button!");
                    exit(-1);
                }
            }
            return current_val == target;
        }
        ```

        - Bắt đầu với current_val = 0
        - `A`: Cộng 1, nhưng không thể nhấn hai lần liên tiếp hoặc trước khi bắt đầu.
        - `B`: Nhân 2, chỉ có thể sử dụng sau khi bắt đầu với 'A'.
        - Phải bắt đầu với `A`, chỉ cho phép `A` và `B`.
        - Mục tiêu: `current_val == target (seed)`

## Nhận xét
- Game đã sử dụng alarm ngăn brute-force (không thể chạy quá lâu) 
- Các seed random được sinh ngẫu nhiên
- Input validated không cho phép ký tự lạ, không cho phép một chuỗi 'A' liên tiếp.

## Reverse
- Từ các nhận xét và phân tích, ta có hướng reverse như sau:
    - Làm ngược lại: Nếu target lẻ, kết thúc với 'A' (trừ 1), ngược lại kết thúc với 'B' (chia 2).
    - Điều này đảm bảo không có 'A' liên tiếp và bắt đầu với 'A'.

- Source code:
    ```python
    import socket
    import re

    def get_spell(target):
        spell = []
        current = target
        while current > 0:
            if current % 2 == 1:
                spell.append('A')
                current -= 1
            else:
                spell.append('B')
                current //= 2
        return ''.join(reversed(spell))

    def main():
        host = 'host3.dreamhack.games'
        port = 24098  # External port, assuming it's the one to connect to

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))

        buffer = b''
        while True:
            data = s.recv(1024)
            if not data:
                break
            buffer += data
            lines = buffer.split(b'\n')
            buffer = lines[-1]  # Keep incomplete line

            for line in lines[:-1]:
                line = line.decode('utf-8', errors='ignore').strip()
                print(f"Received: {line}")

                # Parse stats
                match = re.search(r'HP:\s*(\d+).*STR:\s*(\d+).*AGI:\s*(\d+).*VIT:\s*(\d+).*INT:\s*(\d+).*END:\s*(\d+).*DEX:\s*(\d+)', line)
                if match:
                    HP, STR, AGI, VIT, INT, END, DEX = map(int, match.groups())
                    seed = (HP << 48) | (DEX << 40) | (END << 32) | (INT << 24) | (VIT << 16) | (AGI << 8) | STR
                    spell = get_spell(seed)
                    print(f"Seed: {seed}, Spell: {spell}")
                    s.sendall((spell + '\n').encode())
                    break

                if 'flag' in line.lower():
                    print(f"Flag: {line}")
                    return

    if __name__ == '__main__':
        main()
    ```
- Flag là `DH{ddfd394275e80d059f04cee16667ad40e81820a0b105e2f80f0d17544a274a62}`