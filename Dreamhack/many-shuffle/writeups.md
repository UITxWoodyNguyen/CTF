# many-shuffle
> Problem Link: https://dreamhack.io/wargame/challenges/1618

## Analyzing
- Challenge cho một file binary. Thực hiện decompile bằng IDA và dịch lại, ta có được `main()` của chương trình như sau:
    ```c++
    #include <iostream>
    #include <vector>
    #include <string>
    #include <cstring>
    #include <cstdlib>
    #include <ctime>

    // This is the transposition table found at 0x4020 in the binary.
    // It dictates which index moves where during each of the 16 rounds.
    extern unsigned char byte_4020[256]; 

    void sub_1664() {
        // Usually a function to disable buffering for CTF challenges
        setvbuf(stdout, NULL, _IONBF, 0);
    }

    int main(int argc, char** argv) {
        char original_s[64];    // s in decompiler
        char shuffled_dest[32]; // dest in decompiler
        char user_input[24];    // s2 in decompiler
        
        sub_1664();
        srand(time(0));

        // 1. Generate a random 16-character string (A-Z)
        for (int i = 0; i < 16; ++i) {
            original_s[i] = (rand() % 26) + 'A';
        }
        original_s[16] = '\0';

        puts("Random String Generated! Now Shuffle...");

        // Initialize shuffled_dest with the original string
        strncpy(shuffled_dest, original_s, strlen(original_s));

        // 2. The Shuffling Logic
        // This loop swaps data between the back-half of 'original_s' and 'shuffled_dest'
        // based on the mapping table 'byte_4020'.
        for (int j = 0; j <= 15; ++j) {
            for (int k = 0; k <= 15; ++k) {
                int table_index = 16 * j + k;
                int target_map = byte_4020[table_index];

                if (j & 1) { 
                    // Odd rounds: Copy from original_s (offset 32) back to shuffled_dest
                    shuffled_dest[target_map] = original_s[k + 32];
                } else {
                    // Even rounds: Copy from shuffled_dest to original_s (offset 32)
                    original_s[target_map + 32] = shuffled_dest[k];
                }
            }
        }

        printf("Shuffled String: %s\n", shuffled_dest);

        // 3. The Challenge
        printf("Original String?: ");
        if (fgets(user_input, 18, stdin)) {
            // Remove trailing newline
            user_input[strcspn(user_input, "\n")] = 0;

            if (strcmp(original_s, user_input) == 0) {
                FILE* stream = fopen("./flag", "r");
                if (stream) {
                    char* lineptr = NULL;
                    size_t n = 0;
                    getline(&lineptr, &n, stream);
                    printf("Match! Here's your flag: %s", lineptr);
                    free(lineptr);
                    fclose(stream);
                }
            } else {
                puts("Wrong...");
            }
        }

        return 0;
    }
    ```
- Cụ thể, chương trình sẽ thực hiện tạo một random string gồm 16 kí tự trong khoảng `[A...Z]`, sau đó sử dụng bảng chuyển vị 256 byte `byte_4020` để xáo trộn string vừa tạo 16 lần. Người dùng cần tìm string gốc để lấy flag.
- Thực hiện kiểm tra bằng IDA, ta thấy bảng chuyển vị được tạo tại địa chỉ `0x4020`:

    ![Raw](https://github.com/UITxWoodyNguyen/CTF/blob/main/Dreamhack/many-shuffle/Screenshot%202026-02-09%20154908.png)
- Ta sử dụng `objdump` để dump toàn bộ bảng từ file nhị phân challenge cung cấp:
    ```
    $ objdump -s many-shuffle | grep -A 50 4020
    4020 0b080304 01000e0d 0f090c06 0205070a  ................
    4030 0f04080b 06070d02 0c03050e 0a000109  ................
    4040 040c0e05 0d06090a 01000b0f 02070308  ................
    4050 0a080f03 0406000b 010d0907 05020c0e  ................
    4060 0b06090f 02010a0e 030c0d00 05040807  ................
    4070 09040b05 060f0800 03010a0d 020e0c07  ................
    4080 0a0e0907 080d030b 0c0f0200 04050601  ................
    4090 05040d01 0002090b 0c07080a 060e0f03  ................
    40a0 04080502 0a0f0b07 00010c03 0e06090d  ................
    40b0 0d0e0f0b 00020a04 07060901 0503080c  ................
    40c0 0e020305 0a010700 090d0c0b 04060f08  ................
    40d0 030b0e0a 06040701 020d0f00 0c090508  ................
    40e0 0d0f0102 0c0a0307 09060805 00040b0e  ................
    40f0 000e040d 06010a05 030c070b 0f020809  ................
    4100 0b020807 0503090d 040f0001 060c0e0a  ................
    4110 0b010800 0c0d040e 0a060f07 09050302  ................
    ```

## Reversing
- Ta nhận thấy thuật toán xáo trộn đã sử dụng được thực hiện như sau:

    - Xáo trộn hoán đổi giữa `shuffled_dest` và `original_s[32..47]` dựa trên bảng. Để đảo ngược:
    - Bắt đầu với chuỗi đã xáo
    - Áp dụng thao tác đảo ngược cho vòng 15 đến 0
    - Cho vòng lẻ: set temp[k] = shuf[t]
    - Cho vòng chẵn: set shuf[k] = temp[t]
- Từ đây, ta đã có đủ dữ kiện để tìm string gốc:
    ```python
    import socket

    # Transposition table extracted from binary at 0x4020
    table = [
        0x0b, 0x08, 0x03, 0x04, 0x01, 0x00, 0x0e, 0x0d, 0x0f, 0x09, 0x0c, 0x06, 0x02, 0x05, 0x07, 0x0a,
        0x0f, 0x04, 0x08, 0x0b, 0x06, 0x07, 0x0d, 0x02, 0x0c, 0x03, 0x05, 0x0e, 0x0a, 0x00, 0x01, 0x09,
        0x04, 0x0c, 0x0e, 0x05, 0x0d, 0x06, 0x09, 0x0a, 0x01, 0x00, 0x0b, 0x0f, 0x02, 0x07, 0x03, 0x08,
        0x0a, 0x08, 0x0f, 0x03, 0x04, 0x06, 0x00, 0x0b, 0x01, 0x0d, 0x09, 0x07, 0x05, 0x02, 0x0c, 0x0e,
        0x0b, 0x06, 0x09, 0x0f, 0x02, 0x01, 0x0a, 0x0e, 0x03, 0x0c, 0x0d, 0x00, 0x05, 0x04, 0x08, 0x07,
        0x09, 0x04, 0x0b, 0x05, 0x06, 0x0f, 0x08, 0x00, 0x03, 0x01, 0x0a, 0x0d, 0x02, 0x0e, 0x0c, 0x07,
        0x0a, 0x0e, 0x09, 0x07, 0x08, 0x0d, 0x03, 0x0b, 0x0c, 0x0f, 0x02, 0x00, 0x04, 0x05, 0x06, 0x01,
        0x05, 0x04, 0x0d, 0x01, 0x00, 0x02, 0x09, 0x0b, 0x0c, 0x07, 0x08, 0x0a, 0x06, 0x0e, 0x0f, 0x03,
        0x04, 0x08, 0x05, 0x02, 0x0a, 0x0f, 0x0b, 0x07, 0x00, 0x01, 0x0c, 0x03, 0x0e, 0x06, 0x09, 0x0d,
        0x0d, 0x0e, 0x0f, 0x0b, 0x00, 0x02, 0x0a, 0x04, 0x07, 0x06, 0x09, 0x01, 0x05, 0x03, 0x08, 0x0c,
        0x0e, 0x02, 0x03, 0x05, 0x0a, 0x01, 0x07, 0x00, 0x09, 0x0d, 0x0c, 0x0b, 0x04, 0x06, 0x0f, 0x08,
        0x03, 0x0b, 0x0e, 0x0a, 0x06, 0x04, 0x07, 0x01, 0x02, 0x0d, 0x0f, 0x00, 0x0c, 0x09, 0x05, 0x08,
        0x0d, 0x0f, 0x01, 0x02, 0x0c, 0x0a, 0x03, 0x07, 0x09, 0x06, 0x08, 0x05, 0x00, 0x04, 0x0b, 0x0e,
        0x00, 0x0e, 0x04, 0x0d, 0x06, 0x01, 0x0a, 0x05, 0x03, 0x0c, 0x07, 0x0b, 0x0f, 0x02, 0x08, 0x09,
        0x0b, 0x02, 0x08, 0x07, 0x05, 0x03, 0x09, 0x0d, 0x04, 0x0f, 0x00, 0x01, 0x06, 0x0c, 0x0e, 0x0a,
        0x0b, 0x01, 0x08, 0x00, 0x0c, 0x0d, 0x04, 0x0e, 0x0a, 0x06, 0x0f, 0x07, 0x09, 0x05, 0x03, 0x02
    ]

    def reverse_shuffle(shuffled):
        shuf = list(shuffled)
        temp = [0] * 16
        for j in range(15, -1, -1):
            for k in range(16):
                idx = 16 * j + k
                t = table[idx]
                if j % 2 == 1:
                    temp[k] = shuf[t]
                else:
                    shuf[k] = temp[t]
        return ''.join(shuf)

    def main():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('host3.dreamhack.games', 20520))
        data = b''
        while True:
            chunk = s.recv(1024)
            if not chunk:
                break
            data += chunk
            if b'Original String?: ' in data:
                break
        data = data.decode()
        print("Received:", repr(data))
        lines = data.split('\n')
        shuffled = None
        for line in lines:
            if line.startswith('Shuffled String: '):
                shuffled = line[17:]
                break
        if not shuffled:
            print("No shuffled string found")
            return
        print("Shuffled:", shuffled)
        original = reverse_shuffle(shuffled)
        print("Original:", original)
        s.send((original + '\n').encode())
        response = s.recv(1024).decode()
        print("Response:", response)
        s.close()

    if __name__ == '__main__':
        main()
    ```
- Flag: `DH{7db43cb3498cbe8f2fa1416975bbdca04da997cddf20177be2d141edc2abc23c}`