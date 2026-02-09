#include <iostream>
#include <vector>
#include <cstdio>
#include <cstdlib>
#include <cstring>

unsigned char byte_4060;           // Giá trị "Stage" (hạt giống cho bộ sinh số ngẫu nhiên)
unsigned char byte_4080[256];      // Bàn cờ 16x16 lưu giá trị các quân bài (tổng 256 ô)
unsigned char byte_4180[256];      // Trạng thái các ô (0: chưa lật, 1: đã khớp)
int dword_4280 = 0;                // Bộ đếm số lần thử (Trials)

// --- [Hàm gốc: sub_1289] ---
// Thiết lập chế độ đệm (buffering) cho các luồng nhập/xuất chuẩn.
void init_system() {
    setvbuf(stdin,  nullptr, _IONBF, 0); // Tắt bộ đệm để nhập dữ liệu ngay lập tức
    setvbuf(stdout, nullptr, _IONBF, 0); // Tắt bộ đệm để in dữ liệu ngay lập tức
    setvbuf(stderr, nullptr, _IONBF, 0);
}

// --- [Hàm gốc: sub_12EE] ---
// Thuật toán LFSR (Linear Feedback Shift Register) dùng để tạo số giả ngẫu nhiên.
// Hàm này thay đổi hạt giống (byte_4060) sau mỗi lần gọi.
unsigned char lfsr_next() {
    unsigned char lsb = byte_4060 & 1; // Lấy bit cuối cùng
    byte_4060 >>= 1;                   // Dịch phải 1 bit
    if (lsb) {
        byte_4060 ^= 0xB8;             // Nếu bit cuối là 1, thực hiện XOR với đa thức 0xB8
    }
    return byte_4060;
}

// --- [Hàm gốc: sub_132B] ---
// Khởi tạo bàn cờ và thực hiện tráo bài (Shuffle).
void setup_game() {
    unsigned char val = 0;
    // Bước 1: Điền 128 cặp bài vào bàn cờ 16x16 (giá trị từ 0x00 đến 0x7F)
    for (int i = 0; i < 16; ++i) {
        for (int j = 0; j < 16; j += 2) {
            byte_4080[16 * i + j] = val;     // Lá bài thứ nhất của cặp
            byte_4080[16 * i + 1 + j] = val; // Lá bài thứ hai của cặp
            val++;
        }
    }

    // Bước 2: Tráo bài dựa trên kết quả từ hàm LFSR
    for (int k = 0; k < 256; ++k) {
        // Lấy vị trí hoán đổi thứ nhất (r1, c1)
        lfsr_next();
        int r1 = byte_4060 & 0xF;        // Lấy 4 bit thấp làm dòng
        int c1 = (byte_4060 >> 4) & 0xF; // Lấy 4 bit cao làm cột

        // Lấy vị trí hoán đổi thứ hai (r2, c2)
        lfsr_next();
        int r2 = byte_4060 & 0xF;
        int c2 = (byte_4060 >> 4) & 0xF;

        // Hoán đổi giá trị hai lá bài tại (r1, c1) và (r2, c2)
        unsigned char temp = byte_4080[16 * r1 + c1];
        byte_4080[16 * r1 + c1] = byte_4080[16 * r2 + c2];
        byte_4080[16 * r2 + c2] = temp;
    }
}

// --- [Hàm gốc: sub_1754] ---
// Kiểm tra xem trò chơi đã kết thúc chưa (đã tìm thấy hết các cặp chưa).
bool is_game_active() {
    for (int i = 0; i < 256; ++i) {
        if (!byte_4180[i]) return true; // 4180 lưu trạng thái. Nếu còn ít nhất 1 ô chưa khớp, trả về true
    }
    return false;
}

// --- [Hàm gốc: sub_14A9] ---
// Logic xử lý một lượt chơi (chọn 2 lá bài).
void play_trial(int trial_num) {
    int r[2], c[2];
    unsigned char picked_cards[2];

    printf("* Trial %d\n", trial_num);

    for (int i = 0; i < 2; ++i) {
        printf("%s pick: ", (i == 0) ? "1st" : "2nd");
        if (scanf("%d %d", &r[i], &c[i]) != 2) exit(0);

        // Kiểm tra tọa độ nhập vào có hợp lệ không (0-15)
        if (r[i] >= 16 || c[i] >= 16 || r[i] < 0 || c[i] < 0) {
            puts("Invalid Input!");
            return; 
        }
        // Kiểm tra xem ô này đã được mở trước đó chưa
        if (byte_4180[16 * r[i] + c[i]]) {
            puts("Already Matched!");
            return;
        }

        // Tiết lộ giá trị quân bài vừa chọn
        picked_cards[i] = byte_4080[16 * r[i] + c[i]];
        printf("Revealed %hhx!\n", picked_cards[i]);

        if (i == 1) { // Sau khi đã chọn đủ 2 lá bài
            if (picked_cards[0] == picked_cards[1]) {
                // Nếu 2 lá bài giống nhau -> Khớp thành công
                printf("Found matching pairs of %hhx!\n", picked_cards[0]);
                byte_4180[16 * r[0] + c[0]] = 1;
                byte_4180[16 * r[1] + c[1]] = 1;
            } else {
                // Nếu 2 lá bài khác nhau -> Thất bại
                printf("%hhx does not match %hhx...\n", picked_cards[1], picked_cards[0]);
            }
        }
    }
}

// --- Hàm Main ---
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