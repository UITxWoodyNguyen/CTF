#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// --- Dữ liệu tĩnh từ Binary (Data Segment) ---
extern char unk_2008; // Dữ liệu dùng để tính độ dài flag
extern char aZNh[];    // Chuỗi đích để so sánh (Target string)

// --- Khai báo các hàm nguyên mẫu ---
unsigned int swap_elements(uint8_t *data_ptr, int length, int stride);
unsigned int shuffle_data(uint8_t *data_ptr, unsigned int length, int direction);
void xor_transform(char *data, unsigned int len, unsigned int key);
char* decrypt_data(char *src, size_t n);
int validate_solution(char *src, size_t n);

// --- [Hàm gốc: sub_751] ---
// Hoán đổi các byte dựa trên bước nhảy (stride)
unsigned int swap_elements(uint8_t *data_ptr, int length, int stride) {
    unsigned int result;
    uint8_t temp;
    unsigned int i;

    for (i = 0; ; i += stride) {
        result = length - stride + 1;
        if (i >= result) break;

        temp = data_ptr[i];
        data_ptr[i] = data_ptr[i + stride - 1];
        data_ptr[i + stride - 1] = temp;
    }
    return result;
}

// --- [Hàm gốc: sub_7C2] ---
// Xáo trộn toàn bộ mảng theo hướng tiến hoặc lùi
unsigned int shuffle_data(uint8_t *data_ptr, unsigned int length, int direction) {
    unsigned int result = 0;
    if (direction <= 0) {
        // Hướng lùi: Stride giảm dần
        for (int i = length - 1; i > 0; --i) {
            result = swap_elements(data_ptr, length, i);
        }
    } else {
        // Hướng tiến: Stride tăng dần
        for (unsigned int j = 1; j < length; ++j) {
            swap_elements(data_ptr, length, j);
            result = j;
        }
    }
    return result;
}

// --- [Hàm gốc: sub_6BD] ---
// Thực hiện phép XOR 4-byte
void xor_transform(char *data, unsigned int len, unsigned int key) {
    unsigned char key_bytes[4];
    key_bytes[0] = (unsigned char)((key >> 24) & 0xFF);
    key_bytes[1] = (unsigned char)((key >> 16) & 0xFF);
    key_bytes[2] = (unsigned char)((key >> 8) & 0xFF);
    key_bytes[3] = (unsigned char)(key & 0xFF);

    for (unsigned int i = 0; i < len; ++i) {
        data[i] ^= key_bytes[i % 4];
    }
}

// --- [Hàm gốc: sub_82B] ---
// Giải mã đa vòng XOR
char* decrypt_data(char *src, size_t n) {
    size_t aligned_size = (n & 0xFFFFFFFC) + 4;
    char *dest = (char *)malloc(aligned_size + 1);
    if (!dest) return NULL;

    memset(dest, 0, aligned_size + 1);
    strncpy(dest, src, aligned_size);

    // Vòng lặp XOR từ 0x0ABCFE0D đến 0xDEADBEEF
    for (unsigned int current_key = 180154381; current_key < 0xDEADBEEF; current_key += 2075469) {
        xor_transform(dest, aligned_size, current_key);
    }
    return dest;
}

// --- [Hàm gốc: sub_8C4] ---
// Xác thực cuối cùng giữa Input và Target (aZNh)
int validate_solution(char *src, size_t n) {
    char *user_data = (char *)calloc(n + 1, 1);
    char *target_data = (char *)calloc(n + 1, 1);
    
    strncpy(user_data, src, n);
    strncpy(target_data, aZNh, n);

    // Cả hai đều được xáo trộn ngược trước khi so sánh
    shuffle_data((uint8_t *)user_data, n, -1);
    shuffle_data((uint8_t *)target_data, n, -1);

    puts("checking solution...");
    int is_correct = 1;
    for (size_t i = 0; i < n; ++i) {
        if (user_data[i] != target_data[i]) {
            is_correct = -1;
            break;
        }
    }

    free(user_data);
    free(target_data);
    return is_correct;
}

// --- [Hàm gốc: sub_9AF] ---
// Luồng chính của chương trình
int validate_flag() {
    char *input_buffer = (char *)calloc(512, 1);
    if (!input_buffer) return -1;

    printf("input the flag: ");
    if (fgets(input_buffer, 512, stdin) == NULL) {
        free(input_buffer);
        return -1;
    }

    // Xóa ký tự xuống dòng từ fgets
    input_buffer[strcspn(input_buffer, "\n")] = 0;

    // Tính độ dài flag mục tiêu
    size_t flag_len = strnlen(&unk_2008, 512);

    // 1. Biến đổi dữ liệu nguồn (Decrypt XOR)
    char *transformed_data = decrypt_data(&unk_2008, flag_len);

    // 2. Xáo trộn dữ liệu vừa giải mã (Shuffle Forward)
    shuffle_data((uint8_t *)transformed_data, flag_len, 1);

    // 3. So sánh Input với chuỗi đích thông qua xáo trộn ngược
    if (validate_solution(input_buffer, flag_len) == 1) {
        puts("Correct!");
    } else {
        puts("Incorrect.");
    }

    free(input_buffer);
    free(transformed_data);
    return 0;
}

int main() {
    return validate_flag();
}