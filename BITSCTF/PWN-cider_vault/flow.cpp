#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <emmintrin.h> // Cho các lệnh SIMD _mm_loadu_si128

// Cấu trúc đại diện cho một trang sách trong bộ nhớ
struct Page {
    void* data;
    size_t size;
};

// Mảng quản lý các trang (vats trong mã decompile)
Page pages[12]; // Giới hạn 0xB (11) + 1 = 12 trang

void init_workshop() {
    setbuf(stdin, nullptr);
    setbuf(stdout, nullptr);
    setbuf(stderr, nullptr);
    std::cout << "\033[38;5;213mstorybook-workshop\033[0m\n";
    std::cout << "\033[38;5;117mOnce upon a midnight, the workshop lamp stayed on.\033[0m\n";
    std::cout << "...\n";
}

// --- LUỒNG CHÍNH CỦA WORKSHOP ---

int main() {
    init_workshop();
    
    while (true) {
        // ... (Hiển thị Menu và đếm số trang đang hoạt động) ...
        std::cout << "> ";
        long long choice = get_num();

        switch (choice) {
            case 1: { // Open Page (Malloc)
                std::cout << "page id:\n";
                unsigned int id = get_num();
                if (id > 11 || pages[id].data) { std::cout << "no\n"; break; }
                
                std::cout << "page size:\n";
                size_t sz = get_num();
                if (sz < 128 || sz > 1184 + 128) { std::cout << "no\n"; break; }
                
                pages[id].data = malloc(sz);
                if (!pages[id].data) exit(1);
                pages[id].size = sz;
                std::cout << "ok\n";
                break;
            }

            case 2: { // Paint Page (Write - LỖ HỔNG OVERFLOW)
                std::cout << "page id:\n";
                unsigned int id = get_num();
                if (id > 11 || !pages[id].data) { std::cout << "no\n"; break; }
                
                std::cout << "ink bytes:\n";
                size_t ink_bytes = get_num();
                // LỖ HỔNG: Cho phép viết quá kích thước thực tế 128 bytes
                if (ink_bytes > pages[id].size + 128) { std::cout << "no\n"; break; }
                
                std::cout << "ink:\n";
                read(0, pages[id].data, ink_bytes); 
                std::cout << "ok\n";
                break;
            }

            case 3: { // Peek Page (Read - LỖ HỔNG LEAK)
                std::cout << "page id:\n";
                unsigned int id = get_num();
                if (id > 11 || !pages[id].data) { std::cout << "no\n"; break; }
                
                std::cout << "peek bytes:\n";
                size_t peek_bytes = get_num();
                // LỖ HỔNG: Cho phép đọc quá kích thước thực tế 128 bytes (Heap Leak)
                if (peek_bytes > pages[id].size + 128) { std::cout << "no\n"; break; }
                
                write(1, pages[id].data, peek_bytes);
                std::cout << "\nok\n";
                break;
            }

            case 4: { // Tear Page (Free)
                std::cout << "page id:\n";
                unsigned int id = get_num();
                if (id > 11 || !pages[id].data) { std::cout << "no\n"; break; }
                
                free(pages[id].data);
                // LỖ HỔNG: Không đặt con trỏ về NULL (Dangling Pointer) -> Use After Free
                std::cout << "ok\n";
                break;
            }

            case 5: { // Stitch Pages (Realloc & SIMD Copy)
                // Nối nội dung trang 2 vào cuối trang 1
                // Sử dụng lệnh XMM để copy 32 bytes (2 lần 16 bytes)
                break;
            }

            case 6: { // Whisper Path (Arbitrary Write - Obfuscated)
                std::cout << "page id:\n";
                unsigned int id = get_num();
                if (id <= 11 && pages[id].data) {
                    std::cout << "star token:\n";
                    // Ghi đè con trỏ với giá trị XOR (Obfuscation)
                    pages[id].data = (void*)(get_num() ^ 0x51F0D1CE6E5B7A91LL);
                    std::cout << "ok\n";
                }
                break;
            }
            
            case 8: exit(0);
        }
    }
}