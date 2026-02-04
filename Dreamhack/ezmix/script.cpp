#include <iostream>
#include <fstream>
#include <vector>
#include <string>

// Xoay trái 1 byte
unsigned char rol(unsigned char val, unsigned char shift) {
    shift &= 7;
    return (val << shift) | (val >> (8 - shift));
}

int main() {
    const char* scriptFile = "program.bin"; // File script điều khiển (file .bin gốc)
    const char* inputFile = "output.bin";  // File đã mã hóa
    const char* outputFile = "recovered.txt"; // File kết quả giải mã

    // Đọc script
    std::ifstream script(scriptFile, std::ios::binary);
    if (!script) {
        std::cerr << "Không thể mở script điều khiển!\n";
        return 1;
    }
    std::vector<unsigned char> ops((std::istreambuf_iterator<char>(script)), std::istreambuf_iterator<char>());
    script.close();
    // Đọc dữ liệu mã hóa
    std::ifstream in(inputFile, std::ios::binary);
    if (!in) {
        std::cerr << "Không thể mở file mã hóa!\n";
        return 1;
    }
    std::string data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();

    // Tìm chuỗi đầu tiên (sau lệnh 4)
    std::string s = data;
    size_t op_count = ops.size();
    size_t idx = 0;
    std::vector<std::pair<unsigned char, unsigned char>> op_pairs;
    while (idx + 1 < op_count) {
        unsigned char cmd = ops[idx];
        unsigned char param = ops[idx + 1];
        op_pairs.push_back({cmd, param});
        idx += 2;
    }

    // Áp dụng NGƯỢC các thao tác (từ cuối về đầu)
    for (int i = (int)op_pairs.size() - 1; i >= 0; --i) {
        unsigned char cmd = op_pairs[i].first;
        unsigned char param = op_pairs[i].second;
        if (cmd == 4) {
            // Lệnh nhập chuỗi, bỏ qua khi giải mã
            continue;
        } else if (cmd == 1) {
            // Giải mã: trừ param
            for (size_t j = 0; j < s.size(); ++j) {
                s[j] = (unsigned char)(s[j] - param);
            }
        } else if (cmd == 2) {
            // Giải mã: XOR lại với param
            for (size_t j = 0; j < s.size(); ++j) {
                s[j] = (unsigned char)(s[j] ^ param);
            }
        } else if (cmd == 3) {
            // Giải mã: xoay trái
            for (size_t j = 0; j < s.size(); ++j) {
                s[j] = rol((unsigned char)s[j], param);
            }
        } else {
            std::cerr << "Lệnh không hợp lệ trong script!\n";
            return 1;
        }
    }

    // Ghi kết quả
    std::ofstream out(outputFile);
    if (!out) {
        std::cerr << "Không thể ghi file kết quả!\n";
        return 1;
    }
    out << s;
    out.close();
    std::cout << "Đã giải mã xong, kết quả lưu ở recovered.txt\n";
    return 0;
}
