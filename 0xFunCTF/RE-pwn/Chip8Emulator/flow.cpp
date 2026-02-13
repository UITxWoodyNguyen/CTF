#include <iostream>
#include <string>
#include <memory>
#include "Emulator.h"
#include "DisplaySDL.h"
#include "KeyboardSDL.h"
#include "SoundSDL.h"
#include "CmdLineParser.h"
#include "Logger.h"

int main(int argc, char** argv) {
    // Quản lý Logger qua shared_ptr (v10 trong decompile)
    std::shared_ptr<Logger> logger = Logger::getInstance();
    
    // Khởi tạo bộ phân tích tham số dòng lệnh
    CmdLineParser parser;
    parser.parseCmdLine(argc, argv);

    // Thiết lập mức độ Log (LogLevel) nếu được người dùng chỉ định
    if (parser.isLogLevelSet()) {
        int level = parser.getLogLevel();
        switch (level) {
            case 0: logger->setLogLevel(LogLevel::TRACE); break;
            case 1: logger->setLogLevel(LogLevel::DEBUG); break;
            case 2: logger->setLogLevel(LogLevel::INFO);  break;
            case 3: logger->setLogLevel(LogLevel::WARN);  break;
            case 4: logger->setLogLevel(LogLevel::ERROR); break;
            default: break;
        }
    }

    // Kiểm tra xem đường dẫn ROM có được cung cấp hay không
    if (!parser.isRomFileNameSet()) {
        logger->log("No rom path provided", LogLevel::DEBUG);
        exit(1);
    }

    // Khởi tạo các thành phần phần cứng qua giao diện SDL
    DisplaySDL display;   // Quản lý hiển thị màn hình
    KeyboardSDL keyboard; // Quản lý nhập liệu bàn phím
    SoundSDL sound;       // Quản lý âm thanh

    // Khởi tạo lõi giả lập và kết nối các thiết bị ngoại vi
    Emulator emulator;
    emulator.setDisplay(&display);
    emulator.setKeyboard(&keyboard);
    emulator.setSound(&sound);

    // Lấy tên file ROM và bắt đầu quá trình giả lập
    std::string romPath = parser.getRomFileName();
    
    if (emulator.init(romPath)) {
        emulator.run();     // Vòng lặp chính của giả lập
        emulator.deinit();  // Giải phóng tài nguyên
    }

    // Các đối tượng tự động gọi Destructor khi ra khỏi phạm vi hàm main
    return 0;
}