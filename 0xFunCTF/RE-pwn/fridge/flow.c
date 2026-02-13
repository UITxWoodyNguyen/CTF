#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Giả định các biến và đường dẫn từ phân vùng data của binary
const char* open_message = "Welcome to the Smart Fridge Manager!";
const char* options_message = "1. List food in fridge\n2. Set welcome message\n3. Exit";
const char* config_filepath = "./config.txt";

// --- [Raw function name: print_food] ---
// Hàm này liệt kê các tệp tin trong thư mục 'food_dir'
int print_food() {
    puts("Food currently in fridge:");
    // Sử dụng lệnh hệ thống ls để liệt kê file, cách nhau bởi dấu phẩy (-m)
    return system("ls -m food_dir");
}

// --- [Raw function name: set_welcome_message] ---
// Hàm này cho phép người dùng nhập tin nhắn mới và lưu vào file cấu hình
int set_welcome_message() {
    char s[32];      // Bộ đệm 32 byte [esp+Ch] [ebp-2Ch]
    FILE *stream;    // [esp+2Ch] [ebp-Ch]

    puts("New welcome message (up to 32 chars):");
    
    // LỖ HỔNG BẢO MẬT: Hàm gets() không kiểm tra độ dài đầu vào
    // Cho phép tấn công Stack Buffer Overflow
    gets(s); 

    stream = fopen(config_filepath, "w");
    if (!stream) {
        puts("Unable to open config file.");
        exit(1);
    }

    // Ghi tin nhắn mới vào file cấu hình
    fprintf(stream, "welcome_msg: %s", s);
    return fclose(stream);
}

// --- [Raw function name: main] ---
int main(int argc, const char **argv, const char **envp) {
    char choice;

    puts(open_message);

    while (1) {
        puts(options_message);
        printf("> ");
        fflush(stdout);

        choice = getchar();
        
        // Xóa bộ đệm cho đến khi gặp dòng mới (ASCII 10)
        while (getchar() != 10 && !feof(stdin));

        if (choice == '3') { // ASCII 51
            break;
        }

        if (choice > '3') {
            goto INVALID_OPTION;
        }

        if (choice == '1') { // ASCII 49
            print_food();
        }
        else if (choice == '2') { // ASCII 50
            set_welcome_message();
        }
        else {
        INVALID_OPTION:
            puts("Invalid option.");
        }
    }

    puts("Bye!");
    return 0;
}