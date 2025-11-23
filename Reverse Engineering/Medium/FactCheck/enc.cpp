#include <iostream>
#include <string>

int main() {
    // Start with the prefix
    std::string flag = "picoCTF{wELF_d0N3_mate_";

    // Individual characters (or small strings)
    char local_208 = '5';
    char local_1e8 = '9';
    char local_1c8 = '3';
    char local_1a8 = '0';
    char local_188 = '4';
    char local_168 = 'a';
    char local_148 = 'e';
    char local_128 = 'a';
    char local_108 = 'd';
    char local_e8  = 'b';
    char local_c8  = '2';
    char local_a8  = '6';
    char local_88  = '4';
    char local_68  = '3';
    char local_48  = '8';
    char local_228 = '7';

    // Conditional concatenation
    if (local_208 < 'B') {
        flag += local_c8; // '2'
    }

    if (local_a8 != 'A') {
        flag += local_68; // '3'
    }

    if ((local_1c8 - local_148) == 3) {
        flag += local_1c8; // not added in this case
    }

    // Append the remaining characters in order
    flag += local_1e8;  // '9'
    flag += local_188;  // '4'
    if (local_168 == 'G') {
        flag += local_168; // not added here
    }
    flag += local_1a8;  // '0'
    flag += local_88;   // '4'
    flag += local_228;  // '7'
    flag += local_128;  // 'a'

    // Closing brace
    flag += '}';

    // Print the flag
    std::cout << flag << std::endl;

    return 0;
}

