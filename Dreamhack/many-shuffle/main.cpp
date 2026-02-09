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