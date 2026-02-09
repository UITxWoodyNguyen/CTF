#include <iostream>
#include <cstdio>
#include <cstring>
#include <cstdlib>

// Define the data arrays
int result[] = {57, -101, 44, 198, 89, 88, 57, 171, -50, 198, 396, 400, -38, 115, 82, 102, -85, -81, -39, -83, -82, -80, -78, -32, -30, -31, 79, 83, 76, 83, 79, 87, 131, 84, 89, 135, 12, 19, 62, 59, 62, 57, 58, 56, 13, 52, 2392, 2350, 2592, 4851, 2800, 5202, 2964, 5300, 2646, 2970, 99, 95, 143, 89, 140, 137, 140, 85};
int dword_4024 = result[1];
int dword_4028 = result[2];
int dword_402C = result[3];
int dword_4030 = result[4];
int dword_4034 = result[5];
int dword_4038 = result[6];
int dword_403C = result[7];
int dword_4040 = result[8];
int dword_4044 = result[9];
int dword_4048 = result[10];
int dword_404C = result[11];
int dword_4050 = result[12];
int dword_4054 = result[13];
int dword_4058 = result[14];
int dword_405C = result[15];

/**
 * Merged validation logic representing the full call chain
 */
bool perform_full_check(char *a1) {
    
    // --- Starting raw function: check ---
    if (!( *a1 + 9 == result[0]                // result[0] corresponds to the first 'result'
        && ~a1[1] == dword_4024
        && a1[2] - 4 == dword_4028
        && 2 * a1[3] == dword_402C
        && a1[4] + 34 == dword_4030
        && a1[5] + 40 == dword_4034
        && a1[6] - 40 == dword_4038
        && 3 * a1[7] == dword_403C
        && ~a1[8] == dword_4040
        && 2 * a1[9] == dword_4044
        && 4 * a1[10] == dword_4048
        && 4 * a1[11] == dword_404C
        && 19 - a1[12] == dword_4050
        && a1[13] + 17 == dword_4054
        && a1[14] + 30 == dword_4058
        && a1[15] == dword_405C )) 
    {
        return false;
    }

    // --- Starting raw function: check_not ---
    for (int i = 16; i <= 25; ++i) {
        if ((char)(~a1[i]) + i != result[i]) 
            return false;
    }

    // --- Starting raw function: check_add ---
    for (int i = 26; i <= 35; ++i) {
        if (a1[i] + i != result[i]) 
            return false;
    }

    // --- Starting raw function: check_dec ---
    for (int i = 36; i <= 45; ++i) {
        if (a1[i] - i != result[i]) 
            return false;
    }

    // --- Starting raw function: check_mul ---
    for (int i = 46; i <= 55; ++i) {
        if (i * a1[i] != result[i]) 
            return false;
    }

    // --- Starting raw function: check_la ---
    for (int i = 56; i <= 63; ++i) {
        if (a1[i] + 100 - i != result[i]) 
            return false;
    }

    return true;
}

int main(int argc, const char **argv, const char **envp) {
    char input[128];

    puts("Input: ");
    if (scanf("%127s", input) != 1) return 0;
    printf("Read: %s\n", input);
    printf("Len: %zu\n", strlen(input));

    if (strlen(input) == 64) {
        if (perform_full_check(input)) {
            puts("Nice!");
            printf("Flag is DH{%s}\n", input);
        } else {
            puts("good."); // Failure message in original binary
        }
    } else {
        puts("Try again.");
    }

    return 0;
}