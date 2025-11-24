#include <stdint.h>
#include <stdio.h>

int main(void) {
    int32_t local_c = 123098;   // 0x1E0DA in decimal
    for (int32_t i = 0; i < 607; ++i) {   // 0x25F = 607
        local_c += i;
    }
    printf("picoCTF{%d}\n", local_c);   // print decimal
}
