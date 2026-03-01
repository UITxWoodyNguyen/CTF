#include <stdio.h>
#include <stdint.h>
#include <string.h>

uint16_t sub_1349(uint16_t a1) {
    uint16_t v = (uint16_t)(a1 * 0x1234);
    v = (uint16_t)((uint32_t)(v << 5) | (uint32_t)((v >> 11) & 0x1F));
    v = (uint16_t)(v * 0x5678);
    return v;
}

uint16_t sub_138A(const char *s, int len, uint16_t seed) {
    uint16_t h = seed;
    int count = len / 2;
    int i = 0;
    while (count > 0) {
        uint16_t word = (uint8_t)s[i] | ((uint16_t)(uint8_t)s[i+1] << 8);
        i += 2;
        h ^= sub_1349(word);
        uint32_t edx = (uint32_t)h << 7;
        uint32_t eax = (uint32_t)((h >> 9) & 0x7F);
        h = (uint16_t)(eax | edx);
        uint32_t tmp = (uint32_t)h * 5;
        h = (uint16_t)(tmp - 0x2153);
        count--;
    }
    uint16_t last_word = 0;
    if (len & 1) last_word = (uint8_t)s[i];
    h ^= sub_1349(last_word);
    h ^= (uint16_t)len;
    h ^= (h >> 8);
    h = (uint16_t)(h * 0xDEAD);
    h ^= (h >> 5);
    h = (uint16_t)(h * 0xDEAD);
    h ^= (h >> 8);
    return h;
}

int main() {
    char chars[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    int n = strlen(chars);
    char s[4] = {0};
    for(int i=0; i<n; i++)
        for(int j=0; j<n; j++)
            for(int k=0; k<n; k++) {
                s[0]=chars[i]; s[1]=chars[j]; s[2]=chars[k];
                if (sub_138A(s, 3, 0xCAFE) == 0x0796) {
                    printf("FOUND COLLISION: %s\n", s);
                    return 0;
                }
            }
    printf("Not found\n");
    return 0;
}