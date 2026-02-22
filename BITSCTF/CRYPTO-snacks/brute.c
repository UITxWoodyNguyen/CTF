#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

static const uint8_t RCON[10] = {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36};

uint8_t gf_mult(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) result ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1B; // IRREDUCIBLE_POLY 0x11B reduced to 0x1B
        b >>= 1;
    }
    return result;
}

uint8_t gf_pow(uint8_t base, int exp) {
    if (exp == 0) return 1;
    uint8_t result = 1;
    while (exp > 0) {
        if (exp & 1) {
            result = gf_mult(result, base);
        }
        base = gf_mult(base, base);
        exp >>= 1;
    }
    return result;
}

void generate_sbox(uint8_t sbox[256]) {
    for (int x = 0; x < 256; x++) {
        uint8_t val = gf_pow((uint8_t)x, 23);
        val ^= 0x63;
        sbox[x] = val;
    }
}

void generate_inv_sbox(uint8_t sbox[256], uint8_t inv[256]){
    for (int i=0;i<256;i++) inv[i]=0;
    for (int i=0;i<256;i++) inv[sbox[i]] = i;
}

void bytes_to_state(const uint8_t *data, uint8_t state[4][4]){
    for (int r=0;r<4;r++) for (int c=0;c<4;c++) state[r][c]=0;
    for (int i=0;i<16;i++){
        state[i%4][i/4] = data[i];
    }
}

void state_to_bytes(uint8_t state[4][4], uint8_t *out){
    for (int c=0;c<4;c++){
        for (int r=0;r<4;r++){
            *out++ = state[r][c];
        }
    }
}

void add_round_key(uint8_t state[4][4], const uint8_t *round_key){
    for (int r=0;r<4;r++){
        for (int c=0;c<4;c++){
            state[r][c] = state[r][c] ^ round_key[r + 4*c];
        }
    }
}

void sub_bytes(uint8_t state[4][4], const uint8_t sbox[256]){
    for (int r=0;r<4;r++) for (int c=0;c<4;c++) state[r][c] = sbox[state[r][c]];
}

void inv_sub_bytes(uint8_t state[4][4], const uint8_t inv_sbox[256]){
    for (int r=0;r<4;r++) for (int c=0;c<4;c++) state[r][c] = inv_sbox[state[r][c]];
}

void shift_rows(uint8_t state[4][4]){
    uint8_t tmp[4][4];
    for (int r=0;r<4;r++){
        for (int c=0;c<4;c++) tmp[r][c] = state[r][(c + r) % 4];
    }
    memcpy(state, tmp, 16);
}

void inv_shift_rows(uint8_t state[4][4]){
    uint8_t tmp[4][4];
    for (int r=0;r<4;r++){
        for (int c=0;c<4;c++) tmp[r][c] = state[r][(c - r + 4) % 4];
    }
    memcpy(state, tmp, 16);
}

void mix_columns(uint8_t state[4][4], const uint8_t MIX[4][4]){
    uint8_t result[4][4] = {0};
    for (int c=0;c<4;c++){
        for (int r=0;r<4;r++){
            uint8_t val = 0;
            for (int i=0;i<4;i++){
                val ^= gf_mult(MIX[r][i], state[i][c]);
            }
            result[r][c] = val;
        }
    }
    memcpy(state, result, 16);
}

void key_expansion(const uint8_t key[16], uint8_t round_keys[][16], const uint8_t sbox[256], int rounds){
    uint8_t words[4* (rounds+1)][4];
    for (int i=0;i<4;i++){
        for (int j=0;j<4;j++) words[i][j] = key[4*i + j];
    }
    int total_words = 4*(rounds+1);
    for (int i=4;i< total_words;i++){
        uint8_t temp[4];
        for (int k=0;k<4;k++) temp[k] = words[i-1][k];
        if (i % 4 == 0){
            uint8_t t0 = temp[0];
            temp[0] = sbox[temp[1]];
            temp[1] = sbox[temp[2]];
            temp[2] = sbox[temp[3]];
            temp[3] = sbox[t0];
            temp[0] ^= RCON[(i/4)-1];
        }
        for (int j=0;j<4;j++) words[i][j] = words[i-4][j] ^ temp[j];
    }
    for (int r=0;r<=rounds;r++){
        for (int i=0;i<4;i++){
            for (int j=0;j<4;j++){
                round_keys[r][j + 4*i] = words[r*4 + i][j];
            }
        }
    }
}

int encrypt_block(const uint8_t round_keys[][16], const uint8_t sbox[256], const uint8_t MIX[4][4], const uint8_t in[16], uint8_t out[16], int rounds){
    uint8_t state[4][4];
    bytes_to_state(in, state);
    add_round_key(state, round_keys[0]);
    for (int r=1;r<rounds;r++){
        sub_bytes(state, sbox);
        shift_rows(state);
        mix_columns(state, MIX);
        add_round_key(state, round_keys[r]);
    }
    sub_bytes(state, sbox);
    shift_rows(state);
    add_round_key(state, round_keys[rounds]);
    state_to_bytes(state, out);
    return 0;
}

int decrypt_block(const uint8_t round_keys[][16], const uint8_t inv_sbox[256], const uint8_t INV_MIX[4][4], const uint8_t in[16], uint8_t out[16], int rounds){
    uint8_t state[4][4];
    bytes_to_state(in, state);
    add_round_key(state, round_keys[rounds]);
    inv_shift_rows(state);
    inv_sub_bytes(state, inv_sbox);
    for (int r=rounds-1;r>0;r--){
        add_round_key(state, round_keys[r]);
        mix_columns(state, INV_MIX);
        inv_shift_rows(state);
        inv_sub_bytes(state, inv_sbox);
    }
    add_round_key(state, round_keys[0]);
    state_to_bytes(state, out);
    return 0;
}

int hex2bytes(const char *hex, uint8_t *out, int outlen){
    int len = strlen(hex);
    if (len != outlen*2) return -1;
    for (int i=0;i<outlen;i++){
        unsigned int v;
        if (sscanf(hex+2*i, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

int main(){
    const char *key_hint = "26ab77cadcca0ed41b03c8f2e5"; // 26 hex chars -> 13 bytes
    const char *pt_hex = "376f73334dc9db2a4d20734c0783ac69";
    const char *ct_hex = "9070f81f4de789663820e8924924732b";
    const char *enc_flag_hex = "8e70387dc377a09cbc721debe27c468157b027e3e63fe02560506f70b3c72ca19130ae59c6eef47b734bb0147424ec936fc91dc658d15dee0b69a2dc24a78c44";

    uint8_t sbox[256], inv_sbox[256];
    generate_sbox(sbox);
    generate_inv_sbox(sbox, inv_sbox);

    uint8_t MIX[4][4] = {{0x02,0x03,0x01,0x01},{0x01,0x02,0x03,0x01},{0x01,0x01,0x02,0x03},{0x03,0x01,0x01,0x02}};
    uint8_t INV_MIX[4][4] = {{0x0E,0x0B,0x0D,0x09},{0x09,0x0E,0x0B,0x0D},{0x0D,0x09,0x0E,0x0B},{0x0B,0x0D,0x09,0x0E}};

    uint8_t pt[16], ct[16];
    if (hex2bytes(pt_hex, pt, 16) || hex2bytes(ct_hex, ct, 16)){
        fprintf(stderr, "bad hex\n"); return 1;
    }

    int rounds = 4;

    // prepare key hint bytes
    int hint_len = strlen(key_hint);
    if (hint_len != 26){
        fprintf(stderr, "unexpected key_hint length\n"); return 1;
    }
    uint8_t hint_bytes[13];
    for (int i=0;i<13;i++){
        unsigned int v; sscanf(key_hint+2*i, "%2x", &v); hint_bytes[i] = v;
    }

    uint8_t key[16];
    // fill first 13 bytes
    memcpy(key, hint_bytes, 13);

    uint8_t round_keys[5][16];

    uint64_t max = 1ULL<<24;
    for (uint64_t i=0;i<max;i++){
        // append 3 bytes big-endian of i? In hex append as lowercase zero-padded 6 hex digits
        // Python printf used %06x, which yields lowercase hex; order: appended to hint -> so last bytes are the 3 bytes of that hex in sequence
        unsigned int b0 = (i >> 16) & 0xFF;
        unsigned int b1 = (i >> 8) & 0xFF;
        unsigned int b2 = i & 0xFF;
        key[13] = b0; key[14] = b1; key[15] = b2;

        key_expansion(key, round_keys, sbox, rounds);
        uint8_t out[16];
        encrypt_block(round_keys, sbox, MIX, pt, out, rounds);
        if (memcmp(out, ct, 16) == 0){
            printf("Found key: ");
            for (int k=0;k<16;k++) printf("%02x", key[k]);
            printf("\n");
            // decrypt flag
            int enc_len = strlen(enc_flag_hex)/2;
            int blocks = enc_len / 16;
            uint8_t encblk[16], decblk[16];
            for (int b=0;b<blocks;b++){
                char chunk[33];
                memcpy(chunk, enc_flag_hex + b*32, 32);
                chunk[32]=0;
                hex2bytes(chunk, encblk, 16);
                decrypt_block(round_keys, inv_sbox, INV_MIX, encblk, decblk, rounds);
                for (int j=0;j<16;j++) putchar(decblk[j]);
            }
            putchar('\n');
            return 0;
        }
    }
    printf("Key not found\n");
    return 0;
}
