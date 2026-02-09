#include <iostream>
#include <vector>
#include <string>
#include <cstdio>
#include <cstring>
#include <csignal>
#include <unistd.h>
#include <cstdlib>

/**
 * Macro definitions to mimic the decompiled byte-level access
 */
#define BYTE_GET(val, n) (((unsigned __int64)(val) >> (8 * (n))) & 0xFF)
#define HIWORD(val)      ((unsigned short)((unsigned __int64)(val) >> 48))

// Global handler for the 5-second timeout
void handler(int sig) {
    puts("\n[!] Time's up! The dungeon collapsed.");
    exit(-1);
}

/**
 * sub_130A: Environment Setup
 */
void setup_dungeon() {
    // Disable buffering for immediate output (standard in CTF challenges)
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stdin, nullptr, _IOLBF, 0);
    setvbuf(stderr, nullptr, _IOLBF, 0);

    // Set a 5-second alarm to prevent brute-forcing
    signal(SIGALRM, handler);
    alarm(5);
}

/**
 * sub_138D: Display Monster Stats
 * Interprets the 64-bit seed as a series of RPG-style attributes.
 */
void print_monster_stats(uint64_t seed) {
    printf("[INFO] HP: %5hu, STR: %5hhu, AGI: %5hhu, VIT: %5hhu, INT: %5hhu, END: %5hhu, DEX: %5hhu\n",
           HIWORD(seed),
           (unsigned char)BYTE_GET(seed, 0),
           (unsigned char)BYTE_GET(seed, 1),
           (unsigned char)BYTE_GET(seed, 2),
           (unsigned char)BYTE_GET(seed, 3),
           (unsigned char)BYTE_GET(seed, 4),
           (unsigned char)BYTE_GET(seed, 5));
}

/**
 * sub_1407: The Spell Validator
 * Reconstructs a number based on 'A' (+1) and 'B' (*2).
 */
bool validate_spell(const char* s, uint64_t target) {
    uint64_t current_val = 0;
    bool a_pressed_last = false;
    bool spell_started = false;

    for (int i = 0; s[i] != '\0'; ++i) {
        if (s[i] == 'A') {
            spell_started = true;
            current_val += 1;
            
            if (a_pressed_last) {
                puts("A button stucked! Retreat...");
                exit(-1);
            }
            a_pressed_last = true;
        } 
        else if (s[i] == 'B') {
            if (!spell_started) {
                puts("Lore says the spell should start with A...");
                exit(-1);
            }
            current_val *= 2;
            a_pressed_last = false;
        } 
        else {
            puts("Invalid button!");
            exit(-1);
        }
    }
    return current_val == target;
}

int main(int argc, char** argv) {
    const char* monsters[] = {
        "Basilisk", "Chimera", "Kraken", "Gorgon", "Wendigo",
        "Minotaur", "Leviathan", "Hydra", "Manticore", "Orc"
    };

    uint64_t random_seed;
    char input_buffer[200];
    FILE* urandom_ptr;

    setup_dungeon();

    urandom_ptr = fopen("/dev/urandom", "r");
    if (!urandom_ptr) {
        perror("fopen /dev/urandom");
        return -1;
    }

    printf("Welcome to the Dungeon!\n");
    printf("You have only two buttons: A and B.\n");
    printf("Each monster requires certain series of key combinations to be defeated!\n");

    for (int i = 0; i < 10; ++i) {
        if (fread(&random_seed, 8, 1, urandom_ptr) != 1) break;

        printf("[STAGE %2d]: %s\n", i + 1, monsters[i]);
        print_monster_stats(random_seed);

        printf("Cast your spell!: ");
        if (!fgets(input_buffer, sizeof(input_buffer), stdin)) break;

        // Strip newline
        size_t len = strlen(input_buffer);
        if (len > 0 && input_buffer[len - 1] == '\n') {
            input_buffer[len - 1] = '\0';
        }

        if (!validate_spell(input_buffer, random_seed)) {
            puts("You were defeated. Retreat!");
            fclose(urandom_ptr);
            return -1;
        }

        printf("%s defeated. STAGE %2d cleared!\n", monsters[i], i + 1);
    }

    fclose(urandom_ptr);

    // Final Stage: Flag output
    printf("It's dangerous to go alone! Take the flag: ");
    FILE* flag_file = fopen("./flag", "r");
    if (flag_file) {
        char *line = nullptr;
        size_t n = 0;
        if (getline(&line, &n, flag_file) != -1) {
            printf("%s", line);
        }
        free(line);
        fclose(flag_file);
    } else {
        printf("CTF{fake_flag_for_testing}\n");
    }

    return 0;
}