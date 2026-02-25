# include <stdio.h>
# include <stdlib.h>

int main(int argc, char *argv[]) {
    if (argc <= 1) {
        // Print welcome message and usage
        puts("Welcome my DRM-protected application!");
        puts("Usage: ./challenge <license file path>");
        return -1;
    }

    // 1. Read the license file into memory
    char *file_data = read_file(argv[1]);
    puts("[i] loaded license file");

    // 2. Check mandatory prefix "LICENSE-"
    if (file_data == NULL || strncmp(file_data, "LICENSE-", 8) != 0) {
        puts("[!] invalid license format");
        return -1;
    }

    // 3. Advance past the prefix
    char *hex_data = file_data + 8;          // pointer to hex string
    size_t len = strlen(hex_data);

    // 4. Strip trailing whitespace (\n, \r, space)
    while (len > 0) {
        char c = hex_data[len - 1];
        if (c != '\n' && c != '\r' && c != ' ') break;
        len--;
    }

    // 5. ★★★ HEX DECODE ★★★
    // Each pair of hex digits encodes one raw key byte.
    // The format string "%02x" is stored in rodata and used here.
    size_t key_len = len / 2;                // 2 hex chars → 1 byte
    uint8_t *key = calloc(1, key_len + 1);
    for (size_t i = 0; i < key_len; i++) {
        sscanf(hex_data + i*2, "%02x", &key[i]);  // ← "%02x" in rodata
    }

    // 6. Pass key bytes to the VM
    setup_vm_license(key, key_len);

    // 7. Anti-debug check
    // Reads /proc/self/status → TracerPid field
    // Reads /proc/version     → checks for "Microsoft" (WSL)
    // Reads /proc/<ppid>/comm → checks parent process name
    if (check_debugger()) {
        puts("DEBUGGER DETECTED! LICENSING TERMS VIOLATED! >:(");
        return -1;
    }

    // 8. Trigger SIGILL → signal handler executes the VM
    //    (ud2 = undefined instruction, generates SIGILL)
    __asm__("ud2");      // → SIGILL → installed handler runs VM
    run_vm();

    return 0;
}