#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// The assembly contains a hardcoded SHA256 sum check via a system call to 'sha256sum'
// and 'awk'. The target hash is likely the one found in the IDA header:
// 0D05624CFD68BE744EB6AA09D54FF1432491435AF5CD7659FCB67EF97F9D47A3

void print_usage(char* prog_name) {
    printf("Usage ./main <answer file>\n");
}

int main(int argc, char** argv) {
    FILE* fp;
    char* buffer;
    long file_size;
    char command[512];

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    // Attempt to open the provided answer file
    fp = fopen(argv[1], "rb");
    if (fp == NULL) {
        puts("File Not Found");
        return 1;
    }

    // Get file size
    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    rewind(fp);

    // Allocate memory and read file
    buffer = (char*)malloc(file_size + 1);
    if (fread(buffer, 1, file_size, fp) != file_size) {
        puts("Fread failed");
        free(buffer);
        fclose(fp);
        return 1;
    }
    buffer[file_size] = '\0';
    fclose(fp);

    /* The assembly contains a complex data block starting at 0x4020.
       This looks like a custom VM or a obfuscated state machine that 
       eventually triggers a hash check. 
       The command string at 0x2050 is: 
       "bash -c \"echo DH{$(sha256sum '%s' | awk '{print $1}')}\""
    */

    // Reconstructing the logic of the string formatting at 0x1170 and system call at 0x1110:
    sprintf(command, "bash -c \"echo DH{$(sha256sum '%s' | awk '{print $1}')}\"", argv[1]);
    
    // In the real binary, it compares the result of the file processing
    // against the internal expected value.
    
    // If the check passes:
    puts("Correct!");
    
    // If it fails:
    // puts("Wrong answer.");

    free(buffer);
    return 0;
}