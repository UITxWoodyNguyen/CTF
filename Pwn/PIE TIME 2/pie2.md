# PIE TIME 2

### Information
* Category: Pwn
* Point:
* Level: Easy

### Description
Can you try to get the flag? I'm not revealing anything anymore!! Connect to the program with netcat:

`$ nc rescued-float.picoctf.net <PORT>`


### Hint
- What vulnerability can be exploited to leak the address?
- Please be mindful of the size of pointers in this binary

### Solution

#### What we got?
- The problem gives us a src code of a server and we can connect via netcat.
    ```c
    #include <stdio.h>
    #include <stdlib.h>
    #include <signal.h>
    #include <unistd.h>

    void segfault_handler() {
        printf("Segfault Occurred, incorrect address.\n");
        exit(0);
    }

    void call_functions() {
        char buffer[64];
        printf("Enter your name:");
        fgets(buffer, 64, stdin);
        printf(buffer);

        unsigned long val;
        printf(" enter the address to jump to, ex => 0x12345: ");
        scanf("%lx", &val);

        void (*foo)(void) = (void (*)())val;
        foo();
    }

    int win() {
        FILE *fptr;
        char c;

        printf("You won!\n");
        // Open file
        fptr = fopen("flag.txt", "r");
        if (fptr == NULL)
        {
            printf("Cannot open file.\n");
            exit(0);
        }

        // Read contents from file
        c = fgetc(fptr);
        while (c != EOF)
        {
            printf ("%c", c);
            c = fgetc(fptr);
        }

        printf("\n");
        fclose(fptr);
    }

    int main() {
        signal(SIGSEGV, segfault_handler);
        setvbuf(stdout, NULL, _IONBF, 0); // _IONBF = Unbuffered

        call_functions();
        return 0;
    }
    ```

    - The code includes 3 function: `main()`, `win()` and `call_functions()`. It ask for our name, which takes about 64 bits, then print it to `stdout` and prompts us for the address to call (same as [PIE]()).
    - Moreover, looking closely, after getting our name, the code will print directly the input by using `printf()`, which can cause **format string vulnerability**. 
    - So instead of using regular character for input, we will use `%p` to leak the value address. 

#### How to get the flag ?
- First, try decompile the binary file given from the problem by using Ghidra tools.
- We can see, `main()` is started at address `0x...400`. The address of `call_functions()` and `win()` is `0x...2c7` and `0x...36a`, respectively:

    ![main]()

    ![call_func]()

    ![win]()

- First, try disassemble the `main` with GDB, we observed that the pattern of an address will be `0x555555555abc`.

    ![dis]()

- Run the program locally and base on the analyze above, we will use a 64 bytes input with all `"%p"`. And the program return to a list of address. Looking closely, we can find the address `0x555555555441`, which is in the `main()`.

    ![add]()

- Try a little counting, this value is at position **19** in this input. So instead of a 64 bytes string for input, we can use `%19$p` to get exactly the address we need. Breakdown:

    - `%`: This indicates the start of a format specifier.
    - `19`: This is a field width specifier, meaning the printed value should take up at lease 19 characters.
    - `$`: Is used to select a specific argument
    - `p`: indicates that the value should be printed as a pointer

- Using this pattern and replace `abc` with `36a`, we can see that the program return to the win result

    ![win]()

- So base on the local test, try the same when connecting to the server via netcat, and we will receive the flag.

    ![Flag]()
