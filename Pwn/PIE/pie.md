# PIE

### Information
* Category: Pwn
* Point:
* Level: Hard

### Description
Can you try to get the flag? Beware we have PIE!

Additional details will be available after launching your challenge instance.

### Hint
Can you figure out what changed between the address you found locally and in the server output?

### Solution

#### What we got?
- The problem give us a binary file and the src code of the page: [`pie.c`]()
- Check out the `main`, we observed that this code will get the address that we want to run. Moreover, we see that the flag contents is open in `win()` function. So our target is find out the address of `win()`.

    ```c
    printf("Address of main: %p\n", &main);

    unsigned long val;
    printf("Enter the address to jump to, ex => 0x12345: ");
    scanf("%lx", &val);
    printf("Your input: %lx\n", val);
    ```

#### How to get the flag ?
- First decompile the file in IDA and check the "Export" tab, we will find all the address of each functions. Check the `win`, its address is `00000000000012a7`. 
- However, when run the page via netcat, the address of main we receive is `0x5f7958d7133d`, which is not the same as the address in IDA.
- So we can find out the pattern of address is `0x5f7958d7XYZT`. Replace `XYZT` with `12a7` to get flag.

    ![Flag]()
