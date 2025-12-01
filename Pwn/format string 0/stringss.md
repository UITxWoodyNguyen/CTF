# Heap 0

### Information
* Category: Pwn
* Point:
* Level: Easy

### Description
Can you use your knowledge of format strings to make the customers happy? 

Connect with the server via `nc mimas.picoctf.net <PORT>`

### Hint
- This is an introduction of format string vulnerabilities. Look up "format specifiers" if you have never seen them before.
- Just try out the different options

### Solution

#### What we got?
- The problem give us a binary file and a page. Try connect to the page via netcat, we found there are 3 input options.
- Moreover, check the src [`string0.c`](https://github.com/UITxWoodyNguyen/CTF/blob/main/Pwn/format%20string%200/string0.c), we can see that the count check is based on printed character. 
    ```c
    if (count > 2 * BUFSIZE) {
        serve_bob();
    }
    ```

#### How to get the flag ?
- The value of `BUFSIZE` is only 32. So we can use buffer overflow to crack this problem by using an input with the length over than 64.
    ![Flag](https://github.com/UITxWoodyNguyen/CTF/blob/main/Pwn/format%20string%200/Screenshot%202025-12-01%20153200.png?raw=true)
