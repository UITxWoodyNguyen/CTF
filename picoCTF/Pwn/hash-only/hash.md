# hash-only

### Information
* Category: Pwn
* Point:
* Level: Medium

### Description
Here is a binary that has enough privilege to read the content of the flag file but will only let you know its hash. If only it could just give you the actual content!

---

## Version 1
### Hint
None

### Solution

#### What we got?
- The problem gives us a server and we can connect via `ssh`. Try to connect, we find a binary file named `flaghashed`, and when we run it, it will print a string, which is the "MD5 hasing" the flag located in `root/flag.txt`. 
- So we need to find the raw flag.

#### How to get the flag ?
- Make a copy of the file by using the command given in the problem and decompile it with Ghidra tools. 

    ![Ghidra](https://github.com/UITxWoodyNguyen/CTF/blob/main/Pwn/hash-only/ver1/Screenshot%202025-12-03%20140745.png?raw=true)

- Looking closely, the yellow line in the src code means this program will run like a shell. And with the command `md5sum`, it will auto do the MD5 hashing process for the file located in each path. Base on this, if we can change the command from `md5sum` to `cat`, we can have the flag.
- To do this, we need to copy the `cat` command to the directory containing the binary file and rename it into `md5sum`. Run the file again and we will get the flag.

    - To copy, we use this command:

        ```cmd
        cp $(which cat) md5sum
        ```

    - After being copied, the content in this directory will be like this:

        ![ls](https://github.com/UITxWoodyNguyen/CTF/blob/main/Pwn/hash-only/ver1/Screenshot%202025-12-03%20141326.png?raw=true)

    - Run the file again in this directory (using `PATH` to modify the directory) to get the flag:

        ![flag](https://github.com/UITxWoodyNguyen/CTF/blob/main/Pwn/hash-only/ver1/Screenshot%202025-12-03%20141334.png?raw=true)

---

## Version 2
### Hint
None

### Solution

#### What we got?
- The same as version 1

#### How to get the flag ?
- Try the same method as version 1. However, we observed that PATH is only read, and it is use rbash, which is a restricted version of the Bash shell. It’s the same program as bash, just launched in a mode that disables certain features to limit what a user can do. It’s often to limit shells, or locked-down user environments.
- Using `sh` to change from `rbash` to `sh` and to the same as version 1.

    ![Flag](https://github.com/UITxWoodyNguyen/CTF/blob/main/Pwn/hash-only/Screenshot%202025-12-03%20143138.png?raw=true)
