# Safe Opener 2

### Information
* Category: RE
* Point:
* Level: Medium

### Description
What can you do with this file? I forgot the key to my safe but this file is supposed to help me with retrieving the lost key. Can you help me unlock my safe?

### Hint
Download and try to decompile the file.

### Solution
#### What we got ?
- We got a `.class` file, so I try to decompile it with http://www.javadecompilers.com/. After decompiling, we will have [decompile.java](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Medium/Safe%20Opener%202/decompile.java)

#### How to get the flag ?
- Check the `openSafe()` function, we will find out the flag:
    ```java
    public static boolean openSafe(String password) {
        String encodedkey = "picoCTF{SAf3_0p3n3rr_y0u_solv3d_it_5bfbd6f1}";
        if (password.equals(encodedkey)) {
            System.out.println("Sesame open");
            return true;
        } else {
            System.out.println("Password is incorrect\n");
            return false;
        }
    }
    ```
