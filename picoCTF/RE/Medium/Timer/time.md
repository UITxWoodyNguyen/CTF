# Timer

### Information
* Category: RE
* Point:
* Level: Medium

### Description
You will find the flag after analysing this apk

### Hint
- Decompile
- mobsf or jadx

### Solution
#### What we got ?
- The problem gives us a `.apk` file.

#### How to get the flag ?
- Try to decompile it by using `apktool`:
    ```
    apktool d timer.apk
    ```
- We will get a list of file after decompiling. Check the file `apktool.yml`, we will get the flag:
    ```yml
    versionInfo:
    versionCode: '1'
    versionName: picoCTF{t1m3r_r3v3rs3d_succ355fully_17496}
    ```
