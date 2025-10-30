# byp4ss3d
### Information
- Category: Web Exploitation
- Points: 300
- Level: Medium
### Description
The task is finding a way to bypass the registration portal requiring students to upload ID images and enforces image-only filters

Here is the website:

![](https://github.com/UITxWoodyNguyen/CTF/blob/main/Picture/image_5.png?raw=true)
### Hint
- Apache can be tricked into executing non-PHP files as PHP with a `.htaccess` file.
- Try uploading more than just one file.

## Solution
> Overall, the web only allows users to upload file with basic image extension checks (`.jpg, .png, .gif`). However, the server runs Apache, which can be tricked via `.htaccess` file in order to certain file types are handled as PHP scripts. -> We need to create this file types.
>
> Read more about [`.htaccess`](https://hackmd.io/@thanhnguyne2403/ByBCkEyy-x) file

### Create files

- `.htaccess` file: This file tells Apache: "Treat files with `.jpg, .png, .gif` extensions as PHP files"

![](https://github.com/UITxWoodyNguyen/CTF/blob/main/Picture/image_6.png?raw=true)


-  `shell.jpg` file: The file will run the PHP code in `shell.jpg` instead of serving it as image content, which allow us to pass arbitrary operating system commands in the command query parameter.

![](https://github.com/UITxWoodyNguyen/CTF/blob/main/Picture/image_7.png?raw=true)

### Uploading the files and Executing commands
* We upload `.htaccess` file and `shell.jpg` file respectively.
  
* After the files uploaded, we can see both files are located in `/images/` directory
![](https://github.com/UITxWoodyNguyen/CTF/blob/main/Picture/image_8.png?raw=true)

* Verified the shell was working by listing the contents (using `ls` command):
![](https://github.com/UITxWoodyNguyen/CTF/blob/main/Picture/image_9.png?raw=true)

* Next, using `find` command to search the flag file (`command=find / -name "*flag*"`). Then we can see the `flag.txt` file located in `/var/www/`
![](https://github.com/UITxWoodyNguyen/CTF/blob/main/Picture/image_10.png?raw=true)

* Using `cat` command to get the flag (`command=cat /var/www/flag.txt`):
![](https://github.com/UITxWoodyNguyen/CTF/blob/main/Picture/image_11.png?raw=true)

##### The flag is **`picoCTF{s3rv3r_byp4ss_0c257942}`**
