# byp4ss3d
### Information
- Category: Web Exploitation
- Points: 300
- Level: Medium

### Description
This challenge asks us to bypass a registration portal that only allows students to upload ID images. The portal enforces image-only filters, so only files with image extensions are accepted.

Here is the website:
![](https://cdn.discordapp.com/attachments/961544480366931969/1432366069108047992/image.png?ex=69869a9a&is=6985491a&hm=0cabeaf298d3bbd4f0fbf87e411f2ab37c32c306d4402db0905dd43a9e472a27&)

### Hint
- Apache can be tricked into executing non-PHP files as PHP with a `.htaccess` file.
- Try uploading more than just one file.

## Solution
The website checks for image file extensions like `.jpg`, `.png`, and `.gif` before allowing uploads. However, the server uses Apache, which can be manipulated using a `.htaccess` file. By uploading a `.htaccess` file, we can instruct Apache to treat files with image extensions as PHP scripts, allowing us to upload a PHP shell disguised as an image.

Read more about [`.htaccess`](https://hackmd.io/@thanhnguyne2403/ByBCkEyy-x) files.

### Create files

- **`.htaccess` file**: This file configures Apache to process files with `.jpg`, `.png`, and `.gif` extensions as PHP code. This is the key to bypassing the image-only filter.

![](https://cdn.discordapp.com/attachments/961544480366931969/1432564452645146634/image.png?ex=6986aa9d&is=6985591d&hm=555da0d9adef612f766c2c9813be2e8229fa7a727d529d0f9bef0bbbf6e7cfac&)

- **`shell.jpg` file**: This file contains PHP code. When Apache processes it as a PHP script (thanks to the `.htaccess`), it allows us to execute system commands by passing them as parameters.

![](https://cdn.discordapp.com/attachments/961544480366931969/1432564789971779703/image.png?ex=6986aaed&is=6985596d&hm=d929b27a281b3e694dcbbfe5e450a8d69b0d4539af03492b343ecb99f33931af&)

### Uploading the files and Executing commands
1. Upload the `.htaccess` file and the `shell.jpg` file to the server.
2. After uploading, both files appear in the `/images/` directory:
![](https://cdn.discordapp.com/attachments/961544480366931969/1432566452992479332/image.png?ex=6986ac7a&is=69855afa&hm=b8b97ff9a2867c51239178d2299f7ad3eac0f770b045bd79a24c434186991d50&)
3. To check if the shell works, use the `ls` command to list directory contents:
![](https://cdn.discordapp.com/attachments/961544480366931969/1432566521644974185/image.png?ex=6986ac8a&is=69855b0a&hm=20d0f5dc2c0f2406f4d1d3115f44163b4d5971e3794f338432fbca8ff8f5d807&)
4. Use the `find` command to search for the flag file (`find / -name "*flag*"`). The flag file is found in `/var/www/`:
![](https://cdn.discordapp.com/attachments/961544480366931969/1432567930138398921/image.png?ex=6986adda&is=69855c5a&hm=0df88ab2704fe1297c9ef6c895807cd91fa1d6bbe81c7d1b457624a47242a4da&)
5. Finally, use the `cat` command to read the flag (`cat /var/www/flag.txt`):
![](https://cdn.discordapp.com/attachments/961544480366931969/1432569140614267032/image.png?ex=6986aefa&is=69855d7a&hm=93af22a34db0862c6d479b8b200ec7957a4e4470cceca8c089a77ed859c9b0b7&)

##### The flag is **`picoCTF{s3rv3r_byp4ss_0c257942}`**

---

### Conclusion
The main bug in this website is that it only checks file extensions to enforce image uploads, but does not validate the actual file content or restrict server-side configuration changes. Because Apache allows `.htaccess` files to override how files are handled, an attacker can upload a `.htaccess` file to make the server treat image files as PHP scripts. This lets a malicious user upload a PHP shell disguised as an image and execute arbitrary code on the server.

**Scripted summary of the bug:**
1. User uploads `.htaccess` file, changing Apache's behavior to treat `.jpg`, `.png`, `.gif` files as PHP.
2. User uploads a PHP shell with an image extension (e.g., `shell.jpg`).
3. Server executes the shell as PHP, allowing command execution.
4. Attacker gains access to sensitive files and system commands.

**Root cause:**
- The website relies only on file extension checks and allows `.htaccess` uploads, enabling attackers to change server behavior and bypass security restrictions.
