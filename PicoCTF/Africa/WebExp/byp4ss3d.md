# byp4ss3d
### Information
- Category: Web Exploitation
- Points: 300
- Level: Medium
### Description
The task is finding a way to bypass the registration portal requiring students to upload ID images and enforces image-only filters

Here is the website:

![](https://media.discordapp.net/attachments/961544480366931969/1432366069108047992/image.png?ex=6900ca5a&is=68ff78da&hm=f2512067ec3f480ae716cbcb9f7642cda4fed5f2e7e63e879731b888b60bb577&=&format=webp&quality=lossless&width=688&height=325)
### Hint
- Apache can be tricked into executing non-PHP files as PHP with a .htaccess file.
- Try uploading more than just one file.

## Solution
> Overall, the web only allows users to upload file with basic image extension checks (`.jpg, .png, .gif`). However, the server runs Apache, which can be tricked via `.htaccess` file in order to certain file types are handled as PHP scripts. -> We need to create this file types.

### Create files

- `.htaccess` file:

![](https://media.discordapp.net/attachments/961544480366931969/1432564452645146634/image.png?ex=6901831d&is=6900319d&hm=7dcd39f81cc25afb388d4344af80489caf3185ffe55e2f066733bfe88e1e832a&=&format=webp&quality=lossless&width=611&height=190)

-  `shell.jpg` file: The file content allow us to pass arbitrary operating system commands in the command query parameter.

![](https://media.discordapp.net/attachments/961544480366931969/1432564789971779703/image.png?ex=6901836d&is=690031ed&hm=b79c1d892acded4cb14d8c699477fc47c3786032bfd5ab5e9f771b42e608dbf2&=&format=webp&quality=lossless&width=539&height=194)

### Uploading the files and Executing commands
* We upload `.htaccess` file and `shell.jpg` file respectively.
* After the files uploaded, we can see both files are located in `/images/` directory
![](https://media.discordapp.net/attachments/961544480366931969/1432566452992479332/image.png?ex=690184fa&is=6900337a&hm=af7a6f8b5d52a92a4a721bf329d1ba26a508e2386a98c58724f86be0a0faf070&=&format=webp&quality=lossless&width=869&height=49)
![](https://media.discordapp.net/attachments/961544480366931969/1432566521644974185/image.png?ex=6901850a&is=6900338a&hm=f01fb49cc0dcd783c2f2fd646be4ad6f906422dc2611e976ff5b9ae0e589c434&=&format=webp&quality=lossless&width=871&height=53)
* Verified the shell was working by listing the contents:
![](https://media.discordapp.net/attachments/961544480366931969/1432567930138398921/image.png?ex=6901865a&is=690034da&hm=f7078ecfc4ebb05d69db8a9d815c4491ced11a6271172d20adb82216f8e9654a&=&format=webp&quality=lossless&width=1265&height=161)
* Next, searching the flag file by using `command=find / -name "*flag*"`. Then we can see the `flag.txt` file is located in `/var/www/`
![](https://media.discordapp.net/attachments/961544480366931969/1432642078441209906/image.png?ex=6901cb68&is=690079e8&hm=1e378b5f24e9e10db88f26282e80efd23faaa8def14cd8fd2936fe3fedee1c89&=&format=webp&quality=lossless&width=1860&height=201)
* Using `cat` command to get the flag (`command=cat /var/www/flag.txt`):
![](https://media.discordapp.net/attachments/961544480366931969/1432569140614267032/image.png?ex=6901877a&is=690035fa&hm=2dd5b0c6beb02a7cb2ea35875c258ade4f7177073c5afbcf9157c98aff6b4ff8&=&format=webp&quality=lossless&width=1288&height=155)

**The flag is `picoCTF{s3rv3r_byp4ss_0c257942}`**
