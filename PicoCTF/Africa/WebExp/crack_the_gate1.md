# Crack the Gate 1
### Information
* Category: Web Exploitation
* Points: 100
* Level: Easy

### Description
For this challenge, we have access to a web application that we must log into. There is no option to create an account, so we will have to find credentials in another way.

![](https://github.com/UITxWoodyNguyen/CTF/blob/main/Picture/image_1.jpg?raw=true)

### Hint
1. Developers sometimes leave notes in the code; but not always in plain text.
2. A common trick is to rotate each letter by 13 positions in the alphabet.

## Solution
When checking the source code of the page, we come across this:

![](https://github.com/UITxWoodyNguyen/CTF/blob/main/Picture/image_2.png?raw=true)

Base on the hints, the HTML comments we find is encoded in [ROT13](https://en.wikipedia.org/wiki/ROT13). So we need to decode it. This is the ROT13 decoding code:
```c++
#include <bits/stdc++.h>
using namespace std;

// ABGR: Wnpx - grzcbenel olcnff: hfr urnqre "K-Qri-Npprff: lrf"

int main () {
    string lower_encrypted = "#nopqrstuvwxyzabcdefghijklm";
    string lower_alphabet = "#abcdefghijklmnopqrstuvwxyz";
    string higher_encrypted = "#NOPQRSTUVWXYZABCDEFGHIJKLM";
    string higher_alphabet = "#ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    
    string plaintext;
    getline(cin, plaintext);
    int n = plaintext.size();
    for(int i=0; i<n; i++) {
    	if (plaintext[i] >= 'a' and plaintext[i] <= 'z') {
    	    int index = int(plaintext[i]) - 'a' + 1;
    	    cout << lower_encrypted[index];
    	} else if (plaintext[i] >= 'A' and plaintext[i] <= 'Z') {
    	    int index = int(plaintext[i]) - 'A' + 1;
    	    cout << higher_encrypted[index];
    	} else cout << plaintext[i];
    }
    cout << endl;
}
```
Checking the code result, we find this: 

![](https://github.com/UITxWoodyNguyen/CTF/blob/main/Picture/image_3.png?raw=true)

According to this message, we can use the header `X-Dev-Access:yes`, which is a backdoor left by the developers. To do this, we can use [BurpSuite](https://portswigger.net/burp).

After intercepting and adding the header `X-Dev-Access:yes` to the request (along with any password), we can find the flag.

![](https://github.com/UITxWoodyNguyen/CTF/blob/main/Picture/image_4.png?raw=true)
