# Crack the Gate 1
### Information
* Category: Web Exploitation
* Points: 100
* Level: Easy

### Description:
We’re in the middle of an investigation. One of our persons of interest, ctf player, is believed to be hiding sensitive data inside a restricted web portal. We’ve uncovered the email address he uses to log in: `ctf-player@picoctf.org`. Unfortunately, we don’t know the password, and the usual guessing techniques haven’t worked. But something feels off... it’s almost like the developer left a secret way in. Can you figure it out?

Additional details will be available after launching your challenge instance.

### Hint
1. Developers sometimes leave notes in the code; but not always in plain text.
2. A common trick is to rotate each letter by 13 positions in the alphabet.

## Solution
For this challenge, we have access to a web application that we must log into. There is no option to create an account, so we will have to find credentials one way or another.

![](https://media.discordapp.net/attachments/961544480366931969/1432290314797711400/image.png?ex=690083cd&is=68ff324d&hm=a635dfdc01cbaf0c9befba32972efd91ce3dc02c147b65c129d40ff3954ca42b&=&format=webp&quality=lossless&width=624&height=434&)

When checking the source code of the page, we come across this:

![](https://media.discordapp.net/attachments/961544480366931969/1432291465928642610/image.png?ex=690084e0&is=68ff3360&hm=2cd9a815382d119b64602c6b3cacff95a3593d5384fd9e73718e14e2dd890c76&=&format=webp&quality=lossless&width=751&height=415)

Base on the hints, the HTML comments we find is encoded in [ROT13](https://en.wikipedia.org/wiki/ROT13). So we need to decode it. This is the ROT13 decoding code:
```
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

![](https://media.discordapp.net/attachments/961544480366931969/1432295988344787004/image.png?ex=69008916&is=68ff3796&hm=a3961be6bd8c913887de90e6bdf2cf04613a8a06046e98cdfabfe263458a7f8f&=&format=webp&quality=lossless&width=650&height=126)

According to this message, we can use the header `X-Dev-Access:yes`, which is a backdoor left by the developers. To do this, we can use [BurpSuite](https://portswigger.net/burp).

After intercepting and adding the header X-Dev-Access:yes to the request (along with any password), we can find the flag.

![](https://media.discordapp.net/attachments/961544480366931969/1432297979443675156/image.png?ex=69008af1&is=68ff3971&hm=1d861470ec8f58cef2956c90b8e4452335e19577833b59e032bc50a12eba46e8&=&format=webp&quality=lossless&width=1291&height=451)
