# 13
### Information
* Category: Cryptography
* Points: 
* Level: Easy

### Description
Cryptography can be easy, do you know what ROT13 is? 

`cvpbPGS{abg_gbb_onq_bs_n_ceboyrz}`

### Hint
* This can be solved online if you don't want to do it by hand!

## Solution
* ROT13 (short for "rotate by 13 places") is a simple letter substitution cipher used to obscure text. It works by replacing each letter in the alphabet with the letter 13 positions after it, looping around if necessary.
*Here’s how it works:
    * The English alphabet has 26 letters.
    * Shifting by 13 means that applying ROT13 twice gives you back the original text.
* The encrypted flag is given in description, so we need a decrypting code to get the plaintext of the flag. Here is the code:
```
#include <bits/stdc++.h>
using namespace std;

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
**Flag: `picoCTF{not_too_bad_of_a_problem}`**
