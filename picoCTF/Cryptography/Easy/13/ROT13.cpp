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
