# Quantum Scrambler

### Information
* Category: Reverse Engineering
* Point:
* Level: Medium

### Description
We invented a new cypher that uses "quantum entanglement" to encode the flag. Do you have what it takes to decode it? 

Connect to the program with netcat: `$ nc verbal-sleep.picoctf.net 64292`

### Hint
- Run `eval` on the cypher to interpret it as a python object
- Print the outer list one object per line
- Feed in a known plaintext through the scrambler

### Solution

#### What we got ?
- First, try to connect with the server via netcat, it will return to a set of hex value
![no text here]()
