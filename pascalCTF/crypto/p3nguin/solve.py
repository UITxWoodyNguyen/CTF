from pwn import *

HOST = 'penguin.ctf.pascalctf.it'
PORT = 5003

words = [
    "biocompatibility", "biodegradability", "characterization", "contraindication",
    "counterbalancing", "counterintuitive", "decentralization", "disproportionate",
    "electrochemistry", "electromagnetism", "environmentalist", "internationality",
    "internationalism", "institutionalize", "microlithography", "microphotography",
    "misappropriation", "mischaracterized", "miscommunication", "misunderstanding",
    "photolithography", "phonocardiograph", "psychophysiology", "rationalizations",
    "representational", "responsibilities", "transcontinental", "unconstitutional"
]

def main():
    r = remote(HOST, PORT)
    
    # Read intro until first prompt
    r.recvuntil(b"Give me 4 words")
    
    # Build ciphertext->word mapping
    cipher_to_word = {}
    
    # We have 7 rounds, each round sends 4 words = 28 words max (we have exactly 28 words)
    for round_num in range(7):
        batch = words[round_num*4:(round_num+1)*4]
        
        # Send 4 words
        for w in batch:
            r.recvuntil(b": ")
            r.sendline(w.encode())
        
        # Get encrypted words
        r.recvuntil(b"Encrypted words: ")
        enc_line = r.recvline().decode().strip()
        encs = enc_line.split()
        
        for w, c in zip(batch, encs):
            cipher_to_word[c] = w
        
        print(f"Round {round_num+1}: mapped {len(batch)} words")
        
        # After last round, the server will show ciphertext and ask for guesses
        if round_num < 6:
            r.recvuntil(b"Give me 4 words")
    
    # Now get the ciphertext line (after 7 rounds, server shows the challenge)
    r.recvuntil(b"Ciphertext: ")
    ct_line = r.recvline().decode().strip()
    challenge_cts = ct_line.split()
    
    print(f"Challenge ciphertexts: {challenge_cts}")
    print(f"Mapping has {len(cipher_to_word)} entries")
    
    # Map ciphertexts to words
    guesses = [cipher_to_word.get(c, None) for c in challenge_cts]
    
    print(f"Guesses: {guesses}")
    
    if None in guesses:
        print("Failed to map all ciphertexts!")
        print("Missing ciphertexts:")
        for c in challenge_cts:
            if c not in cipher_to_word:
                print(f"  {c}")
        r.close()
        return
    
    # Send guesses
    for i, g in enumerate(guesses):
        r.recvuntil(b": ")
        r.sendline(g.encode())
        response = r.recvline().decode().strip()
        print(f"Guess {i+1}: {g} -> {response}")
        if "Wrong" in response:
            print("Wrong guess, exiting.")
            r.close()
            return
    
    # Get the flag
    flag = r.recvall(timeout=2).decode()
    print(f"Flag: {flag}")
    
    r.close()

if __name__ == '__main__':
    main()
