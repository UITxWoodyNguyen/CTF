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
![Server Respond](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Medium/Quantum_Scrambler/image_1.jpg?raw=true)

- Next, try to analyze the python script:
```python
import sys

def exit():
  sys.exit(0)

def scramble(L):
  A = L
  i = 2
  while (i < len(A)):
    A[i-2] += A.pop(i-1)
    A[i-1].append(A[:i-2])
    i += 1
    
  return L

def get_flag():
  flag = open('flag.txt', 'r').read()
  flag = flag.strip()
  hex_flag = []
  for c in flag:
    hex_flag.append([str(hex(ord(c)))])

  return hex_flag

def main():
  flag = get_flag()
  cypher = scramble(flag)
  print(cypher)

if __name__ == '__main__':
  main()
```

- Throughout this python script:
    
    - First, we look into the `scramble` function: I
    
        - It will take a list `L` and modifies it in place by referencing it as `A`. With each element at index `i` in list `L`, it will `pop` the element at index `i-1`, then add the popped element into the element at index `i-2`.
        - After the list shrinks from the pop operation, the function takes the element now at index `i−1` and calls `.append()` on it, adding a slice of the earlier part of the list (`A[:i−2]`). For this to work, `A[i−1]` must be **a list**, and `A[i−2]` must support `+=` with the popped value.
        ⇨ Overall, the function does an unusual transformation: it merges elements, appends sublists into later elements, and continuously shrinks and reshapes the original list.
    - Next, moving to the `get_flag()` function, it read a file called `“flag.txt”` and then converting the read content to hex value and making a list of those values.

⇨ We can observed that, this python script will read something in a `.txt` file, then convert it into hex value list and scramble that list. Finally, it will return the scramble hex value list.

#### How to get the flag ?
- Try to copy the server's respond into a `.txt` file. 
- The `hex_list_to_text()` function will try to convert hex value to text. For each pair of hex value, try to convert hex value into decimal value, and convert once again into text (except error value).

```python
import ast

def hex_list_to_text(hex_list):
    result = ''
    for pair in hex_list:
        # Đảm bảo pair là list hoặc tuple
        if not isinstance(pair, (list, tuple)):
            continue
        for hx in pair:
            try:
                # Chuyển hex string sang số, rồi sang ký tự
                result += chr(int(hx, 16))
            except (ValueError, TypeError):
                # Bỏ qua nếu không chuyển được
                pass
    return result

def main():
    try:
        with open('raw.txt', 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Chuyển chuỗi đọc được thành list Python
        hex_list = ast.literal_eval(content)
    except Exception as e:
        print(f"Error reading or parsing file: {e}")
        return

    text = hex_list_to_text(hex_list)
    print("Decoded text:")
    print(text)

if __name__ == '__main__':
    main()
```
- Here is the result:
![Result](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Medium/Quantum_Scrambler/image_2.jpg?raw=true)
