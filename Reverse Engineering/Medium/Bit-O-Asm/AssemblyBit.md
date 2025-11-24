# Bit-O-Asm

### Information
* Category: Reverse Engineering
* Point:
* Level: Medium

### Description
Can you figure out what is in the eax register? Put your answer in the picoCTF flag format: `picoCTF{n}` where n is the contents of the eax register in the decimal number base. If the answer was `0x11` your flag would be `picoCTF{17}`.

## Bit 1
### Hint
As with most assembly, there is a lot of noise in the instruction dump. Find the one line that pertains to this question and don't second guess yourself!

### Solution
#### What we got ?
- Check the assembly file:
    ```assembly
    <+0>:     endbr64 
    <+4>:     push   rbp
    <+5>:     mov    rbp,rsp
    <+8>:     mov    DWORD PTR [rbp-0x4],edi
    <+11>:    mov    QWORD PTR [rbp-0x10],rsi
    <+15>:    mov    eax,0x30
    <+20>:    pop    rbp
    <+21>:    ret
    ```

#### How to get the flag ?
- We can find the hex value `0x30` at `<+15>`. Try to get the decimal value `0x30 = 48`. So the flag is `picoCTF{48}`

---

## Bit 2
### Hint
`PTR`'s or 'pointers', reference a location in memory where values can be stored.

### Solution
#### What we got ?
- Check the assembly file:
    ```assembly
    <+0>:     endbr64 
    <+4>:     push   rbp
    <+5>:     mov    rbp,rsp
    <+8>:     mov    DWORD PTR [rbp-0x14],edi
    <+11>:    mov    QWORD PTR [rbp-0x20],rsi
    <+15>:    mov    DWORD PTR [rbp-0x4],0x9fe1a
    <+22>:    mov    eax,DWORD PTR [rbp-0x4]
    <+25>:    pop    rbp
    <+26>:    ret
    ```

#### How to get the flag ?
- We observed that, at `<+15>`, the function stored `0x9f1a` at `[rbp-0x]`.
- At `<+22>`, it loads the same value into `eax`. 
- So the decimal value of `0x91fa` is the flag. Flag is `picoCTF{655130}`.

---

## Bit 3
### Hint
Not everything in this disassembly listing is optimal.

### Solution
#### What we got ?
- Check the assembly file:
    ```assembly
    <+0>:     endbr64 
    <+4>:     push   rbp
    <+5>:     mov    rbp,rsp
    <+8>:     mov    DWORD PTR [rbp-0x14],edi
    <+11>:    mov    QWORD PTR [rbp-0x20],rsi
    <+15>:    mov    DWORD PTR [rbp-0xc],0x9fe1a
    <+22>:    mov    DWORD PTR [rbp-0x8],0x4
    <+29>:    mov    eax,DWORD PTR [rbp-0xc]
    <+32>:    imul   eax,DWORD PTR [rbp-0x8]
    <+36>:    add    eax,0x1f5
    <+41>:    mov    DWORD PTR [rbp-0x4],eax
    <+44>:    mov    eax,DWORD PTR [rbp-0x4]
    <+47>:    pop    rbp
    <+48>:    ret
    ```

#### How to get the flag ?
- From the assembly file, we observed that at `<+29>`, a value is loading into `eax` from `[rbp-0xc]`.
- So, let's find out the `[rbp-0xc]`, we find it at `<+15>` and its value is `0x9fe1a`.
- The next line is `imul   eax,DWORD PTR [rbp-0x8]`, which means multiple `eax` with `DWORD` at `[rbp-0x8]`. Find out the `[rbp-0x8]`, it locates at `<+22>` and its value is `0x4`. So, the operation is `0x9fe1a * 0x4`.
- The next line is `add    eax,0x1f5`, which means add `0x1f5` into `eax`. Now, the operation is `0x9fe1a * 0x4 + 0x1f5`.
- Next 2 lines is:
    ```assembly
    mov    DWORD PTR [rbp-0x4],eax
    mov    eax,DWORD PTR [rbp-0x4]
    ```
- We can see that, it not change the value of `eax`, since the value is loaded from `eax` to `DWORD`, then loaded back again.
- Calculate the opt and get the flag. Flag is `picoCTF{2619997}`

## Bit 4
### Hint
- Don't tell anyone I told you this, but you can solve this problem without understanding the compare/jump relationship.
- Of course, if you're really good, you'll only need one attempt to solve this problem.

### Solution
#### What we got ?
- Check the assembly file:
```assembly
<+0>:     endbr64 
<+4>:     push   rbp
<+5>:     mov    rbp,rsp
<+8>:     mov    DWORD PTR [rbp-0x14],edi
<+11>:    mov    QWORD PTR [rbp-0x20],rsi
<+15>:    mov    DWORD PTR [rbp-0x4],0x9fe1a
<+22>:    cmp    DWORD PTR [rbp-0x4],0x2710
<+29>:    jle    0x55555555514e <main+37>
<+31>:    sub    DWORD PTR [rbp-0x4],0x65
<+35>:    jmp    0x555555555152 <main+41>
<+37>:    add    DWORD PTR [rbp-0x4],0x65
<+41>:    mov    eax,DWORD PTR [rbp-0x4]
<+44>:    pop    rbp
<+45>:    ret
```

#### How to get the flag ?
- Here is the explanation of the assembly file:

    - `<+15>:    mov    DWORD PTR [rbp-0x4],0x9fe1a`: Load `value = 0x9fe1a` into `DWORD`. Now, `DWORD = 0x9fe1a (= 654,874 (dec))`
    - `<+22>:    cmp    DWORD PTR [rbp-0x4],0x2710`: compare `DWORD = 0x9fe1a` with `right_opt = 0x2710 (= 10,000(dec))`. If `DWORD <= right_opt`, do `<+29>:    jle    0x55555555514e <main+37>`, means jump into the `<main+37>` to `add    DWORD PTR [rbp-0x4],0x65` (add `0x65 = 101` into `DWORD`).
    - If not, continue and `<+31>:    sub    DWORD PTR [rbp-0x4],0x65` (sub `0x65 = 101` into `DWORD`).
    - `<+35>:    jmp    0x555555555152 <main+41>` is the uncondition jump, so we can skip.
    - `<+41>:    mov    eax,DWORD PTR [rbp-0x4]`: load `DWORD` into `eax`.

- Base on the explanation, we observed the final operation to get the final hex value is `0x9fe1a - 0x65` = `654,874 - 101 = 654,773`.
So the flag is `picoCTF{654773}`.
