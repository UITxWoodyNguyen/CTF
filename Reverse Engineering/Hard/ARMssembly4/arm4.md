# breadth

### Information
* Category: RE
* Point:
* Level: Hard

### Description
What integer does this program print with argument `1151828495`? File: chall_4.S Flag format: `picoCTF{XXXXXXXX}` -> (hex, lowercase, no 0x, and 32 bits. ex. `5614267` would be `picoCTF{0055aabb}`)

### Hint
None

### Solution
#### What we got ?
- The problem gives us a [assembler src code](). And we need to run this raw src code with the input `1151828495`, then convert the output into hex, lowercase, no 0x, and 32 bits to get the flag.

#### How to get the flag ?

##### About function boundaries
- First, we observed that every ARM AArch64 often starts with something like:
    ```csharp
    stp x29, x30, [sp, -X]!
    add x29, sp, 0
    ```

    And ending with:
    ```csharp
    ldp x29, x30, [sp], X
    ret
    ```

    This means function will begin at its label and ends at `ret`. These boundaries will give you one function per blocks.

##### Decode the Stack frame
- Assembly uses stack for local variables. For example:
    ```
    str w0, [x29, 28]
    ldr w0, [x29, 28]
    ```

- Means:

    - local variable located at `[x29 + 28]`
    - stores argument `x`

- Conventionally, in C this becomes:
    ```c
    int local = x;
    ```

##### Track Register
- AArch64 calling convention:

    * `w0/x0` → 1st argument, also return value
    * `w1/x1` → 2nd argument
    * functions return results in `w0/x0`

- So:

    ```csharp
    ldr w0, [x29, 28]
    bl func2
    ```

    means:

    - load argument
    - call `func2(argument)`
    - return its result

- This maps directly into:
    ```c
    return func2(local);
    ```

##### Reconstuct Control Flow
- Branches like:
    ```csharp
    cmp w0, 100
    bls .L2
    ```

    will turn into:

    ```c
    if (x <= 100) {
        // L2 block
    } else {
        // fall-through block
    }
    ```

- Loops use patterns like:
    ```csharp
    cmp w0, limit
    bls .L15
    ```

    which becomes:

    ```c
    while (counter <= limit) {
        ...
    }
    ```
##### Recognize Arithmetic Patterns

- Assembly:
    
    ```
    add w0, w0, 100
    sub w0, w0, #86
    mul w0, w1, w0
    udiv w2, w0, w1
    ```

    translates directly to C operators:

    ```c
    x = x + 100;
    x = x - 86;
    x = a * b;
    q = a / b;   // unsigned division
    ```

##### Rebuild Function Calls

When you see:

```
bl func5
```

you replace it in C with:

```c
func5(x);
```

Registers holding arguments (`w0`, `w1`, …) become C function parameters.

##### Conclusion:
Base on all the analyze, we have the final src code:
```c
#include <stdio.h>
#include <stdlib.h>

int func1(int x);
int func2(int x);
int func3(int x);
int func4(int x);
int func5(int x);
int func6(int x);
int func7(int x);
int func8(int x);

int func1(int x) {
    if (x > 100) {
        return func2(x + 100);
    } else {
        return func3(x);
    }
}

int func2(int x) {
    if (x <= 499) {
        return func4(x - 86);
    } else {
        return func5(x + 13);
    }
}

int func3(int x) {
    return func7(x);
}

int func4(int x) {
    int tmp = 17;
    tmp = func1(tmp);
    return x;
}

int func5(int x) {
    x = func8(x);
    return x;
}

int func6(int x) {
    int a = x;
    int b = 314;
    int c = 1932;
    int counter = 0;

    while (counter <= 899) {
        int temp = c * 800;
        int q = temp / b;
        int r = temp - (q * b);
        a = r;
        counter++;
    }
    return a;
}

int func7(int x) {
    if (x <= 100) return 7;
    return x;
}

int func8(int x) {
    return x + 2;
}

int main(void) {
    int val = 1151828495;   // <-- fixed input inserted here

    int result = func1(val);

    printf("Result: %ld\n", (long)result);
    return 0;
}
```
