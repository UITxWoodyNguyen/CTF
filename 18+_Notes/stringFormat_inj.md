A **Format String Attack** occurs when an application processes user-supplied input as a **format string** for a function like `printf`, `fprintf`, or `sprintf` without proper validation.

The core vulnerability is that these format functions expect arguments on the stack that correspond to the **format parameters** (like `%x`, `%s`, `%n`) present in the format string. If an attacker injects these parameters into the input string, the function will try to read or write data from the program's **stack** or **memory** to fulfill the request.

Here is a summary of the attack, its components, and its consequences:

***

## 1. Description of the Attack

The exploit happens when the submitted data is mistakenly evaluated as a **command** by the application's format function.

**Consequences of a Format String Attack:**

* **Execute Code:** The attacker can potentially execute arbitrary code on the system.
* **Read the Stack/Memory:** They can read data from the program's stack (using `%x` or `%p`) to leak sensitive information, or read process memory (using `%s`).
* **Write to Memory:** They can write arbitrary integer values to specific memory locations (using `%n`), which is often the key step in achieving arbitrary code execution.
* **Cause a Segmentation Fault/Denial of Service (DoS):** By supplying too many format parameters, the function may attempt to read an invalid memory address, causing the program to crash.

## 2. Key Components

* **Format Function:** An ANSI C conversion function, such as `printf`, `fprintf`, `sprintf`, or `snprintf`, that converts variables into a human-readable string.
* **Format String:** The argument of the format function, which contains regular text and format parameters.
    * *Example of safe use:* `printf("The user's name is: %s\n", userName);`
* **Format String Parameter:** Directives like `%d`, `%x`, `%s`, or `%n` that define the type of conversion the function should perform.

## 3. How the Attack Works (Vulnerable vs. Safe Code)

The vulnerability arises when a developer uses a variable containing user input directly as the *format string* argument, instead of treating it as a literal string to be printed.

| Scenario | Example Code | Security Implication |
| :--- | :--- | :--- |
| **Vulnerable Code** | `printf(userName);` | The program interprets the content of `userName` (the user input) as the **format string**. If the user inputs `%x`, the function will read an integer value off the stack. |
| **Safe Code** | `printf("%s", userName);` | The program treats the input `userName` as a literal string argument (`%s`) and safely prints it. Any format parameters in `userName` are printed as regular text and are **not** interpreted as commands. |

## 4. Format Parameters Used in Attacks

Attackers use specific format parameters to achieve different goals:

| Parameter | Function | Attack Goal |
| :--- | :--- | :--- |
| **`%x` or `%p`** | Reads a hexadecimal value or a pointer. | **Information Leakage:** Reads data off the program's stack. |
| **`%s`** | Reads a character string from memory at the address provided on the stack. | **Information Leakage:** Reads arbitrary data from the process's memory. |
| **`%n`** | Writes the number of characters printed so far into a location in the process's memory (as a pointer on the stack). | **Memory Write/Code Execution:** This is the most dangerous parameter, as it allows attackers to write values to memory, often hijacking program control flow. |

## 5. Mitigation

The primary defense is **Input Validation** and, more specifically, ensuring that user-controlled strings are **never** used directly as the format string argument for functions like `printf`.

The fix is to always use a fixed, constant format string like `"%s"` to safely print user-supplied data:

* **Vulnerable:** `printf(input_buffer);`
* **Safe:** `printf("%s", input_buffer);`
