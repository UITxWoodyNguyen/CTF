# ✅ Why the offsets differ between `radiff2` and IDA

There are **three main reasons**:

---

## **1. radiff2 uses *file offsets*; decompilers use *virtual addresses (VMA)***

This is the most common cause.

* `radiff2 -u` often reports **file offset (in the raw binary file)**
* Ghidra / IDA / Binary Ninja show **virtual memory addresses** (where the code is loaded in memory)

Because of section alignment, padding, and loader rules:

> **File offset ≠ Virtual address**

So `0x9504E` in the file may correspond to `0x95040` when loaded.

---

## **2. radiff2 reports the exact byte that changed, not the start of the instruction**

`radiff2` works at **byte-level**, not instruction-level.

Example:

* Instruction starts at **0x95040**
* It is, say, 16 bytes long and ends at **0x9504F**
* Only one byte inside it changed, e.g., at **0x9504E**

Then:

* **radiff2 shows:** `@@ 0x0009504e @@`
* **Decompiler still shows the instruction beginning at:** `0x00095040`

→ This is normal.
→ radiff2 highlights the exact changed byte.
→ Decompiler highlights the whole instruction.

---

## **3. Decompilers “canonicalize” instructions**

Decompilers always display the **start address of the instruction**, even if the difference is inside the instruction.

For example:

* radiff2 highlights a change at byte 14 of the instruction
* disassembler still prints the instruction at the start address

---

# 🔍 Example scenario

Instruction range:

```
0x95040 → 0x9504F
```

Change occurs at:

```
0x9504E
```

Results:

| Tool           | Shows                       |
| -------------- | --------------------------- |
| **radiff2**    | 0x9504E (byte changed)      |
| **IDA/Ghidra** | 0x95040 (instruction start) |

Both are correct—they just show **different levels of granularity**.

---

# 📌 Summary

**radiff2 reports the exact changed byte.
Decompilers report the start of the instruction containing the byte.
Also FO and VMA may differ.**

This is why you see:

* radiff2 → `0x0009504E`
* decompiler → `0x00095040`
