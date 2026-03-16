import argparse
import re
import socket
import time
from pathlib import Path
from typing import Optional, Tuple

HOST = "challenge.utctf.live"
PORT = 7255
PLAY_PROMPT = "Play a hand? (y to play / n to exit / t to toggle Unicode suits [currently on]):"
ACTION_PREFIX = "Action ("


def send_line(sock: socket.socket, line: str) -> None:
    sock.sendall((line + "\n").encode())


def recv_until(sock: socket.socket, buf: str, marker: str, timeout: float = 4.0) -> Tuple[str, str]:
    end = time.time() + timeout
    while marker not in buf:
        if time.time() > end:
            raise TimeoutError(f"timeout waiting for marker: {marker}")
        data = sock.recv(4096)
        if not data:
            raise ConnectionError("remote closed")
        buf += data.decode(errors="replace")
    idx = buf.index(marker) + len(marker)
    return buf[:idx], buf[idx:]


def recv_action_prompt(sock: socket.socket, buf: str, timeout: float = 4.0) -> Tuple[str, str]:
    end = time.time() + timeout
    while True:
        idx = buf.find(ACTION_PREFIX)
        if idx != -1:
            colon = buf.find(":", idx)
            if colon != -1:
                prompt = buf[idx : colon + 1]
                return prompt, buf[colon + 1 :]

        if time.time() > end:
            raise TimeoutError("timeout waiting action prompt")

        data = sock.recv(4096)
        if not data:
            raise ConnectionError("remote closed")
        buf += data.decode(errors="replace")


def parse_last_chips(text: str) -> Tuple[Optional[int], Optional[int]]:
    m = re.findall(r"Your chips:\s*(\d+)\s*\|\s*Dealer chips:\s*(\d+)", text)
    if not m:
        return None, None
    y, d = m[-1]
    return int(y), int(d)


def play_to_menu(sock: socket.socket, buf: str, transcript: str, aggressive: bool = False) -> Tuple[str, str]:
    # Keep the hand moving with check/call so showdown can resolve naturally.
    deadline = time.time() + 12.0
    while time.time() < deadline:
        if PLAY_PROMPT in buf:
            cut = buf.index(PLAY_PROMPT) + len(PLAY_PROMPT)
            transcript += buf[:cut]
            buf = buf[cut:]
            return buf, transcript

        idx = buf.find(ACTION_PREFIX)
        if idx != -1:
            colon = buf.find(":", idx)
            if colon != -1:
                prompt = buf[idx : colon + 1]
                transcript += buf[: colon + 1]
                buf = buf[colon + 1 :]
                if "check" in prompt:
                    send_line(sock, "check")
                elif "call" in prompt:
                    send_line(sock, "call")
                else:
                    send_line(sock, "fold")
                continue

        try:
            data = sock.recv(4096)
        except (TimeoutError, socket.timeout):
            continue

        if not data:
            break
        chunk = data.decode(errors="replace")
        buf += chunk
        transcript += chunk

    raise TimeoutError("did not return to play menu in time")


def single_attempt(name: str, aggressive: bool = False, max_hands: int = 2) -> Tuple[bool, str, Tuple[Optional[int], Optional[int]]]:
    transcript = ""
    with socket.create_connection((HOST, PORT), timeout=8) as sock:
        sock.settimeout(1.5)
        buf = ""

        # Login
        chunk, buf = recv_until(sock, buf, "Enter your name:")
        transcript += chunk
        send_line(sock, name)

        # Menu -> start hand 1
        chunk, buf = recv_until(sock, buf, PLAY_PROMPT)
        transcript += chunk
        send_line(sock, "y")

        # Hand 1: force near all-in from SB spot
        prompt, buf = recv_action_prompt(sock, buf)
        transcript += prompt
        if "call 10 / raise <n> / fold" in prompt:
            send_line(sock, "raise 480")
        elif "check / raise <n> / fold" in prompt:
            send_line(sock, "raise 480")
        else:
            send_line(sock, "fold")

        # Finish hand 1 and return to menu
        buf, transcript = play_to_menu(sock, buf, transcript, aggressive=aggressive)
        y1, d1 = parse_last_chips(transcript)

        y2, d2 = y1, d1
        hands_played = 1
        while hands_played < max_hands:
            if (y2, d2) == (1000, 0):
                break
            if y2 is None or d2 is None:
                break
            if y2 <= 0 or d2 <= 0:
                break

            send_line(sock, "y")
            buf, transcript = play_to_menu(sock, buf, transcript, aggressive=aggressive)
            y2, d2 = parse_last_chips(transcript)
            hands_played += 1

        # Exit cleanly
        send_line(sock, "n")
        end = time.time() + 1.0
        while time.time() < end:
            try:
                data = sock.recv(4096)
            except (TimeoutError, socket.timeout):
                break
            if not data:
                break
            transcript += data.decode(errors="replace")

    return (y2, d2) == (1000, 0), transcript, (y1, d1)


def main() -> int:
    parser = argparse.ArgumentParser(description="Retry remote sessions until chips become exactly 1000-0")
    parser.add_argument("--attempts", type=int, default=400, help="Maximum sessions to try")
    parser.add_argument("--aggressive", action="store_true", help="Use more assertive line selection and play extra hands")
    parser.add_argument("--max-hands", type=int, default=2, help="Maximum hands to play per session")
    parser.add_argument(
        "--save",
        type=Path,
        default=Path("blind/1000_0_transcript.txt"),
        help="Where to save the successful transcript",
    )
    args = parser.parse_args()

    for i in range(1, args.attempts + 1):
        try:
            ok, transcript, hand1 = single_attempt(
                name=f"hunt{i}",
                aggressive=args.aggressive,
                max_hands=max(2, args.max_hands),
            )
            y, d = parse_last_chips(transcript)
            print(f"[attempt {i}] hand1={hand1} final={y}-{d}")
            if ok:
                args.save.parent.mkdir(parents=True, exist_ok=True)
                args.save.write_text(transcript, encoding="utf-8")
                print(f"[+] Hit target 1000-0 on attempt {i}")
                print(f"[+] Saved transcript to {args.save}")
                return 0
        except Exception as exc:
            print(f"[attempt {i}] error: {exc}")
            time.sleep(0.08)

    print("[!] END")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())