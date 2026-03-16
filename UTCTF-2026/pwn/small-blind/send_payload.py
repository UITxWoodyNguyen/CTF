import argparse
import re
import socket
import time
from pathlib import Path


DEFAULT_HOST = "challenge.utctf.live"
DEFAULT_PORT = 7255
ENTER_PROMPT = "Enter your name:"
PLAY_PROMPT = "Play a hand?"
ACTION_PROMPT = "Action ("


def recv_some(sock: socket.socket, timeout: float) -> str:
    sock.settimeout(timeout)
    chunks = []
    while True:
        try:
            data = sock.recv(4096)
        except (TimeoutError, socket.timeout):
            break
        if not data:
            break
        chunks.append(data)
        if len(data) < 4096:
            break
    return b"".join(chunks).decode(errors="replace")


def send_line(sock: socket.socket, line: str) -> None:
    sock.sendall((line + "\n").encode())


def wait_for_marker(sock: socket.socket, marker: str, timeout: float, transcript: str) -> tuple[bool, str]:
    end = time.time() + timeout
    buf = transcript
    while time.time() < end:
        if marker in buf:
            return True, buf
        piece = recv_some(sock, timeout=0.35)
        if piece:
            buf += piece
    return marker in buf, buf


def extract_summary(transcript: str) -> str:
    welcome = re.search(r"Welcome to the table, (.*?)!", transcript, re.S)
    chips = re.findall(r"Your chips:\s*(\d+)\s*\|\s*Dealer chips:\s*(\d+)", transcript)
    parts = []
    if welcome:
        w = welcome.group(1).replace("\n", " ").strip()
        if len(w) > 80:
            w = w[:77] + "..."
        parts.append(f"welcome={w!r}")
    if chips:
        y, d = chips[-1]
        parts.append(f"chips={y}-{d}")
    if "{" in transcript and "}" in transcript:
        m = re.search(r"[A-Za-z0-9_]*\{[^\n{}]+\}", transcript)
        if m:
            parts.append(f"flag={m.group(0)}")
    return " | ".join(parts) if parts else "no-summary"


def run_single(
    host: str,
    port: int,
    name_payload: str,
    queued_lines: list[str],
    auto_next: bool,
    timeout: float,
) -> tuple[int, str]:
    transcript = ""
    queue = list(queued_lines)

    with socket.create_connection((host, port), timeout=8) as sock:
        sock.settimeout(1.2)

        ok, transcript = wait_for_marker(sock, ENTER_PROMPT, timeout, transcript)
        if not ok:
            return 1, transcript

        send_line(sock, name_payload)
        print(f"[send:name] {name_payload}")

        # Read response right after name payload.
        transcript += recv_some(sock, timeout=1.0)

        if auto_next and queue:
            end = time.time() + timeout
            while queue and time.time() < end:
                # Keep pulling output until one of the prompts appears.
                transcript += recv_some(sock, timeout=0.4)
                if PLAY_PROMPT in transcript or ACTION_PROMPT in transcript:
                    line = queue.pop(0)
                    send_line(sock, line)
                    print(f"[send] {line}")
                    transcript += recv_some(sock, timeout=0.8)

        elif queue:
            # Non-auto mode: send all queued lines immediately.
            for line in queue:
                send_line(sock, line)
                print(f"[send] {line}")
                transcript += recv_some(sock, timeout=0.8)

        # Final drain.
        transcript += recv_some(sock, timeout=1.0)

    return 0, transcript


def main() -> int:
    parser = argparse.ArgumentParser(description="Send payloads to poker service and capture transcript")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Target host")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Target port")
    parser.add_argument("--name", default=None, help="Payload to send as name")
    parser.add_argument(
        "--batch-name",
        action="append",
        default=[],
        help="Batch mode: payload as name (repeat this flag for multiple payloads)",
    )
    parser.add_argument(
        "--send",
        action="append",
        default=[],
        help="Additional lines to send after login (can be repeated, e.g. --send y --send n)",
    )
    parser.add_argument(
        "--auto-next",
        action="store_true",
        help="Send queued --send lines when Play/Action prompt appears",
    )
    parser.add_argument(
        "--auto-exit",
        action="store_true",
        help="Ensure command 'n' is queued (useful in batch mode)",
    )
    parser.add_argument("--timeout", type=float, default=8.0, help="Overall wait timeout per stage")
    parser.add_argument("--save", type=Path, default=None, help="Optional file path to save full transcript")
    args = parser.parse_args()

    payloads: list[str] = []
    if args.name is not None:
        payloads.append(args.name)
    payloads.extend(args.batch_name)

    if not payloads:
        print("[-] Provide --name or at least one --batch-name")
        return 2

    queue = list(args.send)
    if args.auto_exit and "n" not in queue:
        queue.append("n")

    if len(payloads) == 1:
        rc, transcript = run_single(
            host=args.host,
            port=args.port,
            name_payload=payloads[0],
            queued_lines=queue,
            auto_next=args.auto_next,
            timeout=args.timeout,
        )
        if rc != 0:
            print("[-] Did not receive name prompt")
            print(transcript[-1000:])
            return rc

        if args.save is not None:
            args.save.parent.mkdir(parents=True, exist_ok=True)
            args.save.write_text(transcript, encoding="utf-8")
            print(f"[+] Saved transcript to {args.save}")

        print("\n===== Transcript Tail =====")
        print(transcript[-2500:])
        return 0

    save_dir = args.save
    if save_dir is not None:
        save_dir.parent.mkdir(parents=True, exist_ok=True)

    ok_count = 0
    print(f"[*] Batch mode: {len(payloads)} payload(s)")
    for idx, payload in enumerate(payloads, start=1):
        print(f"\n=== [{idx}/{len(payloads)}] payload={payload!r} ===")
        try:
            rc, transcript = run_single(
                host=args.host,
                port=args.port,
                name_payload=payload,
                queued_lines=queue,
                auto_next=args.auto_next,
                timeout=args.timeout,
            )
        except Exception as exc:
            print(f"[!] error: {exc}")
            continue

        if rc != 0:
            print("[-] no name prompt")
            continue

        ok_count += 1
        print(f"[summary] {extract_summary(transcript)}")

        if save_dir is not None:
            out_path = save_dir.with_name(f"{save_dir.stem}_{idx}{save_dir.suffix or '.txt'}")
            out_path.write_text(transcript, encoding="utf-8")
            print(f"[+] saved {out_path}")

    print(f"\n[*] Batch done: {ok_count}/{len(payloads)} succeeded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())