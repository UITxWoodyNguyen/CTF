# UTCTF-2026 — pwn

Overview

This directory contains writeups, notes, and exploit scripts for the pwn challenges used in the UTCTF-2026 category. Each challenge lives in its own subfolder and includes a `writeup.md` plus any helper scripts used during exploitation.

Structure (examples)

- `small-blind/` — remote poker service; format-string primitives and write (`%n`) exploitation.
- `rude-guard/` — local binary; stack overflow -> ret-to-`secret_function` exploit.
- `hour-of-joy/` — local binary; format-string leak to recover a hardcoded secret and trigger `print_flag()`.

Quick start

Prerequisites

- Python 3.8+
- Optional: `pwntools` for local exploit automation (`pip install pwntools`)
- `gdb`, `objdump`, `readelf`, `checksec` for static analysis
- `nc` (netcat) for remote interaction (where applicable)

How to use

- Read the challenge writeup:
  - Open the challenge folder and read `writeup.md`.
- Run an exploit script (if provided):

```bash
cd <challenge-folder>
python3 exploit.py
```

- For remote targets, check the writeup for host/port and any CLI flags the exploit supports.

Contributing

- Add a new folder for each challenge with:
  - `writeup.md` — documented analysis and steps
  - `exploit.py` or helper scripts used to reproduce the solve
- Keep code and prose separated: do not edit other challenges without discussion.

Notes and conventions

- Keep exploits idempotent where possible (use timeouts, non-blocking I/O).
- When including binary addresses, mark whether the binary is PIE/non-PIE.
- Prefer to reference exact file paths when describing where to run commands.

License / attribution

This workspace contains personal CTF notes and writeups. Reuse and redistribution should respect authorship and contest rules.
