#!/usr/bin/env python3
import argparse

from exploit import run_with_retries


def main():
    parser = argparse.ArgumentParser(description="Brick City Office Space solver")
    parser.add_argument("--mode", choices=["local", "remote"], default="local")
    parser.add_argument("--host", default="")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--retries", type=int, default=5)
    parser.add_argument("--offset", type=int, default=4)
    parser.add_argument("--auto-offset", action="store_true", help="Auto-discover format offset")
    args = parser.parse_args()

    known_offset = None if args.auto_offset else args.offset
    print(
        run_with_retries(
            mode=args.mode,
            host=args.host,
            port=args.port,
            retries=args.retries,
            known_offset=known_offset,
        )
    )


if __name__ == "__main__":
    main()
