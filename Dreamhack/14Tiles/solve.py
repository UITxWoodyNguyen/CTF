#!/usr/bin/env python3
"""
14Tiles CTF Solver

The challenge works as follows:
- 32 tiles are created: 4 copies each of tile types 0-7
- They're Fisher-Yates shuffled using /dev/urandom
- First 13 tiles are displayed as a histogram (tile counts)
- We must identify which tile(s) 0-7, when added to the 13-tile hand, form a
  complete winning mahjong hand: 4 melds (triplet or sequence) + 1 pair
- Or answer "None" if no such tile exists
- Repeat 100 times correctly to get the flag
"""

from pwn import *


def _solve(counts, melds, pairs):
    """
    Recursive mahjong hand validator.
    Checks if 'counts' can be broken into 'melds' melds + 'pairs' pairs.
    Melds: triplet (3 same) or sequence (3 consecutive).
    """
    if melds == 0 and pairs == 0:
        return True

    if melds > 0:
        # Try removing a triplet
        for i in range(8):
            if counts[i] >= 3:
                counts[i] -= 3
                if _solve(counts, melds - 1, pairs):
                    counts[i] += 3
                    return True
                counts[i] += 3

        # Try removing a sequence (3 consecutive tile types)
        for i in range(6):
            if counts[i] > 0 and counts[i+1] > 0 and counts[i+2] > 0:
                counts[i] -= 1; counts[i+1] -= 1; counts[i+2] -= 1
                if _solve(counts, melds - 1, pairs):
                    counts[i] += 1; counts[i+1] += 1; counts[i+2] += 1
                    return True
                counts[i] += 1; counts[i+1] += 1; counts[i+2] += 1

        return False

    # melds == 0, try removing pairs
    for i in range(8):
        if counts[i] >= 2:
            counts[i] -= 2
            if _solve(counts, 0, pairs - 1):
                counts[i] += 2
                return True
            counts[i] += 2

    return False


def is_winning(counts):
    """Check if 14-tile hand is a winner (4 melds + 1 pair)."""
    return _solve(list(counts), 4, 1)


def solve_hand(counts):
    """
    Given the 13-tile hand (counts[0..7]), find all tiles that complete it.
    Returns a string of digit chars, or 'None'.
    """
    answers = []
    for tile in range(8):
        if counts[tile] >= 4:
            continue  # Already 4 of this tile, can't draw more
        counts[tile] += 1
        if is_winning(counts):
            answers.append(str(tile))
        counts[tile] -= 1
    return ''.join(answers) if answers else 'None'


def parse_tiles(data):
    """
    Extract the 13-tile string from the round output.
    The binary prints: '   ' + (digits) + '   \n-----...'
    So we look for digits between the header and 'Your answer?'
    """
    counts = [0] * 8
    # Find lines between '------ [Tiles]' and '-----' separator
    in_tiles = False
    for line in data.split('\n'):
        if '[Tiles]' in line:
            in_tiles = True
            continue
        if in_tiles and '---' in line:
            break
        if in_tiles:
            for ch in line:
                if ch.isdigit() and int(ch) < 8:
                    counts[int(ch)] += 1
    return counts


def main():
    host = 'host3.dreamhack.games'
    port = 18933

    r = remote(host, port)

    for round_num in range(1, 101):
        data = r.recvuntil(b'Your answer?\n').decode(errors='replace')

        counts = parse_tiles(data)
        total = sum(counts)

        if total != 13:
            log.warning(f"Round {round_num}: unexpected tile count={total}, counts={counts}")
            log.warning(f"Raw data:\n{data}")

        answer = solve_hand(counts)
        log.info(f"Round {round_num:3d}: counts={counts} -> {answer}")
        r.sendline(answer.encode())

    # Receive flag
    r.interactive()


if __name__ == '__main__':
    main()
