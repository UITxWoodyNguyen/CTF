import socket
import re

def get_spell(target):
    spell = []
    current = target
    while current > 0:
        if current % 2 == 1:
            spell.append('A')
            current -= 1
        else:
            spell.append('B')
            current //= 2
    return ''.join(reversed(spell))

def main():
    host = 'host3.dreamhack.games'
    port = 24098  # External port, assuming it's the one to connect to

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))

    buffer = b''
    while True:
        data = s.recv(1024)
        if not data:
            break
        buffer += data
        lines = buffer.split(b'\n')
        buffer = lines[-1]  # Keep incomplete line

        for line in lines[:-1]:
            line = line.decode('utf-8', errors='ignore').strip()
            print(f"Received: {line}")

            # Parse stats
            match = re.search(r'HP:\s*(\d+).*STR:\s*(\d+).*AGI:\s*(\d+).*VIT:\s*(\d+).*INT:\s*(\d+).*END:\s*(\d+).*DEX:\s*(\d+)', line)
            if match:
                HP, STR, AGI, VIT, INT, END, DEX = map(int, match.groups())
                seed = (HP << 48) | (DEX << 40) | (END << 32) | (INT << 24) | (VIT << 16) | (AGI << 8) | STR
                spell = get_spell(seed)
                print(f"Seed: {seed}, Spell: {spell}")
                s.sendall((spell + '\n').encode())
                break

            if 'flag' in line.lower():
                print(f"Flag: {line}")
                return

if __name__ == '__main__':
    main()