import socket
import random

def untemper(y):
    y ^= y >> 18
    y ^= (y << 15) & 0xEFC60000
    for i in range(7):
        y ^= ((y << 7) & 0x9D2C5680)
    for i in range(3):
        y ^= y >> 11
    return y & 0xFFFFFFFF

def clone_mt(outputs):
    state = [untemper(o) for o in outputs[:624]]
    state.append(624)
    return (3, tuple(state), None)

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('chall.0xfun.org', 45386))
    s.settimeout(10)
    s.recv(1024)
    
    # Thu thập 624 outputs
    outputs = []
    for i in range(624):
        s.send(b'spin\n')
        data = b''
        while b'\n' not in data:
            data += s.recv(1024)
        line = data.split(b'\n')[0].strip().decode()
        if '>' in line:
            line = line.replace('>', '').strip()
        obfuscated = int(line)
        raw = obfuscated ^ 0xCAFEBABE
        outputs.append(raw)
    
    # Clone MT state
    mt = random.Random()
    mt.setstate(clone_mt(outputs))
    
    # Dự đoán 10 số tiếp theo
    predictions = [mt.getrandbits(32) for _ in range(10)]
    
    # Gửi predict
    s.send(b'predict\n')
    s.recv(1024)
    
    prediction_str = ' '.join(map(str, predictions))
    s.send(prediction_str.encode() + b'\n')
    
    print(s.recv(4096).decode())
    s.close()

if __name__ == "__main__":
    main()