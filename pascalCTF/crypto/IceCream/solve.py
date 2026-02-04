import socket
import re
import numpy as np

HOST = 'cramer.ctf.pascalctf.it'
PORT = 5002

# Connect to the remote server
s = socket.create_connection((HOST, PORT))

# Helper to receive until a prompt
recv = b''
while True:
    data = s.recv(4096)
    if not data:
        break
    recv += data
    if b'Solve the system of equations' in recv:
        break

text = recv.decode()

# Extract equations
lines = [line for line in text.splitlines() if '*x_' in line]

# Parse equations
coefs = []
results = []
for line in lines:
    left, right = line.split('=')
    right = int(right.strip())
    terms = left.strip().split('+')
    row = []
    for term in terms:
        m = re.match(r'([\-\d]+)\*x_(\d+)', term.strip())
        row.append(int(m.group(1)))
    coefs.append(row)
    results.append(right)

# Solve the system
A = np.array(coefs)
b = np.array(results)
x = np.linalg.solve(A, b)

# Convert to flag
flag = ''.join(chr(int(round(i))) for i in x)
print('pascalCTF{' + flag + '}')
