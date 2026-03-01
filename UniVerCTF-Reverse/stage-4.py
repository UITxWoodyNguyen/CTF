expected = [0xD7, 0xD1, 0xA7, 0xED, 0x54, 0x39, 0x68, 0x49]
result = []
for i in range(8):
    e = expected[i]
    # e = ((0xA7 - i*0xB) XOR input[i]) + i*3
    # => (0xA7 - i*0xB) XOR input[i] = (e - i*3) & 0xFF
    transformed = (e - i*3) & 0xFF
    result.append(transformed ^ ((0xA7 - i*0xB) & 0xFF))
print(bytes(result))   # => b'pR0b3Z3n'