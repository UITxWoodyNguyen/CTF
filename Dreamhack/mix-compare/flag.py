result = [57, -101, 44, 198, 89, 88, 57, 171, -50, 198, 396, 400, -38, 115, 82, 102, -85, -81, -39, -83, -82, -80, -78, -32, -30, -31, 79, 83, 76, 83, 79, 87, 131, 84, 89, 135, 12, 19, 62, 59, 62, 57, 58, 56, 13, 52, 2392, 2350, 2592, 4851, 2800, 5202, 2964, 5300, 2646, 2970, 99, 95, 143, 89, 140, 137, 140, 85]

flag = ''

for i in range(64):
    if i < 16:
        if i == 0:
            flag += '0'
        elif i == 1:
            flag += 'd'
        elif i == 2:
            flag += '0'
        elif i == 3:
            flag += 'c'
        elif i == 4:
            flag += '7'
        elif i == 5:
            flag += '0'
        elif i == 6:
            flag += 'a'
        elif i == 7:
            flag += '9'
        elif i == 8:
            flag += '1'
        elif i == 9:
            flag += 'c'
        elif i == 10:
            flag += 'c'
        elif i == 11:
            flag += 'd'
        elif i == 12:
            flag += '9'
        elif i == 13:
            flag += 'b'
        elif i == 14:
            flag += '4'
        elif i == 15:
            flag += 'f'
    elif i < 26:
        r = result[i]
        y = r - i
        lower = y if y >= 0 else 256 + y
        x = (~lower) & 0xFF
        flag += chr(x)
    elif i < 36:
        flag += chr(result[i] - i)
    elif i < 46:
        flag += chr(result[i] + i)
    elif i < 56:
        flag += chr(result[i] // i)
    else:
        flag += chr(result[i] - 100 + i)

print(len(flag))
print(repr(flag))