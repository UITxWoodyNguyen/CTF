with open('main', 'rb') as f:
    f.seek(0x3020)
    table_data = f.read(450)

for i in range(150):
    col = table_data[i*3]
    row = table_data[i*3 + 1]
    expected = table_data[i*3 + 2]
    if expected == 0:
        break
    pos = col + row * 15
    print(f"pos {pos} (col={col}, row={row}) = {expected}")