data = bytes([0x7a,0x2e,0x6e,0x68,0x1d,0x65,0x16,0x7c,0x6d,0x43,0x6f,0x36,0x36,0x62,0x1a,0x45,0x43,0x32,0x40,0x61,0x58,0x01,0x58,0x65,0x62,0x66,0x53,0x30,0x3b,0x17])
# Hàm reverse shuffle (nghịch đảo của forward shuffle)
def swap_elements(arr,length,stride):
    i=0
    while True:
        result = length - stride + 1
        if i >= result: break
        a=i; b=i+stride-1
        arr[a],arr[b] = arr[b],arr[a]
        i += stride

def shuffle_reverse(b):
    arr = list(b)
    for s in range(len(arr)-1,0,-1):
        swap_elements(arr,len(arr),s)
    return bytes(arr)

R = shuffle_reverse(data)

# XOR multi-pass (theo code): từ 180154381, step 2075469, tới < 0xDEADBEEF
start = 180154381
end = 0xDEADBEEF
step = 2075469
n = len(R)
aligned_size = (n & 0xFFFFFFFC) + 4
aligned = bytearray(R + b"\x00"*(aligned_size-n))
for key in range(start, end, step):
    kb = [(key >> 24) & 0xFF, (key >> 16) & 0xFF, (key >> 8) & 0xFF, key & 0xFF]
    for i in range(aligned_size):
        aligned[i] ^= kb[i % 4]

flag = bytes(aligned[:n]).decode()
print(flag)