from ctypes import CDLL, cdll
import platform

# Mảng check từ binary
check = [
    0x244B28BE, 0x0AF77805, 0x110DFC17, 0x07AFC3A1, 0x6AFEC533,
    0x4ED659A2, 0x33C5D4B0, 0x286582B8, 0x43383720, 0x055A14FC,
    0x19195F9F, 0x43383720, 0x63149380, 0x615AB299, 0x6AFEC533,
    0x6C6FCFB8, 0x43383720, 0x0F3DA237, 0x6AFEC533, 0x615AB299,
    0x286582B8, 0x055A14FC, 0x3AE44994, 0x06D7DFE9, 0x4ED659A2,
    0x0CCD4ACD, 0x57D8ED64, 0x615AB299, 0x22E9BC2A
]

# Load thư viện C
if platform.system() == "Windows":
    libc = cdll.msvcrt
else:
    libc = CDLL("libc.so.6")

flag = ""
for i in range(29):
    found = False
    for c in range(256):  # thử tất cả giá trị byte
        libc.srand(c)
        if libc.rand() == check[i]:
            flag += chr(c)
            found = True
            break
    if not found:
        flag += "?"

print(f"Flag: {flag}")
