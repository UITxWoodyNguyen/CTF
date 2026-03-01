fn = 'uvt_crackme_work/stage2/void/zen_void.bin'
data = open(fn, 'rb').read()
# Islands identified by scanning for runs of non-zero bytes:
islands = [
    (0x2345, 0x234b),
    (0x234d, 0x2350),
    (0x9550, 0x9557),
    (0x9d20, 0x9d27),
    (0xa1b2, 0xa1b9),
    (0xe3c4, 0xe3ca),
]