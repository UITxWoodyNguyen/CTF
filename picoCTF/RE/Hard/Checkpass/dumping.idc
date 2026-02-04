#include <idc.idc>

static main() {
    auto i;
    auto addr;
    
    // Print pbox
    Message("pbox = [");
    addr = 0x39970;
    for (i = 0; i < 1024; i++) {
        Message("%d", Byte(addr + i));
        if (i < 1023) Message(", ");
    }
    Message("]\n");
    
    // Print expected
    Message("expected = [");
    addr = 0x39D95;
    for (i = 0; i < 32; i++) {
        Message("%d", Byte(addr + i));
        if (i < 31) Message(", ");
    }
    Message("]\n");
}
