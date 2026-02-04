; Attributes: bp-based frame

; int __fastcall main(int argc, const char **argv, const char **envp)
public main
main proc near

var_11C= dword ptr -11Ch
var_118= qword ptr -118h
s= byte ptr -110h
var_8= qword ptr -8

; __unwind {
push    rbp
mov     rbp, rsp
sub     rsp, 120h
mov     rax, fs:28h
mov     [rbp+var_8], rax
xor     eax, eax
mov     eax, 0
call    init
lea     rax, [rbp+s]
mov     edx, 100h       ; n
mov     esi, 0          ; c
mov     rdi, rax        ; s
call    memset

loc_400A40:
mov     eax, 0
call    menu
mov     edi, 10h        ; size
call    malloc
mov     [rbp+var_118], rax
mov     rax, [rbp+var_118]
mov     edx, 10h        ; n
mov     esi, 0          ; c
mov     rdi, rax        ; s
call    memset
mov     rdx, cs:stdin@@GLIBC_2_2_5 ; stream
mov     rax, [rbp+var_118]
mov     esi, 10h        ; n
mov     rdi, rax        ; s
call    fgets
lea     rdx, [rbp+var_11C]
mov     rax, [rbp+var_118]
mov     esi, offset aD  ; "%d"
mov     rdi, rax
mov     eax, 0
call    __isoc99_sscanf
mov     rax, [rbp+var_118]
mov     rdi, rax        ; ptr
call    free
mov     eax, [rbp+var_11C]
cmp     eax, 2
jz      short loc_400AF8

cmp     eax, 3
jz      short loc_400B3E

loc_400B3E:
lea     rax, [rbp+s]
mov     edx, 100h       ; n
mov     esi, 0          ; c
mov     rdi, rax        ; s
call    memset
mov     edi, offset aNoteCleared ; "Note cleared."
call    puts
nop

loc_400AF8:
mov     edi, offset aEnterTheNote ; "Enter the note: "
mov     eax, 0
call    printf
lea     rax, [rbp+s]
mov     edx, 100h       ; nbytes
mov     rsi, rax        ; buf
mov     edi, 0          ; fd
call    read
lea     rax, [rbp+s]
mov     esi, offset reject ; "\n"
mov     rdi, rax        ; s
call    strcspn
mov     [rbp+rax+s], 0
jmp     short loc_400B62

cmp     eax, 1
jz      short loc_400AD8

loc_400AD8:
lea     rax, [rbp+s]
mov     rdi, rax        ; format
mov     eax, 0
call    printf
mov     edi, 0Ah        ; c
call    putchar
jmp     short loc_400B62

jmp     loc_400B62

loc_400B62:
mov     eax, [rbp+var_11C]
test    eax, eax
jle     short loc_400B7B

mov     eax, [rbp+var_11C]
cmp     eax, 4
jle     loc_400A40

loc_400B7B:
mov     eax, 0
mov     rcx, [rbp+var_8]
xor     rcx, fs:28h
jz      short locret_400B94

call    __stack_chk_fail

locret_400B94:
leave
retn
; } // starts at 400A03
main endp