.text:0000000000001349 ; =============== S U B R O U T I N E =======================================
.text:0000000000001349
.text:0000000000001349 ; Attributes: bp-based frame
.text:0000000000001349
.text:0000000000001349 ; __int64 __fastcall sub_1349(_QWORD, _QWORD, _QWORD)
.text:0000000000001349 sub_1349        proc near               ; CODE XREF: main+38↓p

...
; Open file with fopen(argv[0], "rb")
.text:0000000000001368    mov     rax, [rbp+filename]
.text:000000000000136C    lea     rdx, modes      ; "rb"
.text:0000000000001373    mov     rsi, rdx        ; modes
.text:0000000000001376    mov     rdi, rax        ; filename  ← argv[0]
.text:0000000000001379    call    _fopen
.text:000000000000137E    mov     [rbp+stream], rax

...
; Read each byte and compare with byte_4020[0] = 0x9A
.text:00000000000013A2    movzx   edx, [rbp+ptr]        ; byte vừa đọc
.text:00000000000013A6    movzx   eax, cs:byte_4020     ; byte_4020[0] = 0x9A
.text:00000000000013AD    cmp     dl, al                ; so sánh
.text:00000000000013AF    jnz     loc_1460              ; không khớp → tiếp tục vòng lặp

...
; Save the current offset by using ftell() before reading the next 7 bytes
.text:00000000000013B5    mov     rax, [rbp+stream]
.text:00000000000013BC    call    _ftell                ; lưu file offset hiện tại
.text:00000000000013C1    mov     [rbp+off], rax        ; → var `off`

.text:00000000000013D0    mov     edx, 7               ; đọc 7 byte tiếp
.text:00000000000013D5    mov     esi, 1               ; size=1
.text:00000000000013DA    mov     rdi, rax             ; ptr
.text:00000000000013DD    call    _fread
.text:00000000000013E2    cmp     rax, 7               ; kiểm tra đọc đủ

...
; Compare the 7 bytes with byte_4020[1..7]
.text:00000000000013F8    mov     eax, [rbp+var_2C]         ; i
.text:00000000000013FD    movzx   edx, [rbp+rax+ptr]        ; buf[i]
.text:0000000000001402    mov     eax, [rbp+var_2C]
.text:0000000000001405    add     eax, 1
.text:000000000000140A    lea     rcx, byte_4020
.text:0000000000001411    movzx   eax, byte ptr [rax+rcx]   ; byte_4020[i+1]
.text:0000000000001415    cmp     dl, al                     ; so sánh từng byte
.text:0000000000001417    jz      short loc_1420
.text:0000000000001419    mov     [rbp+var_30], 0            ; flag = mismatch

...
; If all 7 bytes match, return var_28 = 0x3020 - the file offset of blob
.text:0000000000001430    cmp     [rbp+var_30], 0
.text:0000000000001434    jz      short loc_1448             ; không khớp
.text:0000000000001436    mov     rax, [rbp+stream]
.text:000000000000143D    call    _fclose
.text:0000000000001442    mov     rax, [rbp+var_28]          ; trả về offset = 0x3020
.text:0000000000001446    jmp     short loc_149F
