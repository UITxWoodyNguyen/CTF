; Init hash = FNV_OFFSET_BASIS
.text:00000000000014F4 loc_14F4:
.text:00000000000014F4    mov     rax, 0CBF29CE484222325h   ; FNV_OFFSET_BASIS
.text:00000000000014FE    mov     [rbp+var_18], rax         ; hash = FNV_OFFSET
.text:0000000000001502    mov     [rbp+var_10], 0           ; pos = 0
.text:000000000000150A    jmp     short loc_1552            ; → vòng đọc byte

; main loops - reading each bytes with fgetc() and calculating hash
.text:0000000000001552 loc_1552:                      ; điểm đầu vòng lặp
.text:0000000000001552    mov     rax, [rbp+stream]
.text:0000000000001556    mov     rdi, rax            ; stream
.text:0000000000001559    call    _fgetc              ; đọc 1 byte
.text:000000000000155E    mov     [rbp+var_1C], eax   ; var_1C = byte (hoặc EOF=-1)
.text:0000000000001561    cmp     [rbp+var_1C], 0FFFFFFFFh  ; kiểm tra EOF
.text:0000000000001565    jnz     short loc_150C      ; còn byte → xử lý

; Check skip zone (blob 64 bytes) - if  offset <= pos <= offset+63 --> Skip
.text:000000000000150C loc_150C:
.text:000000000000150C    cmp     [rbp+var_30], 0         ; offset < 0 ?
.text:0000000000001511    js      short loc_1532          ; → không skip (tính hash)

.text:0000000000001513    mov     rax, [rbp+var_10]       ; pos
.text:0000000000001517    cmp     rax, [rbp+var_30]       ; pos < offset ?
.text:000000000000151B    jl      short loc_1532          ; → không skip

.text:000000000000151D    mov     rax, [rbp+var_30]
.text:0000000000001521    add     rax, 3Fh                ; offset + 63 (= offset+0x3F)
.text:0000000000001525    cmp     [rbp+var_10], rax       ; pos > offset+63 ?
.text:0000000000001529    jg      short loc_1532          ; → không skip

; --- IN BLOB ZONE: skip, only pos++ ---
.text:000000000000152B    add     [rbp+var_10], 1         ; pos++
.text:0000000000001530    jmp     short loc_1552          ; → đọc byte tiếp

; FNV-1a hash: hash = (byte XOR hash) * FNV_PRIME [mod 2^64]
.text:0000000000001532 loc_1532:
.text:0000000000001532    mov     eax, [rbp+var_1C]        ; byte hiện tại
.text:0000000000001535    cdqe
.text:0000000000001537    xor     rax, [rbp+var_18]        ; rax = byte XOR hash
.text:000000000000153B    mov     rdx, 100000001B3h         ; FNV_PRIME
.text:0000000000001545    imul    rax, rdx                 ; rax = (byte XOR hash) * FNV_PRIME
.text:0000000000001549    mov     [rbp+var_18], rax        ; hash = kết quả [mod 2^64]
.text:000000000000154D    add     [rbp+var_10], 1          ; pos++
.text:0000000000001550    jmp     loc_1552                 ; → đọc byte tiếp

; XOR with 0xCAFEBABE00000000 then return
.text:0000000000001567    mov     rax, [rbp+stream]
.text:000000000000156E    call    _fclose
.text:0000000000001573    mov     rax, 0CAFEBABE00000000h   ; magic constant
.text:000000000000157D    xor     rax, [rbp+var_18]         ; result = CAFEBABE00000000 XOR hash
.text:0000000000001581 locret_1581:
.text:0000000000001581    leave
.text:0000000000001582    retn

