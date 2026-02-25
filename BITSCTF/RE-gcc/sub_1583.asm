; var_10 = decrypted[0], var_F = [1], var_E = [2], var_D = [3]
; var_C  = decrypted[4], var_B = [5], var_A = [6], var_9 = [7]

.text:00000000000015FD    movzx   eax, [rbp+var_10]
.text:0000000000001601    cmp     al, 42h  ; 'B'  ← decrypted[0]
.text:0000000000001603    jnz     short loc_1644   ; fail

.text:0000000000001605    movzx   eax, [rbp+var_F]
.text:0000000000001609    cmp     al, 49h  ; 'I'  ← decrypted[1]
.text:000000000000160B    jnz     short loc_1644   ; fail

.text:000000000000160D    movzx   eax, [rbp+var_E]
.text:0000000000001611    cmp     al, 54h  ; 'T'  ← decrypted[2]
.text:0000000000001613    jnz     short loc_1644   ; fail

.text:0000000000001615    movzx   eax, [rbp+var_D]
.text:0000000000001619    cmp     al, 53h  ; 'S'  ← decrypted[3]
.text:000000000000161B    jnz     short loc_1644   ; fail

.text:000000000000161D    movzx   eax, [rbp+var_C]
.text:0000000000001621    cmp     al, 43h  ; 'C'  ← decrypted[4]
.text:0000000000001623    jnz     short loc_1644   ; fail

.text:0000000000001625    movzx   eax, [rbp+var_B]
.text:0000000000001629    cmp     al, 54h  ; 'T'  ← decrypted[5]
.text:000000000000162B    jnz     short loc_1644   ; fail

.text:000000000000162D    movzx   eax, [rbp+var_A]
.text:0000000000001631    cmp     al, 46h  ; 'F'  ← decrypted[6]
.text:0000000000001633    jnz     short loc_1644   ; fail

.text:0000000000001635    movzx   eax, [rbp+var_9]
.text:0000000000001639    cmp     al, 7Bh  ; '{'  ← decrypted[7]
.text:000000000000163B    jnz     short loc_1644   ; fail

.text:000000000000163D    mov     eax, 1           ; return 1 (valid!)
.text:0000000000001642    jmp     short loc_1649

.text:0000000000001644 loc_1644:
.text:0000000000001644    mov     eax, 0           ; return 0 (invalid)
