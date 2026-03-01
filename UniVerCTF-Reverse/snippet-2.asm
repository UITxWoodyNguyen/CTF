loc_14011583C:                          ; CODE XREF: sub_1401156F0+140↑j
                call    j_j_j__free_base

loc_140115841:                          ; CODE XREF: sub_1401156F0+11C↑j
                movzx   eax, sil

loc_140115845:                          ; CODE XREF: sub_1401156F0+22↑j
                mov     rcx, [rsp+88h+var_38]
                xor     rcx, rsp        ; StackCookie
                call    __security_check_cookie
                add     rsp, 68h
                pop     rdi
                pop     rsi
                pop     rbp
                pop     rbx
                retn
; } // starts at 1401156F0
sub_1401156F0   endp

; ---------------------------------------------------------------------------
algn_14011585B:                         ; DATA XREF: .pdata:000000014043D0C8↓o
                align 20h

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

sub_140115860   proc near               ; CODE XREF: main+269↑p
                                        ; DATA XREF: .pdata:000000014043D0D4↓o

var_58          = byte ptr -58h
var_50          = qword ptr -50h
Block           = qword ptr -48h
var_38          = qword ptr -38h
var_30          = qword ptr -30h
var_28          = qword ptr -28h
var_18          = qword ptr -18h
var_10          = qword ptr -10h
var_8           = qword ptr -8
var_s0          = byte ptr  0
arg_8           = qword ptr  28h
arg_10          = qword ptr  30h

; __unwind { // sub_1402DE8E0
                mov     [rsp-18h+arg_8], rbx
                mov     [rsp-18h+arg_10], rsi
                push    rbp
                push    rdi
                push    r15
                mov     rbp, rsp
                sub     rsp, 80h
                mov     rax, cs:__security_cookie
                xor     rax, rsp
                mov     [rbp+var_8], rax
                mov     rsi, rcx
                test    rcx, rcx
                jnz     short loc_140115895
                xor     al, al
                jmp     loc_140115A76
; ---------------------------------------------------------------------------

loc_140115895:                          ; CODE XREF: sub_140115860+2C↑j
                xorps   xmm0, xmm0
                movups  xmmword ptr [rbp+var_28], xmm0
                mov     [rbp+var_18], 0
                mov     [rbp+var_10], 0Fh
                mov     byte ptr [rbp+var_28], 0
                lea     rdx, aEnterFragment3 ; "enter fragment (3 chars): "
                lea     rcx, qword_14043A5E0
                call    sub_14010C790
                mov     rax, cs:qword_14043A430
                movsxd  rax, dword ptr [rax+4]
                lea     r15, qword_14043A430
                mov     rax, [rax+r15+40h]
                mov     rbx, [rax+8]
                mov     [rbp+var_50], rbx
                mov     rax, [rbx]
                mov     rcx, rbx
                call    qword ptr [rax+8]
                nop
                lea     rcx, [rbp+var_58]
                call    sub_14010EA10
                mov     r8, [rax]
                mov     dl, 0Ah
                mov     rcx, rax
                call    qword ptr [r8+40h]
                movzx   edi, al
                mov     rdx, [rbx]
                mov     rcx, rbx
                call    qword ptr [rdx+10h]
                test    rax, rax
                jz      short loc_140115920
                mov     r8, [rax]
                mov     edx, 1
                mov     rcx, rax
                call    qword ptr [r8]

loc_140115920:                          ; CODE XREF: sub_140115860+B0↑j
                movzx   r8d, dil
                lea     rdx, [rbp+var_28]
                mov     rcx, r15
                call    sub_14010E7A0
                mov     rdi, [rbp+var_10]
                mov     rbx, [rbp+var_28]
                cmp     [rbp+var_18], 3
                jz      short loc_140115947
                xor     sil, sil
                jmp     loc_140115A32
; ---------------------------------------------------------------------------

loc_140115947:                          ; CODE XREF: sub_140115860+DD↑j
                lea     rcx, [rbp+Block]
                call    sub_140115AA0
                nop
                lea     rcx, [rbp+var_28]
                cmp     rdi, 0Fh
                cmova   rcx, rbx
                mov     r9, [rbp+var_30]
                lea     rax, [rbp+Block]
                mov     r8, [rbp+Block]
                cmp     r9, 0Fh
                cmova   rax, r8
                movzx   eax, byte ptr [rax]
                cmp     [rcx], al
                jnz     short loc_1401159E8
                lea     rcx, [rbp+var_28]
                cmp     rdi, 0Fh
                cmova   rcx, rbx
                lea     rax, [rbp+Block]
                cmp     r9, 0Fh
                cmova   rax, r8
                movzx   eax, byte ptr [rax+1]
                cmp     [rcx+1], al
                jnz     short loc_1401159E8
                lea     rcx, [rbp+var_28]
                cmp     rdi, 0Fh
                cmova   rcx, rbx
                lea     rax, [rbp+Block]
                cmp     r9, 0Fh
                cmova   rax, r8
                movzx   eax, byte ptr [rax+2]
                cmp     [rcx+2], al
                jnz     short loc_1401159E8
                lea     rax, [rbp+Block]
                cmp     rsi, rax
                jz      short loc_1401159E3
                lea     rdx, [rbp+Block]
                cmp     r9, 0Fh
                cmova   rdx, r8
                mov     r8, [rbp+var_38]
                mov     rcx, rsi
                call    sub_14010CB90
                mov     r9, [rbp+var_30]
                mov     r8, [rbp+Block]

loc_1401159E3:                          ; CODE XREF: sub_140115860+161↑j
                mov     sil, 1
                jmp     short loc_1401159EB
; ---------------------------------------------------------------------------

loc_1401159E8:                          ; CODE XREF: sub_140115860+116↑j
                                        ; sub_140115860+137↑j ...
                xor     sil, sil

loc_1401159EB:                          ; CODE XREF: sub_140115860+186↑j
                cmp     r9, 0Fh
                jbe     short loc_140115A1E
                lea     rdx, [r9+1]
                cmp     rdx, 1000h
                jb      short loc_140115A16
                mov     rax, [r8-8]
                sub     r8, rax
                sub     r8, 8
                cmp     r8, 1Fh
                ja      short loc_140115A5C
                add     rdx, 27h ; '''
                mov     r8, rax

loc_140115A16:                          ; CODE XREF: sub_140115860+19C↑j
                mov     rcx, r8         ; Block
                call    j_j_j__free_base

loc_140115A1E:                          ; CODE XREF: sub_140115860+18F↑j
                mov     [rbp+var_38], 0
                mov     [rbp+var_30], 0Fh
                mov     byte ptr [rbp+Block], 0

loc_140115A32:                          ; CODE XREF: sub_140115860+E2↑j
                cmp     rdi, 0Fh
                jbe     short loc_140115A72
                lea     rdx, [rdi+1]
                cmp     rdx, 1000h
                jb      short loc_140115A6A
                mov     rcx, [rbx-8]
                sub     rbx, rcx
                sub     rbx, 8
                cmp     rbx, 1Fh
                ja      short loc_140115A63
                add     rdx, 27h ; '''
                jmp     short loc_140115A6D
; ---------------------------------------------------------------------------

loc_140115A5C:                          ; CODE XREF: sub_140115860+1AD↑j
                mov     ecx, 5
                int     29h             ; Win8: RtlFailFast(ecx)
; ---------------------------------------------------------------------------

loc_140115A63:                          ; CODE XREF: sub_140115860+1F4↑j
                mov     ecx, 5
                int     29h             ; Win8: RtlFailFast(ecx)
; ---------------------------------------------------------------------------

loc_140115A6A:                          ; CODE XREF: sub_140115860+1E3↑j
                mov     rcx, rbx        ; Block

loc_140115A6D:                          ; CODE XREF: sub_140115860+1FA↑j
                call    j_j_j__free_base

loc_140115A72:                          ; CODE XREF: sub_140115860+1D6↑j
                movzx   eax, sil

loc_140115A76:                          ; CODE XREF: sub_140115860+30↑j
                mov     rcx, [rbp+var_8]
                xor     rcx, rsp        ; StackCookie
                call    __security_check_cookie
                lea     r11, [rsp+80h+var_s0]
                mov     rbx, [r11+28h]
                mov     rsi, [r11+30h]
                mov     rsp, r11
                pop     r15
                pop     rdi
                pop     rbp
                retn
; } // starts at 140115860
sub_140115860   endp

; ---------------------------------------------------------------------------
algn_140115A9A:                         ; DATA XREF: .pdata:000000014043D0D4↓o
                align 20h

; =============== S U B R O U T I N E =======================================


sub_140115AA0   proc near               ; CODE XREF: sub_140115860+EB↑p
                                        ; DATA XREF: .pdata:000000014043D0E0↓o

var_18          = dword ptr -18h
var_10          = qword ptr -10h

; __unwind { // sub_1402E0318
                sub     rsp, 18h
                mov     rax, rcx
                mov     [rsp+18h+var_10], rcx
                mov     [rsp+18h+var_18], 0
                xorps   xmm0, xmm0
                movups  xmmword ptr [rcx], xmm0
                mov     qword ptr [rcx+18h], 0Fh
                mov     byte ptr [rcx], 0
                mov     qword ptr [rcx+10h], 3
                xor     ecx, ecx
                mov     [rax], ecx
                cmp     qword ptr [rax+18h], 0Fh
                jbe     short loc_140115ADC
                mov     rcx, [rax]
                jmp     short loc_140115ADF
; ---------------------------------------------------------------------------

loc_140115ADC:                          ; CODE XREF: sub_140115AA0+35↑j
                mov     rcx, rax

loc_140115ADF:                          ; CODE XREF: sub_140115AA0+3A↑j
                mov     byte ptr [rcx], 4Bh ; 'K'
                cmp     qword ptr [rax+18h], 0Fh
                jbe     short loc_140115AEE
                mov     rcx, [rax]
                jmp     short loc_140115AF1
; ---------------------------------------------------------------------------

loc_140115AEE:                          ; CODE XREF: sub_140115AA0+47↑j
                mov     rcx, rax

loc_140115AF1:                          ; CODE XREF: sub_140115AA0+4C↑j
                mov     byte ptr [rcx+1], 72h ; 'r'
                cmp     qword ptr [rax+18h], 0Fh
                jbe     short loc_140115B08
                mov     rcx, [rax]
                mov     byte ptr [rcx+2], 34h ; '4'
                add     rsp, 18h
                retn
; ---------------------------------------------------------------------------

loc_140115B08:                          ; CODE XREF: sub_140115AA0+5A↑j
                mov     byte ptr [rax+2], 34h ; '4'
                add     rsp, 18h
                retn
; ---------------------------------------------------------------------------
                db 0CCh
; } // starts at 140115AA0
sub_140115AA0   endp

algn_140115B12:                         ; DATA XREF: .pdata:000000014043D0E0↓o
                align 20h

; =============== S U B R O U T I N E =======================================


sub_140115B20   proc near               ; CODE XREF: sub_14030A010+7↓j
                                        ; sub_14030A020+7↓j ...
                push    rbx
                sub     rsp, 20h
                mov     rax, [rcx]
                mov     rbx, rcx
                test    rax, rax
                jz      short loc_140115B74
                mov     rdx, [rcx+10h]
                sub     rdx, rax
                cmp     rdx, 1000h
                jb      short loc_140115B5F
                mov     rcx, [rax-8]
                sub     rax, rcx
                sub     rax, 8
                cmp     rax, 1Fh
                ja      short loc_140115B58
                add     rdx, 27h ; '''
                jmp     short loc_140115B62
; ---------------------------------------------------------------------------

loc_140115B58:                          ; CODE XREF: sub_140115B20+30↑j
                mov     ecx, 5
                int     29h             ; Win8: RtlFailFast(ecx)
; ---------------------------------------------------------------------------

loc_140115B5F:                          ; CODE XREF: sub_140115B20+1F↑j
                mov     rcx, rax        ; Block

loc_140115B62:                          ; CODE XREF: sub_140115B20+36↑j
                call    j_j_j__free_base
                xor     eax, eax
                mov     [rbx], rax
                mov     [rbx+8], rax
                mov     [rbx+10h], rax

loc_140115B74:                          ; CODE XREF: sub_140115B20+F↑j
                add     rsp, 20h
                pop     rbx
                retn
sub_140115B20   endp

; ---------------------------------------------------------------------------
algn_140115B7A:                         ; DATA XREF: .pdata:000000014043D0EC↓o
                align 20h

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame fpd=60h

sub_140115B80   proc near               ; CODE XREF: main+27E↑p
                                        ; DATA XREF: .pdata:000000014043D0F8↓o

var_140         = qword ptr -140h
var_130         = qword ptr -130h
var_120         = qword ptr -120h
Src             = qword ptr -118h
var_108         = qword ptr -108h
Block           = qword ptr -100h
var_F0          = xmmword ptr -0F0h
var_E0          = qword ptr -0E0h
var_D0          = xmmword ptr -0D0h
var_C0          = qword ptr -0C0h
var_B0          = qword ptr -0B0h
var_A8          = qword ptr -0A8h
var_A0          = dword ptr -0A0h
var_9C          = word ptr -9Ch
var_98          = xmmword ptr -98h
var_88          = xmmword ptr -88h
var_78          = xmmword ptr -78h
var_68          = xmmword ptr -68h
var_49          = byte ptr -49h
var_48          = byte ptr -48h
var_28          = qword ptr -28h
var_20          = byte ptr -20h
arg_8           = qword ptr  18h
arg_10          = qword ptr  20h

; __unwind { // sub_1402DE8E0
                mov     [rsp-8+arg_8], rbx
                mov     [rsp-8+arg_10], rsi
                push    rbp
                push    rdi
                push    r12
                push    r14
                push    r15
                lea     rbp, [rsp-40h]
                sub     rsp, 140h
                mov     rax, cs:__security_cookie
                xor     rax, rsp
                mov     [rbp+60h+var_28], rax
                mov     r15, rcx
                test    rcx, rcx
                jnz     short loc_140115BBB
                xor     al, al
                jmp     loc_14011623B
; ---------------------------------------------------------------------------

loc_140115BBB:                          ; CODE XREF: sub_140115B80+32↑j
                xorps   xmm0, xmm0
                movups  xmmword ptr [rbp+60h+var_C0], xmm0
                xor     r12d, r12d
                mov     [rbp+60h+var_B0], r12
                mov     [rbp+60h+var_A8], 0Fh
                mov     byte ptr [rbp+60h+var_C0], r12b
                lea     rdx, aEnterStage2Tok ; "enter stage2 token (8 chars): "
                lea     rcx, qword_14043A5E0
                call    sub_14010C790
                mov     rax, cs:qword_14043A430
                movsxd  rax, dword ptr [rax+4]
                lea     rsi, qword_14043A430
                mov     rax, [rax+rsi+40h]
                mov     rbx, [rax+8]
                mov     qword ptr [rbp+60h+var_98+8], rbx
                mov     rax, [rbx]
                mov     rcx, rbx
                call    qword ptr [rax+8]
                nop
                lea     rcx, [rbp+60h+var_98]
                call    sub_14010EA10
                mov     r8, [rax]
                mov     dl, 0Ah
                mov     rcx, rax
                call    qword ptr [r8+40h]
                movzx   edi, al
                mov     rdx, [rbx]
                mov     rcx, rbx
                call    qword ptr [rdx+10h]
                test    rax, rax
                jz      short loc_140115C45
                mov     r8, [rax]
                mov     edx, 1
                mov     rcx, rax
                call    qword ptr [r8]

loc_140115C45:                          ; CODE XREF: sub_140115B80+B5↑j
                movzx   r8d, dil
                lea     rdx, [rbp+60h+var_C0]
                mov     rcx, rsi
                call    sub_14010E7A0
                mov     r10, [rbp+60h+var_A8]
                mov     r9, [rbp+60h+var_C0]
                cmp     [rbp+60h+var_B0], 8
                jnz     loc_1401161FD
                mov     dword ptr [rbp+60h+var_98], 0FADC2431h
                mov     dword ptr [rbp+60h+var_98+4], 0C5E42C25h
                mov     r8, r12
                nop     dword ptr [rax+00000000h]

loc_140115C80:                          ; CODE XREF: sub_140115B80+138↓j
                lea     rcx, [rbp+60h+var_C0]
                cmp     r10, 0Fh
                cmova   rcx, r9
                movzx   eax, r8b
                imul    edx, eax, 11h
                add     dl, 6Dh ; 'm'
                xor     dl, [rcx+r8]
                movzx   eax, r8b
                imul    ecx, eax, 7
                add     dl, 13h
                add     dl, cl
                cmp     dl, byte ptr [rbp+r8+60h+var_98]
                jnz     loc_1401161FD
                inc     r8
                cmp     r8, 8
                jb      short loc_140115C80
                xorps   xmm0, xmm0
                movdqu  xmmword ptr [rsp+160h+var_130], xmm0
                mov     [rsp+160h+var_120], r12
                movups  xmmword ptr [rsp+160h+Block], xmm0
                mov     qword ptr [rsp+160h+var_F0], r12
                mov     qword ptr [rsp+160h+var_F0+8], r12
                mov     ecx, 20h ; ' '  ; Size
                call    ??2@YAPEAX_K@Z  ; operator new(unsigned __int64)
                mov     [rsp+160h+Block], rax
                mov     qword ptr [rsp+160h+var_F0], 13h
                mov     qword ptr [rsp+160h+var_F0+8], 1Fh
                movups  xmm0, cs:xmmword_14030D808
                movups  xmmword ptr [rax], xmm0
                mov     ecx, dword ptr cs:xmmword_14030D808+0Fh
                mov     [rax+0Fh], ecx
                mov     byte ptr [rax+13h], 0
                lea     rax, [rsp+160h+var_130]
                mov     [rsp+160h+var_140], rax
                mov     r9d, 30h ; '0'
                mov     r8d, 0EA60h
                lea     rdx, [rsp+160h+Block]
                lea     rcx, [rbp+60h+var_C0]
                call    sub_14011E2E0
                movzx   ebx, al
                mov     rdx, qword ptr [rsp+160h+var_F0+8]
                cmp     rdx, 0Fh
                jbe     short loc_140115D78
                mov     rcx, [rsp+160h+Block]
                inc     rdx
                cmp     rdx, 1000h
                jb      short loc_140115D6D
                mov     r8, [rcx-8]
                sub     rcx, r8
                sub     rcx, 8
                cmp     rcx, 1Fh
                ja      loc_140116183
                add     rdx, 27h ; '''
                jmp     short loc_140115D70
; ---------------------------------------------------------------------------

loc_140115D6D:                          ; CODE XREF: sub_140115B80+1D0↑j
                mov     r8, rcx

loc_140115D70:                          ; CODE XREF: sub_140115B80+1EB↑j
                mov     rcx, r8         ; Block
                call    j_j_j__free_base

loc_140115D78:                          ; CODE XREF: sub_140115B80+1BF↑j
                mov     r8, [rsp+160h+var_130]
                test    bl, bl
                jz      loc_1401161A7
                mov     rax, [rsp+160h+var_130+8]
                sub     rax, r8
                cmp     rax, 30h ; '0'
                jnz     loc_1401161A7
                lea     rax, [r8+1Fh]
                lea     rcx, [rbp+60h+var_68]
                cmp     rcx, rax
                ja      short loc_140115DC4
                lea     rax, [rbp+60h+var_49]
                cmp     rax, r8
                jb      short loc_140115DC4
                mov     edx, r12d

loc_140115DB0:                          ; CODE XREF: sub_140115B80+240↓j
                mov     ecx, edx
                movzx   eax, byte ptr [rcx+r8]
                mov     byte ptr [rbp+rcx+60h+var_68], al
                inc     edx
                cmp     edx, 20h ; ' '
                jl      short loc_140115DB0
                jmp     short loc_140115DD5
; ---------------------------------------------------------------------------

loc_140115DC4:                          ; CODE XREF: sub_140115B80+222↑j
                                        ; sub_140115B80+22B↑j
                movups  xmm0, xmmword ptr [r8]
                movups  [rbp+60h+var_68], xmm0
                movups  xmm1, xmmword ptr [r8+10h]
                movups  xmmword ptr [rbp+8], xmm1

loc_140115DD5:                          ; CODE XREF: sub_140115B80+242↑j
                lea     rcx, [r8+20h]
                lea     rax, [r8+2Fh]
                lea     rdx, [rbp+60h+var_78]
                cmp     rdx, rax
                ja      short loc_140115E17
                lea     rax, [rbp+60h+var_78+0Fh]
                cmp     rax, rcx
                jb      short loc_140115E17
                mov     edx, r12d
                nop     dword ptr [rax+00h]
                db      66h, 66h
                nop     word ptr [rax+rax+00000000h]

loc_140115E00:                          ; CODE XREF: sub_140115B80+293↓j
                mov     eax, edx
                mov     ecx, edx
                movzx   eax, byte ptr [rax+r8+20h]
                mov     byte ptr [rbp+rcx+60h+var_78], al
                inc     edx
                cmp     edx, 10h
                jl      short loc_140115E00
                jmp     short loc_140115E1E
; ---------------------------------------------------------------------------

loc_140115E17:                          ; CODE XREF: sub_140115B80+264↑j
                                        ; sub_140115B80+26D↑j
                movups  xmm0, xmmword ptr [rcx]
                movups  [rbp+60h+var_78], xmm0

loc_140115E1E:                          ; CODE XREF: sub_140115B80+295↑j
                mov     [rbp+60h+var_A0], 0DA6F05CCh
                mov     [rbp+60h+var_9C], 0BEB9h
                xorps   xmm0, xmm0
                movdqu  xmmword ptr [rsp+160h+Src], xmm0
                mov     [rsp+160h+var_108], r12
                xor     bl, bl
                lea     rax, [rsp+160h+Src]
                mov     [rsp+160h+var_140], rax
                mov     r9d, 6
                lea     r8, [rbp+60h+var_A0]
                lea     rdx, [rbp+60h+var_78]
                lea     rcx, [rbp+60h+var_68]
                call    sub_14011E1A0
                test    al, al
                jz      loc_140116116
                movzx   eax, byte ptr [rbp+60h+var_68]
                xor     al, byte ptr [rbp+60h+var_68+7]
                test    al, 1
                jnz     short loc_140115EEA
                mov     dword ptr [rbp+60h+var_98], 8933F117h
                mov     word ptr [rbp+60h+var_98+4], 40AAh
                xorps   xmm0, xmm0
                movdqu  xmmword ptr [rsp+160h+Block], xmm0
                mov     qword ptr [rsp+160h+var_F0], r12
                lea     rax, [rsp+160h+Block]
                mov     [rsp+160h+var_140], rax
                mov     r9d, 6
                lea     r8, [rbp+60h+var_98]
                lea     rdx, [rbp+60h+var_78]
                lea     rcx, [rbp+60h+var_68]
                call    sub_14011E1A0
                nop
                mov     rax, [rsp+160h+Block]
                test    rax, rax
                jz      short loc_140115EEA
                mov     rdx, qword ptr [rsp+160h+var_F0]
                sub     rdx, rax
                cmp     rdx, 1000h
                jb      short loc_140115EE2
                mov     rcx, [rax-8]
                sub     rax, rcx
                sub     rax, 8
                cmp     rax, 1Fh
                ja      loc_140116105
                add     rdx, 27h ; '''
                jmp     short loc_140115EE5
; ---------------------------------------------------------------------------

loc_140115EE2:                          ; CODE XREF: sub_140115B80+345↑j
                mov     rcx, rax        ; Block

loc_140115EE5:                          ; CODE XREF: sub_140115B80+360↑j
                call    j_j_j__free_base

loc_140115EEA:                          ; CODE XREF: sub_140115B80+2ED↑j
                                        ; sub_140115B80+334↑j
                mov     dword ptr [rsp+160h+Block], 0FB4FA74Bh
