var_260         = qword ptr -260h
var_258         = xmmword ptr -258h
var_248         = xmmword ptr -248h
var_238         = xmmword ptr -238h
var_228         = xmmword ptr -228h
Buf             = _JBTYPE ptr -210h
var_110         = qword ptr -110h
var_100         = qword ptr -100h
var_F8          = qword ptr -0F8h
var_F0          = qword ptr -0F0h
var_E0          = xmmword ptr -0E0h
var_D0          = xmmword ptr -0D0h
var_C0          = qword ptr -0C0h
var_B8          = qword ptr -0B8h
var_B0          = dword ptr -0B0h
var_AC          = dword ptr -0ACh
var_A8          = word ptr -0A8h
var_A6          = byte ptr -0A6h
var_A0          = dword ptr -0A0h
var_9C          = dword ptr -9Ch
var_98          = dword ptr -98h
var_94          = dword ptr -94h
var_90          = dword ptr -90h
var_8C          = dword ptr -8Ch
var_88          = dword ptr -88h
var_84          = dword ptr -84h
var_80          = dword ptr -80h
var_78          = byte ptr -78h
var_68          = byte ptr -68h
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
                lea     rbp, [rsp-220h]
                sub     rsp, 320h
                mov     rax, cs:__security_cookie
                xor     rax, rsp
                mov     [rbp+240h+var_28], rax
                mov     [rbp+240h+var_2A0], rcx
                test    rcx, rcx
                jz      loc_140116D4B
                xorps   xmm0, xmm0
                movups  xmmword ptr [rbp+240h+var_110], xmm0
                xor     r15d, r15d
                mov     [rbp+240h+var_100], r15
                mov     [rbp+240h+var_F8], 0Fh
                mov     byte ptr [rbp+240h+var_110], r15b
                lea     rdx, aEnterToken8Cha ; "enter token (8 chars): "
                lea     rcx, qword_14043A5E0
                call    sub_14010C790
                mov     rax, cs:qword_14043A430
                movsxd  rax, dword ptr [rax+4]
                lea     rdi, qword_14043A430
                mov     rax, [rax+rdi+40h]
                mov     rcx, [rax+8]
                mov     [rbp+240h+var_290], rcx
                mov     rax, [rcx]
                call    qword ptr [rax+8]
                nop
                lea     rcx, [rbp+240h+var_298]
                call    sub_14010EA10
                mov     r8, [rax]
                mov     dl, 0Ah
                mov     rcx, rax
                call    qword ptr [r8+40h]
                movzx   ebx, al
                mov     rcx, [rbp+240h+var_290]
                test    rcx, rcx
                jz      short loc_140116577
                mov     rdx, [rcx]
                call    qword ptr [rdx+10h]
                mov     rcx, rax
                test    rax, rax
                jz      short loc_140116577
                mov     rax, [rax]
                mov     edx, 1
                call    qword ptr [rax]

loc_140116577:                          ; CODE XREF: sub_1401164A0+BD↑j
                                        ; sub_1401164A0+CB↑j
                movzx   r8d, bl
                lea     rdx, [rbp+240h+var_110]
                mov     rcx, rdi
                call    sub_14010E7A0
                lea     rcx, [rbp+240h+var_110] ; Src
                call    sub_140116F10
                test    al, al
                jz      short loc_1401165E4

loc_14011659A:                          ; CODE XREF: sub_1401164A0+2C9↓j
                                        ; sub_1401164A0+311↓j ...
                mov     rdx, [rbp+240h+var_F8]
                cmp     rdx, 0Fh
                jbe     loc_140116D4B
                inc     rdx
                cmp     rdx, 1000h
                mov     rax, [rbp+240h+var_110]
                jb      short loc_1401165DC
                mov     rcx, [rax-8]
                sub     rax, rcx
                sub     rax, 8
                cmp     rax, 1Fh
                ja      loc_140116D3C
                add     rdx, 27h ; '''
                jmp     loc_140116D46
; ---------------------------------------------------------------------------

loc_1401165DC:                          ; CODE XREF: sub_1401164A0+11C↑j
                mov     rcx, rax
                jmp     loc_140116D46
; ---------------------------------------------------------------------------

loc_1401165E4:                          ; CODE XREF: sub_1401164A0+F8↑j
                mov     r11, [rbp+240h+var_F8]
                mov     r10, [rbp+240h+var_110]
                cmp     [rbp+240h+var_100], 8
                jnz     loc_140116D12
                mov     [rsp+340h+var_300], 0EDA7D1D7h
                mov     [rsp+340h+var_2FC], 49683954h
                mov     r9, r15
                nop     dword ptr [rax+00h]
                nop     word ptr [rax+rax+00000000h]

loc_140116620:                          ; CODE XREF: sub_1401164A0+1C2↓j
                lea     rdx, [rbp+240h+var_110]
                cmp     r11, 0Fh
                cmova   rdx, r10
                movzx   eax, r9b
                imul    ecx, eax, 0Bh
                mov     r8d, 0A7h
                sub     r8b, cl
                xor     r8b, [rdx+r9]
                movzx   eax, r9b
                add     al, al
                lea     ecx, [rax+r9]
                add     r8b, cl
                cmp     r8b, byte ptr [rsp+r9+340h+var_300]
                jnz     loc_140116D12
                inc     r9
                cmp     r9, 8
                jb      short loc_140116620
                xorps   xmm0, xmm0
                movdqu  xmmword ptr [rsp+340h+Block], xmm0
                mov     [rsp+340h+var_2C8], r15
                movups  [rbp+240h+var_D0], xmm0
                mov     [rbp+240h+var_C0], r15
                mov     [rbp+240h+var_B8], r15
                mov     [rbp+240h+var_288], 1Fh
                mov     r12d, 16h
                mov     [rbp+240h+var_280], r12
                mov     ecx, 20h ; ' '  ; Size
                call    ??2@YAPEAX_K@Z  ; operator new(unsigned __int64)
                mov     qword ptr [rbp+240h+var_D0], rax
                mov     [rbp+240h+var_C0], 13h
                mov     [rbp+240h+var_B8], 1Fh
                movups  xmm0, cs:xmmword_14030D8C0
                movups  xmmword ptr [rax], xmm0
                mov     ecx, dword ptr cs:xmmword_14030D8C0+0Fh
                mov     [rax+0Fh], ecx
                mov     byte ptr [rax+13h], 0
                lea     rax, [rsp+340h+Block]
                mov     [rsp+340h+var_320], rax
                mov     r9d, 2Ch ; ','
                mov     r8d, 15F90h
                lea     rdx, [rbp+240h+var_D0]
                lea     rcx, [rbp+240h+var_110]
                call    sub_14011E2E0
                movzx   ebx, al
                mov     rdx, [rbp+240h+var_B8]
                cmp     rdx, 0Fh
                jbe     short loc_140116744
                mov     rcx, qword ptr [rbp+240h+var_D0]
                inc     rdx
                cmp     rdx, 1000h
                jb      short loc_14011673F
                add     rdx, 27h ; '''
                mov     rax, [rcx-8]
                sub     rcx, rax
                sub     rcx, 8
                cmp     rcx, 1Fh
                ja      loc_140116C59
                mov     rcx, rax        ; Block

loc_14011673F:                          ; CODE XREF: sub_1401164A0+281↑j
                call    j_j_j__free_base

loc_140116744:                          ; CODE XREF: sub_1401164A0+26E↑j
                mov     [rbp+240h+var_C0], r15
                mov     [rbp+240h+var_B8], 0Fh
                mov     byte ptr [rbp+240h+var_D0], 0
                test    bl, bl
                jnz     short loc_1401167B6

loc_140116761:                          ; CODE XREF: sub_1401164A0+457↓j
                mov     rax, [rsp+340h+Block]
                test    rax, rax
                jz      loc_14011659A
                mov     rdx, [rsp+340h+var_2C8]
                sub     rdx, rax
                cmp     rdx, 1000h
                jb      short loc_14011679B
                mov     rcx, [rax-8]
                sub     rax, rcx
                sub     rax, 8
                cmp     rax, 1Fh
                ja      loc_140116CA9
                add     rdx, 27h ; '''
                jmp     short loc_14011679E
; ---------------------------------------------------------------------------

loc_14011679B:                          ; CODE XREF: sub_1401164A0+2DE↑j
                mov     rcx, rax        ; Block

loc_14011679E:                          ; CODE XREF: sub_1401164A0+2F9↑j
                                        ; sub_1401164A0+35E↓j ...
                call    j_j_j__free_base
                xorps   xmm0, xmm0
                movdqu  xmmword ptr [rsp+340h+Block], xmm0
                mov     [rsp+340h+var_2C8], r15
                jmp     loc_14011659A
; ---------------------------------------------------------------------------

loc_1401167B6:                          ; CODE XREF: sub_1401164A0+2BF↑j
                mov     rax, [rsp+340h+Block+8]
                mov     rdx, [rsp+340h+Block]
                sub     rax, rdx
                cmp     rax, 2Ch ; ','
                jz      short loc_140116808
                test    rdx, rdx
                jz      loc_14011659A
                mov     rax, [rsp+340h+var_2C8]
                sub     rax, rdx
                cmp     rax, 1000h
                jb      short loc_140116800
                mov     rcx, [rdx-8]
                sub     rdx, rcx
                sub     rdx, 8
                cmp     rdx, 1Fh
                ja      loc_140116CA9
                add     rax, 27h ; '''
                mov     rdx, rax
                jmp     short loc_14011679E
; ---------------------------------------------------------------------------

loc_140116800:                          ; CODE XREF: sub_1401164A0+340↑j
                mov     rcx, rdx
                mov     rdx, rax
                jmp     short loc_14011679E
; ---------------------------------------------------------------------------

loc_140116808:                          ; CODE XREF: sub_1401164A0+327↑j
                mov     r8d, r15d
                nop     dword ptr [rax+rax+00h]

loc_140116810:                          ; CODE XREF: sub_1401164A0+385↓j
                movsxd  rcx, r8d
                movzx   eax, byte ptr [rdx+rcx]
                mov     [rbp+rcx+240h+var_68], al
                inc     r8d
                cmp     r8d, 20h ; ' '
                jl      short loc_140116810
                mov     r8d, r15d
                nop     word ptr [rax+rax+00h]

loc_140116830:                          ; CODE XREF: sub_1401164A0+3AB↓j
                lea     eax, [r8+20h]
                cdqe
                movsxd  rcx, r8d
                movzx   eax, byte ptr [rax+rdx]
                mov     [rbp+rcx+240h+var_78], al
                inc     r8d
