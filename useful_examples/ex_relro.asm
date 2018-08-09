; Disassembly of file: /mnt/hgfs/VM_Shared/reassemblablabla/src/ex_dir/ex_relro
; Tue Jul 24 04:44:53 2018
; Mode: 32 bits
; Syntax: MASM/ML
; Instruction set: 80386

; Error: symbol names contain illegal characters,
; 4 Symbol names not changed

.386
option dotname
.model flat

public _end
public _init
public _start
public __x86.get_pc_thunk.bx
public main
public __libc_csu_init
public __libc_csu_fini
public _fini
public _fp_hw
public _IO_stdin_used
public _IO_stdin_used
public __data_start
public data_start                                       ; Note: Weak. Not supported by MASM 
public __dso_handle
public __TMC_END__
public __bss_start
public _edata

extern _ITM_registerTMCloneTable: byte
extern _Jv_RegisterClasses: byte
extern __libc_start_main@@GLIBC_2.0: near
extern __gmon_start__: byte
extern printf@@GLIBC_2.0: near
extern _ITM_deregisterTMCloneTable: byte
extern __libc_start_main: near
extern printf: near
extern __gmon_start__: near


.interp SEGMENT BYTE PUBLIC 'CONST'                     ; section number 1

        db 2FH, 6CH, 69H, 62H, 2FH, 6CH, 64H, 2DH       ; 08048154 _ /lib/ld-
        db 6CH, 69H, 6EH, 75H, 78H, 2EH, 73H, 6FH       ; 0804815C _ linux.so
        db 2EH, 32H, 00H                                ; 08048164 _ .2.

.interp ENDS

.note.ABI-tag SEGMENT DWORD PUBLIC 'CONST'              ; section number 2

        db 04H, 00H, 00H, 00H, 10H, 00H, 00H, 00H       ; 08048168 _ ........
        db 01H, 00H, 00H, 00H, 47H, 4EH, 55H, 00H       ; 08048170 _ ....GNU.
        db 00H, 00H, 00H, 00H, 02H, 00H, 00H, 00H       ; 08048178 _ ........
        db 06H, 00H, 00H, 00H, 20H, 00H, 00H, 00H       ; 08048180 _ .... ...

.note.ABI-tag ENDS

.note.gnu.build-id SEGMENT DWORD PUBLIC 'CONST'         ; section number 3

        db 04H, 00H, 00H, 00H, 14H, 00H, 00H, 00H       ; 08048188 _ ........
        db 03H, 00H, 00H, 00H, 47H, 4EH, 55H, 00H       ; 08048190 _ ....GNU.
        db 5CH, 0C5H, 62H, 81H, 45H, 83H, 48H, 0F5H     ; 08048198 _ \.b.E.H.
        db 0FCH, 17H, 0C4H, 0F9H, 0C8H, 0EAH, 63H, 97H  ; 080481A0 _ ......c.
        db 96H, 0CAH, 83H, 0ADH                         ; 080481A8 _ ....

.note.gnu.build-id ENDS

.gnu.hash SEGMENT DWORD PUBLIC 'CONST'                  ; section number 4

        db 03H, 00H, 00H, 00H, 02H, 00H, 00H, 00H       ; 080481AC _ ........
        db 01H, 00H, 00H, 00H, 05H, 00H, 00H, 00H       ; 080481B4 _ ........
        db 00H, 60H, 02H, 21H, 00H, 00H, 00H, 00H       ; 080481BC _ .`.!....
        db 02H, 00H, 00H, 00H, 04H, 00H, 00H, 00H       ; 080481C4 _ ........
        db 0B8H, 2BH, 6BH, 15H, 0ADH, 4BH, 0E3H, 0C0H   ; 080481CC _ .+k..K..
        db 2FH, 4EH, 3DH, 0F6H                          ; 080481D4 _ /N=.

.gnu.hash ENDS

.dynsym SEGMENT DWORD PUBLIC 'CONST'                    ; section number 5

        db 00H, 00H, 00H, 00H, 00H, 00H, 00H, 00H       ; 080481D8 _ ........
        db 00H, 00H, 00H, 00H, 00H, 00H, 00H, 00H       ; 080481E0 _ ........
        db 33H, 00H, 00H, 00H, 00H, 00H, 00H, 00H       ; 080481E8 _ 3.......
        db 00H, 00H, 00H, 00H, 20H, 00H, 00H, 00H       ; 080481F0 _ .... ...
        db 1AH, 00H, 00H, 00H, 00H, 00H, 00H, 00H       ; 080481F8 _ ........
        db 00H, 00H, 00H, 00H, 12H, 00H, 00H, 00H       ; 08048200 _ ........
        db 0BH, 00H, 00H, 00H, 0BCH, 84H, 04H, 08H      ; 08048208 _ ........
        db 04H, 00H, 00H, 00H, 11H, 00H, 0FH, 00H       ; 08048210 _ ........
        db 21H, 00H, 00H, 00H, 00H, 00H, 00H, 00H       ; 08048218 _ !.......
        db 00H, 00H, 00H, 00H, 12H, 00H, 00H, 00H       ; 08048220 _ ........

.dynsym ENDS

.dynstr SEGMENT BYTE PUBLIC 'CONST'                     ; section number 6

        db 00H, 6CH, 69H, 62H, 63H, 2EH, 73H, 6FH       ; 08048228 _ .libc.so
        db 2EH, 36H, 00H, 5FH, 49H, 4FH, 5FH, 73H       ; 08048230 _ .6._IO_s
        db 74H, 64H, 69H, 6EH, 5FH, 75H, 73H, 65H       ; 08048238 _ tdin_use
        db 64H, 00H, 70H, 72H, 69H, 6EH, 74H, 66H       ; 08048240 _ d.printf
        db 00H, 5FH, 5FH, 6CH, 69H, 62H, 63H, 5FH       ; 08048248 _ .__libc_
        db 73H, 74H, 61H, 72H, 74H, 5FH, 6DH, 61H       ; 08048250 _ start_ma
        db 69H, 6EH, 00H, 5FH, 5FH, 67H, 6DH, 6FH       ; 08048258 _ in.__gmo
        db 6EH, 5FH, 73H, 74H, 61H, 72H, 74H, 5FH       ; 08048260 _ n_start_
        db 5FH, 00H, 47H, 4CH, 49H, 42H, 43H, 5FH       ; 08048268 _ _.GLIBC_
        db 32H, 2EH, 30H, 00H                           ; 08048270 _ 2.0.

.dynstr ENDS

.gnu.version SEGMENT WORD PUBLIC 'CONST'                ; section number 7

        db 00H, 00H, 00H, 00H, 02H, 00H, 01H, 00H       ; 08048274 _ ........
        db 02H, 00H                                     ; 0804827C _ ..

.gnu.version ENDS

.gnu.version_r SEGMENT DWORD PUBLIC 'CONST'             ; section number 8

        db 01H, 00H, 01H, 00H, 01H, 00H, 00H, 00H       ; 08048280 _ ........
        db 10H, 00H, 00H, 00H, 00H, 00H, 00H, 00H       ; 08048288 _ ........
        db 10H, 69H, 69H, 0DH, 00H, 00H, 02H, 00H       ; 08048290 _ .ii.....
        db 42H, 00H, 00H, 00H, 00H, 00H, 00H, 00H       ; 08048298 _ B.......

.gnu.version_r ENDS

.rel.dyn SEGMENT DWORD PUBLIC 'CONST'                   ; section number 9

        db 0F4H, 9FH, 04H, 08H, 06H, 02H, 00H, 00H      ; 080482A0 _ ........
        db 0F8H, 9FH, 04H, 08H, 06H, 01H, 00H, 00H      ; 080482A8 _ ........
        db 0FCH, 9FH, 04H, 08H, 06H, 04H, 00H, 00H      ; 080482B0 _ ........

.rel.dyn ENDS

.init   SEGMENT DWORD PUBLIC 'CODE'                     ; section number 10

_init   PROC NEAR
        push    ebx                                     ; 080482B8 _ 53
        sub     esp, 8                                  ; 080482B9 _ 83. EC, 08
        call    __x86.get_pc_thunk.bx                   ; 080482BC _ E8, 0000007F(rel)
        add     ebx, 7463                               ; 080482C1 _ 81. C3, 00001D27
; Note: Displacement could be made smaller by sign extension
        mov     eax, dword ptr [ebx+10H]                ; 080482C7 _ 8B. 83, 00000010
        test    eax, eax                                ; 080482CD _ 85. C0
        jz      ?_001                                   ; 080482CF _ 74, 05
        call    ?_003                                   ; 080482D1 _ E8, 00000022(rel)
?_001:  add     esp, 8                                  ; 080482D6 _ 83. C4, 08
        pop     ebx                                     ; 080482D9 _ 5B
        ret                                             ; 080482DA _ C3
_init   ENDP

.init   ENDS

.plt    SEGMENT PARA PUBLIC 'CODE'                      ; section number 11

        push    dword ptr [?_013]                       ; 080482E0 _ FF. 35, 08049FEC(d)
        jmp     dword ptr [?_014]                       ; 080482E6 _ FF. 25, 08049FF0(d)

        db 00H, 00H, 00H, 00H                           ; 080482EC _ ....

.plt    ENDS

.plt.got SEGMENT ALIGN(8) PUBLIC 'CODE'                 ; section number 12


?_002   LABEL NEAR
        jmp     dword ptr [?_015]                       ; 080482F0 _ FF. 25, 08049FF4(d)

; Filling space: 2H
; Filler type: NOP with prefixes
;       db 66H, 90H

ALIGN   8

?_003   LABEL NEAR
        jmp     dword ptr [?_016]                       ; 080482F8 _ FF. 25, 08049FF8(d)

; Filling space: 2H
; Filler type: NOP with prefixes
;       db 66H, 90H

ALIGN   8

?_004   LABEL NEAR
        jmp     dword ptr [?_017]                       ; 08048300 _ FF. 25, 08049FFC(d)

; Filling space: 2H
; Filler type: NOP with prefixes
;       db 66H, 90H

ALIGN   8

.plt.got ENDS

_text   SEGMENT PARA PUBLIC 'CODE'                      ; section number 13

_start  PROC NEAR
        xor     ebp, ebp                                ; 08048310 _ 31. ED
        pop     esi                                     ; 08048312 _ 5E
        mov     ecx, esp                                ; 08048313 _ 89. E1
        and     esp, 0FFFFFFF0H                         ; 08048315 _ 83. E4, F0
        push    eax                                     ; 08048318 _ 50
        push    esp                                     ; 08048319 _ 54
        push    edx                                     ; 0804831A _ 52
        push    offset __libc_csu_fini                  ; 0804831B _ 68, 080484A0(d)
        push    offset __libc_csu_init                  ; 08048320 _ 68, 08048440(d)
        push    ecx                                     ; 08048325 _ 51
        push    esi                                     ; 08048326 _ 56
        push    offset main                             ; 08048327 _ 68, 0804840B(d)
        call    ?_004                                   ; 0804832C _ E8, FFFFFFCF(rel)
        hlt                                             ; 08048331 _ F4
; Filling space: 0EH
; Filler type: NOP with prefixes
;       db 66H, 90H, 66H, 90H, 66H, 90H, 66H, 90H
;       db 66H, 90H, 66H, 90H, 66H, 90H

ALIGN   16

__x86.get_pc_thunk.bx LABEL NEAR
        mov     ebx, dword ptr [esp]                    ; 08048340 _ 8B. 1C 24
        ret                                             ; 08048343 _ C3
_start  ENDP

; Filling space: 0CH
; Filler type: NOP with prefixes
;       db 66H, 90H, 66H, 90H, 66H, 90H, 66H, 90H
;       db 66H, 90H, 66H, 90H

ALIGN   16

deregister_tm_clones LABEL NEAR
        mov     eax, offset ?_018                       ; 08048350 _ B8, 0804A00B(d)
        sub     eax, 134520840                          ; 08048355 _ 2D, 0804A008
        cmp     eax, 6                                  ; 0804835A _ 83. F8, 06
        jbe     ?_005                                   ; 0804835D _ 76, 1A
        mov     eax, 0                                  ; 0804835F _ B8, 00000000
        test    eax, eax                                ; 08048364 _ 85. C0
        jz      ?_005                                   ; 08048366 _ 74, 11
        push    ebp                                     ; 08048368 _ 55
        mov     ebp, esp                                ; 08048369 _ 89. E5
        sub     esp, 20                                 ; 0804836B _ 83. EC, 14
        push    offset _edata                           ; 0804836E _ 68, 0804A008(d)
        call    eax                                     ; 08048373 _ FF. D0
        add     esp, 16                                 ; 08048375 _ 83. C4, 10
        leave                                           ; 08048378 _ C9
?_005:
; Note: Prefix bit or byte has no meaning in this context
        ret                                             ; 08048379 _ F3: C3

        nop                                             ; 0804837B _ 90
; Filling space: 4H
; Filler type: lea with same source and destination
;       db 8DH, 74H, 26H, 00H

ALIGN   8

register_tm_clones LABEL NEAR
        mov     eax, offset _edata                      ; 08048380 _ B8, 0804A008(d)
        sub     eax, 134520840                          ; 08048385 _ 2D, 0804A008
        sar     eax, 2                                  ; 0804838A _ C1. F8, 02
        mov     edx, eax                                ; 0804838D _ 89. C2
        shr     edx, 31                                 ; 0804838F _ C1. EA, 1F
        add     eax, edx                                ; 08048392 _ 01. D0
        sar     eax, 1                                  ; 08048394 _ D1. F8
        jz      ?_006                                   ; 08048396 _ 74, 1B
        mov     edx, 0                                  ; 08048398 _ BA, 00000000
        test    edx, edx                                ; 0804839D _ 85. D2
        jz      ?_006                                   ; 0804839F _ 74, 12
        push    ebp                                     ; 080483A1 _ 55
        mov     ebp, esp                                ; 080483A2 _ 89. E5
        sub     esp, 16                                 ; 080483A4 _ 83. EC, 10
        push    eax                                     ; 080483A7 _ 50
        push    offset _edata                           ; 080483A8 _ 68, 0804A008(d)
        call    edx                                     ; 080483AD _ FF. D2
        add     esp, 16                                 ; 080483AF _ 83. C4, 10
        leave                                           ; 080483B2 _ C9
?_006:
; Note: Prefix bit or byte has no meaning in this context
        ret                                             ; 080483B3 _ F3: C3

; Filling space: 0BH
; Filler type: lea with same source and destination
;       db 8DH, 74H, 26H, 00H, 8DH, 0BCH, 27H, 00H
;       db 00H, 00H, 00H

ALIGN   16

__do_global_dtors_aux LABEL NEAR
        cmp     byte ptr [_edata], 0                    ; 080483C0 _ 80. 3D, 0804A008(d), 00
        jnz     ?_007                                   ; 080483C7 _ 75, 13
        push    ebp                                     ; 080483C9 _ 55
        mov     ebp, esp                                ; 080483CA _ 89. E5
        sub     esp, 8                                  ; 080483CC _ 83. EC, 08
        call    deregister_tm_clones                    ; 080483CF _ E8, FFFFFF7C
        mov     byte ptr [_edata], 1                    ; 080483D4 _ C6. 05, 0804A008(d), 01
        leave                                           ; 080483DB _ C9
?_007:
; Note: Prefix bit or byte has no meaning in this context
        ret                                             ; 080483DC _ F3: C3

; Filling space: 2H
; Filler type: NOP with prefixes
;       db 66H, 90H

ALIGN   8

frame_dummy LABEL NEAR
        mov     eax, offset __JCR_LIST__                ; 080483E0 _ B8, 08049F04(d)
        mov     edx, dword ptr [eax]                    ; 080483E5 _ 8B. 10
        test    edx, edx                                ; 080483E7 _ 85. D2
        jnz     ?_009                                   ; 080483E9 _ 75, 05
?_008:  jmp     register_tm_clones                      ; 080483EB _ EB, 93

; Filling space: 3H
; Filler type: lea with same source and destination
;       db 8DH, 76H, 00H

ALIGN   8
?_009:  mov     edx, 0                                  ; 080483F0 _ BA, 00000000
        test    edx, edx                                ; 080483F5 _ 85. D2
        jz      ?_008                                   ; 080483F7 _ 74, F2
        push    ebp                                     ; 080483F9 _ 55
        mov     ebp, esp                                ; 080483FA _ 89. E5
        sub     esp, 20                                 ; 080483FC _ 83. EC, 14
        push    eax                                     ; 080483FF _ 50
        call    edx                                     ; 08048400 _ FF. D2
        add     esp, 16                                 ; 08048402 _ 83. C4, 10
        leave                                           ; 08048405 _ C9
        jmp     register_tm_clones                      ; 08048406 _ E9, FFFFFF75

main    PROC NEAR
        lea     ecx, [esp+4H]                           ; 0804840B _ 8D. 4C 24, 04
        and     esp, 0FFFFFFF0H                         ; 0804840F _ 83. E4, F0
        push    dword ptr [ecx-4H]                      ; 08048412 _ FF. 71, FC
        push    ebp                                     ; 08048415 _ 55
        mov     ebp, esp                                ; 08048416 _ 89. E5
        push    ecx                                     ; 08048418 _ 51
        sub     esp, 4                                  ; 08048419 _ 83. EC, 04
        sub     esp, 12                                 ; 0804841C _ 83. EC, 0C
        push    offset ?_012                            ; 0804841F _ 68, 080484C0(d)
        call    ?_002                                   ; 08048424 _ E8, FFFFFEC7(rel)
        add     esp, 16                                 ; 08048429 _ 83. C4, 10
        nop                                             ; 0804842C _ 90
        mov     ecx, dword ptr [ebp-4H]                 ; 0804842D _ 8B. 4D, FC
        leave                                           ; 08048430 _ C9
        lea     esp, [ecx-4H]                           ; 08048431 _ 8D. 61, FC
        ret                                             ; 08048434 _ C3
main    ENDP

; Filling space: 0BH
; Filler type: NOP with prefixes
;       db 66H, 90H, 66H, 90H, 66H, 90H, 66H, 90H
;       db 66H, 90H, 90H

ALIGN   16

__libc_csu_init PROC NEAR
        push    ebp                                     ; 08048440 _ 55
        push    edi                                     ; 08048441 _ 57
        push    esi                                     ; 08048442 _ 56
        push    ebx                                     ; 08048443 _ 53
        call    __x86.get_pc_thunk.bx                   ; 08048444 _ E8, FFFFFEF7
        add     ebx, 7071                               ; 08048449 _ 81. C3, 00001B9F
        sub     esp, 12                                 ; 0804844F _ 83. EC, 0C
        mov     ebp, dword ptr [esp+20H]                ; 08048452 _ 8B. 6C 24, 20
        lea     esi, [ebx-0E8H]                         ; 08048456 _ 8D. B3, FFFFFF18
        call    _init                                   ; 0804845C _ E8, FFFFFE57(rel)
        lea     eax, [ebx-0ECH]                         ; 08048461 _ 8D. 83, FFFFFF14
        sub     esi, eax                                ; 08048467 _ 29. C6
        sar     esi, 2                                  ; 08048469 _ C1. FE, 02
        test    esi, esi                                ; 0804846C _ 85. F6
        jz      ?_011                                   ; 0804846E _ 74, 25
        xor     edi, edi                                ; 08048470 _ 31. FF
; Filling space: 6H
; Filler type: lea with same source and destination
;       db 8DH, 0B6H, 00H, 00H, 00H, 00H

ALIGN   8
?_010:  sub     esp, 4                                  ; 08048478 _ 83. EC, 04
        push    dword ptr [esp+2CH]                     ; 0804847B _ FF. 74 24, 2C
        push    dword ptr [esp+2CH]                     ; 0804847F _ FF. 74 24, 2C
        push    ebp                                     ; 08048483 _ 55
        call    dword ptr [ebx+edi*4-0ECH]              ; 08048484 _ FF. 94 BB, FFFFFF14
        add     edi, 1                                  ; 0804848B _ 83. C7, 01
        add     esp, 16                                 ; 0804848E _ 83. C4, 10
        cmp     edi, esi                                ; 08048491 _ 39. F7
        jnz     ?_010                                   ; 08048493 _ 75, E3
?_011:  add     esp, 12                                 ; 08048495 _ 83. C4, 0C
        pop     ebx                                     ; 08048498 _ 5B
        pop     esi                                     ; 08048499 _ 5E
        pop     edi                                     ; 0804849A _ 5F
        pop     ebp                                     ; 0804849B _ 5D
        ret                                             ; 0804849C _ C3
__libc_csu_init ENDP

; Filling space: 3H
; Filler type: lea with same source and destination
;       db 8DH, 76H, 00H

ALIGN   8

__libc_csu_fini PROC NEAR
; Note: Prefix bit or byte has no meaning in this context
        ret                                             ; 080484A0 _ F3: C3
__libc_csu_fini ENDP

_text   ENDS

.fini   SEGMENT DWORD PUBLIC 'CODE'                     ; section number 14

_fini   PROC NEAR
        push    ebx                                     ; 080484A4 _ 53
        sub     esp, 8                                  ; 080484A5 _ 83. EC, 08
        call    __x86.get_pc_thunk.bx                   ; 080484A8 _ E8, FFFFFE93(rel)
        add     ebx, 6971                               ; 080484AD _ 81. C3, 00001B3B
        add     esp, 8                                  ; 080484B3 _ 83. C4, 08
        pop     ebx                                     ; 080484B6 _ 5B
        ret                                             ; 080484B7 _ C3
_fini   ENDP

.fini   ENDS

.rodata SEGMENT DWORD PUBLIC 'CONST'                    ; section number 15

_fp_hw  label dword
        dd 00000003H                                    ; 080484B8 _ 3 

_IO_stdin_used label dword
_IO_stdin_used label dword
        dd 00020001H                                    ; 080484BC _ 131073 

?_012   label byte
        db 67H, 6FH, 00H                                ; 080484C0 _ go.

.rodata ENDS

.eh_frame_hdr SEGMENT DWORD PUBLIC 'CONST'              ; section number 16

__GNU_EH_FRAME_HDR label byte
        db 01H, 1BH, 03H, 3BH, 28H, 00H, 00H, 00H       ; 080484C4 _ ...;(...
        db 04H, 00H, 00H, 00H, 1CH, 0FEH, 0FFH, 0FFH    ; 080484CC _ ........
        db 44H, 00H, 00H, 00H, 47H, 0FFH, 0FFH, 0FFH    ; 080484D4 _ D...G...
        db 68H, 00H, 00H, 00H, 7CH, 0FFH, 0FFH, 0FFH    ; 080484DC _ h...|...
        db 94H, 00H, 00H, 00H, 0DCH, 0FFH, 0FFH, 0FFH   ; 080484E4 _ ........
        db 0E0H, 00H, 00H, 00H                          ; 080484EC _ ....

.eh_frame_hdr ENDS

.eh_frame SEGMENT DWORD PUBLIC 'CONST'                  ; section number 17

        db 14H, 00H, 00H, 00H, 00H, 00H, 00H, 00H       ; 080484F0 _ ........
        db 01H, 7AH, 52H, 00H, 01H, 7CH, 08H, 01H       ; 080484F8 _ .zR..|..
        db 1BH, 0CH, 04H, 04H, 88H, 01H, 00H, 00H       ; 08048500 _ ........
        db 20H, 00H, 00H, 00H, 1CH, 00H, 00H, 00H       ; 08048508 _  .......
        db 0D0H, 0FDH, 0FFH, 0FFH, 10H, 00H, 00H, 00H   ; 08048510 _ ........
        db 00H, 0EH, 08H, 46H, 0EH, 0CH, 4AH, 0FH       ; 08048518 _ ...F..J.
        db 0BH, 74H, 04H, 78H, 00H, 3FH, 1AH, 3BH       ; 08048520 _ .t.x.?.;
        db 2AH, 32H, 24H, 22H, 28H, 00H, 00H, 00H       ; 08048528 _ *2$"(...
        db 40H, 00H, 00H, 00H, 0D7H, 0FEH, 0FFH, 0FFH   ; 08048530 _ @.......
        db 2AH, 00H, 00H, 00H, 00H, 44H, 0CH, 01H       ; 08048538 _ *....D..
        db 00H, 47H, 10H, 05H, 02H, 75H, 00H, 43H       ; 08048540 _ .G...u.C
        db 0FH, 03H, 75H, 7CH, 06H, 57H, 0CH, 01H       ; 08048548 _ ..u|.W..
        db 00H, 41H, 0C5H, 43H, 0CH, 04H, 04H, 00H      ; 08048550 _ .A.C....
        db 48H, 00H, 00H, 00H, 6CH, 00H, 00H, 00H       ; 08048558 _ H...l...
        db 0E0H, 0FEH, 0FFH, 0FFH, 5DH, 00H, 00H, 00H   ; 08048560 _ ....]...
        db 00H, 41H, 0EH, 08H, 85H, 02H, 41H, 0EH       ; 08048568 _ .A....A.
        db 0CH, 87H, 03H, 41H, 0EH, 10H, 86H, 04H       ; 08048570 _ ...A....
        db 41H, 0EH, 14H, 83H, 05H, 4EH, 0EH, 20H       ; 08048578 _ A....N. 
        db 69H, 0EH, 24H, 44H, 0EH, 28H, 44H, 0EH       ; 08048580 _ i.$D.(D.
        db 2CH, 41H, 0EH, 30H, 4DH, 0EH, 20H, 47H       ; 08048588 _ ,A.0M. G
        db 0EH, 14H, 41H, 0C3H, 0EH, 10H, 41H, 0C6H     ; 08048590 _ ..A...A.
        db 0EH, 0CH, 41H, 0C7H, 0EH, 08H, 41H, 0C5H     ; 08048598 _ ..A...A.
        db 0EH, 04H, 00H, 00H, 10H, 00H, 00H, 00H       ; 080485A0 _ ........
        db 0B8H, 00H, 00H, 00H, 0F4H, 0FEH, 0FFH, 0FFH  ; 080485A8 _ ........
        db 02H, 00H, 00H, 00H, 00H, 00H, 00H, 00H       ; 080485B0 _ ........

__FRAME_END__ label byte
        db 00H, 00H, 00H, 00H                           ; 080485B8 _ ....

.eh_frame ENDS

.init_array SEGMENT DWORD PUBLIC 'DATA'                 ; section number 18

__init_array_start label byte
__frame_dummy_init_array_entry label byte
        db 0E0H, 83H, 04H, 08H                          ; 08049EFC _ ....

.init_array ENDS

.fini_array SEGMENT DWORD PUBLIC 'DATA'                 ; section number 19

__init_array_end label byte
__do_global_dtors_aux_fini_array_entry label byte
        db 0C0H, 83H, 04H, 08H                          ; 08049F00 _ ....

.fini_array ENDS

.jcr    SEGMENT DWORD PUBLIC 'DATA'                     ; section number 20

__JCR_END__ label byte
__JCR_LIST__ label byte
        db 00H, 00H, 00H, 00H                           ; 08049F04 _ ....

.jcr    ENDS

.dynamic SEGMENT DWORD PUBLIC 'DATA'                    ; section number 21

_DYNAMIC label byte
        db 01H, 00H, 00H, 00H, 01H, 00H, 00H, 00H       ; 08049F08 _ ........
        db 0CH, 00H, 00H, 00H, 0B8H, 82H, 04H, 08H      ; 08049F10 _ ........
        db 0DH, 00H, 00H, 00H, 0A4H, 84H, 04H, 08H      ; 08049F18 _ ........
        db 19H, 00H, 00H, 00H, 0FCH, 9EH, 04H, 08H      ; 08049F20 _ ........
        db 1BH, 00H, 00H, 00H, 04H, 00H, 00H, 00H       ; 08049F28 _ ........
        db 1AH, 00H, 00H, 00H, 00H, 9FH, 04H, 08H       ; 08049F30 _ ........
        db 1CH, 00H, 00H, 00H, 04H, 00H, 00H, 00H       ; 08049F38 _ ........
        db 0F5H, 0FEH, 0FFH, 6FH, 0ACH, 81H, 04H, 08H   ; 08049F40 _ ...o....
        db 05H, 00H, 00H, 00H, 28H, 82H, 04H, 08H       ; 08049F48 _ ....(...
        db 06H, 00H, 00H, 00H, 0D8H, 81H, 04H, 08H      ; 08049F50 _ ........
        db 0AH, 00H, 00H, 00H, 4CH, 00H, 00H, 00H       ; 08049F58 _ ....L...
        db 0BH, 00H, 00H, 00H, 10H, 00H, 00H, 00H       ; 08049F60 _ ........
        db 15H, 00H, 00H, 00H, 00H, 00H, 00H, 00H       ; 08049F68 _ ........
        db 03H, 00H, 00H, 00H, 0E8H, 9FH, 04H, 08H      ; 08049F70 _ ........
        db 11H, 00H, 00H, 00H, 0A0H, 82H, 04H, 08H      ; 08049F78 _ ........
        db 12H, 00H, 00H, 00H, 18H, 00H, 00H, 00H       ; 08049F80 _ ........
        db 13H, 00H, 00H, 00H, 08H, 00H, 00H, 00H       ; 08049F88 _ ........
        db 18H, 00H, 00H, 00H, 00H, 00H, 00H, 00H       ; 08049F90 _ ........
        db 0FBH, 0FFH, 0FFH, 6FH, 01H, 00H, 00H, 00H    ; 08049F98 _ ...o....
        db 0FEH, 0FFH, 0FFH, 6FH, 80H, 82H, 04H, 08H    ; 08049FA0 _ ...o....
        db 0FFH, 0FFH, 0FFH, 6FH, 01H, 00H, 00H, 00H    ; 08049FA8 _ ...o....
        db 0F0H, 0FFH, 0FFH, 6FH, 74H, 82H, 04H, 08H    ; 08049FB0 _ ...ot...
        db 00H, 00H, 00H, 00H, 00H, 00H, 00H, 00H       ; 08049FB8 _ ........
        db 00H, 00H, 00H, 00H, 00H, 00H, 00H, 00H       ; 08049FC0 _ ........
        db 00H, 00H, 00H, 00H, 00H, 00H, 00H, 00H       ; 08049FC8 _ ........
        db 00H, 00H, 00H, 00H, 00H, 00H, 00H, 00H       ; 08049FD0 _ ........
        db 00H, 00H, 00H, 00H, 00H, 00H, 00H, 00H       ; 08049FD8 _ ........
        db 00H, 00H, 00H, 00H, 00H, 00H, 00H, 00H       ; 08049FE0 _ ........

.dynamic ENDS

.got    SEGMENT DWORD PUBLIC 'DATA'                     ; section number 22

_GLOBAL_OFFSET_TABLE_ label byte
        db 08H, 9FH, 04H, 08H                           ; 08049FE8 _ ....

?_013   label dword
        dd 00000000H                                    ; 08049FEC _ 0 

?_014   label dword                                     ; switch/case jump table
        dd 00000000H                                    ; 08049FF0 _ 00000000 

?_015   label dword                                     ; switch/case jump table
        dd printf                                       ; 08049FF4 _ 00000000 (GOT)

?_016   label dword                                     ; switch/case jump table
        dd __gmon_start__                               ; 08049FF8 _ 00000000 (GOT)

?_017   label dword                                     ; switch/case jump table
        dd __libc_start_main                            ; 08049FFC _ 00000000 (GOT)

.got    ENDS

_data   SEGMENT DWORD PUBLIC 'DATA'                     ; section number 23

__data_start label byte
data_start label byte
        db 00H, 00H, 00H, 00H                           ; 0804A000 _ ....

__dso_handle label byte
        db 00H, 00H, 00H, 00H                           ; 0804A004 _ ....

_data   ENDS

.bss    SEGMENT BYTE PUBLIC 'BSS'                       ; section number 24

__TMC_END__ label byte
__bss_start label byte
_edata  label byte
completed.7209 label byte
        db      3 dup (?)                               ; 0804A008

?_018   label byte
        db      ?                                       ; 0804A00B

.bss    ENDS

END