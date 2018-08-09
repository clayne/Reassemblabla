; nasm -o nasm.o -f elf nasm.s
segment .data
    STRING: db "Hello World!", 0xa, 0xd
    LEN   : equ $-STRING

segment .text
    global _start
_start:
    mov eax, 0x4
    xor ebx, ebx
    mov ecx, STRING
    mov edx, LEN
    int 0x80
    
    mov eax, 0x1
    xor ebx, ebx
    int 0x80
