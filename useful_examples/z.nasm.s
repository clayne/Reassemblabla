; objdump -D -b binary -mi386 z
SECTION .text       ; code section
global main
main:

 sub [edi], strict dword 0x55
 sub [edi], dword 0x55
