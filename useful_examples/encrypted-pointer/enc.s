.global main
.align 16
myfunc1: # 080483a0
    movl $4, %eax
    movl $1, %ebx
    movl $mystr, %ecx
    movl $len, %edx
    int $0x80
    add $0x4, %esp
    call myexit

myexit:
    movl $1, %eax
    movl $3, %ebx
    addl $128, 4(%esp)
    movl 4(%esp), %ebx
    int $0x80

main:
 lea 0x181493b, %ebx
 lea 0x10, %eax
 mul %ebx               # result in %eax
 xor $0x10101010, %eax  # 0x80483a0 (myfunc1)
 
 jmp %eax               # jmp myfunc  

.section .data
    mystr:
    .string "Hello World...\n"
    len = . - mystr

