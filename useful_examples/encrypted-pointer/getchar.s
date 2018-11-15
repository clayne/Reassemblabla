.global main

myfunc1: # 080483a0
    movl $4, %eax
    movl $1, %ebx
    movl $mystr, %ecx
    movl $len, %edx
    int $0x80
    ret

main:
 call myfunc1
 call getchar
 call myfunc1
 ret

.section .data
    mystr:
    .string "Successed to ref calculated func pointer.\n"
    len = . - mystr

