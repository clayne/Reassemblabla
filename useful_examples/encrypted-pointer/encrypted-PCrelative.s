.global main
.align 16
myfunc1: # 0x080483a0
    movl $4, %eax
    movl $1, %ebx
    movl $mystr, %ecx
    movl $len, %edx
    int $0x80
    add $0x4, %esp
    call myexit

get_pc_thunk.bx:
    mov (%esp),%ebx
    ret

myexit:
    movl $1, %eax
    movl $3, %ebx
    addl $128, 4(%esp)
    movl 4(%esp), %ebx
    int $0x80

main:
    call get_pc_thunk.bx 
    xor $0x10101010, %ebx 
    sub $0x1010102f, %ebx # 0x080483a0 
    jmp %ebx
  

.section .data
    mystr:
    .string "Successed to ref calculated func pointer.\n"
    len = . - mystr

