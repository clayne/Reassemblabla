.global main
main:
    push %eip
    mov (%esp), %ebx
    pop %esp
    add $_GLOBAL_OFFSET_TABLE_, %ebx

