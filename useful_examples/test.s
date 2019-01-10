# gcc -o test test.s -Wl,-z,relro,-z,now

.global main




.section .text 
main:
    .lcomm MYSYM_HEREIS_GLOBAL_OFFSET_TABLE_,4
    call get_pc_thunk.bx
    add $_GLOBAL_OFFSET_TABLE_, %ebx
    mov %ebx, MYSYM_HEREIS_GLOBAL_OFFSET_TABLE_
    mov MYSYM_HEREIS_GLOBAL_OFFSET_TABLE_, %eax
    cmp MYSYM_HEREIS_GLOBAL_OFFSET_TABLE_, %ebx
    je MYSYM_YES

get_pc_thunk.bx:
    mov (%esp), %ebx
    ret

MYSYM_YES:
    nop
    nop
    nop
    nop
