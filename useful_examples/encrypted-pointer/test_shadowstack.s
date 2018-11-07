.global main

.section .text
    .lcomm MYSYM_EFLAGS, 4
    .lcomm MYSYM_EAX, 4
    .lcomm MYSYM_ECX, 4
    .lcomm MYSYM_EDX, 4
    .lcomm MYSYM_EBX, 4
    .lcomm MYSYM_TEMP,4
    .lcomm MYSYM_EBP, 4
    .lcomm MYSYM_ESI, 4
    .lcomm MYSYM_EDI, 4



MYSYM_pushal:
    mov %eax, MYSYM_EAX
    mov %ecx, MYSYM_ECX
    mov %edx, MYSYM_EDX
    mov %ebx, MYSYM_EBX
    mov %ebp, MYSYM_EBP
    mov %esi, MYSYM_ESI
    mov %edi, MYSYM_EDI
    ret
   

MYSYM_popal:
    mov MYSYM_EAX, %eax
    mov MYSYM_ECX, %ecx
    mov MYSYM_EDX, %edx
    mov MYSYM_EBX, %ebx
    mov MYSYM_EBP, %ebp
    mov MYSYM_ESI, %esi
    mov MYSYM_EDI, %edi
    ret


MYSYM_pushf:
    push %eax               # I cant move from memory to memory
    pushf                   # EFLAGS -> (%esp) 
    mov 0x0(%esp), %eax     #           (%esp) -> %eax
    mov %eax, MYSYM_EFLAGS  #                     %eax -> MYSYM_EFLAGS
    add $0x4, %esp          # stack revoke : pushf
    pop %eax                # value revoke : %eax
    ret

MYSYM_popf:
    push MYSYM_EFLAGS
    popf

main:

  # call MYSYM_pushal
  # call MYSYM_popal
    call MYSYM_pushf
    call MYSYM_popf
    nop
