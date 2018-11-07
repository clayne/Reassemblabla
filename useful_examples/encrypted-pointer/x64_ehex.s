global _start
%define stdout 1
%define sys_signal 48
%define SIGINT 2
%define SIGSEGV 11

section .text
exit:
    mov eax, 60
    mov rdi, 0
    syscall
catch:
    mov eax, 1
    mov rdi, stdout
    lea rsi, [message]
    mov rdx, 15
    syscall
    jmp exit

_start:
    ; jmp catch
    mov eax, sys_signal
    mov ebx, SIGINT
    mov ecx, catch
    int 80h
loop:
    jmp loop

section .data
    message: db "Signal caught!", 10
