.global _start
XXX:

.section .rodata
.align 16
 .byte 0x03
 .byte 0x00
 .byte 0x00
 .byte 0x00
 .byte 0x01
 .byte 0x00
 .byte 0x02
 .byte 0x00
 .byte 0x67
 .byte 0x6f
 .byte 0x00

.section .data
.align 16
 .byte 0x00
 .byte 0x00
 .byte 0x00
 .byte 0x00
MYSYM_DATA_0:
 .long MYSYM_DATA_0

.section .bss
.align 16
DUMMY___bss_start:
 .byte 0x00
 .byte 0x00
 .byte 0x00
 .byte 0x00

.section .text
.align 16
_start:
 xor %ebp,%ebp
 pop %esi
 mov %esp,%ecx
 and $0xfffffff0,%esp
 push %eax
 push %esp
 push %edx
 call MYSYM_2 
 add $0x1b70,%ebx
 lea -0x1970(%ebx),%eax
 push %eax
 lea -0x19d0(%ebx),%eax
 push %eax
 push %ecx
 push %esi
 pushl -0xc(%ebx)
 call __libc_start_main
 hlt
MYSYM_2:
 mov (%esp),%ebx
 ret
 xchg %ax,%ax
 xchg %ax,%ax
 xchg %ax,%ax
 xchg %ax,%ax
 xchg %ax,%ax
MYSYM_0:
 mov (%esp),%ebx
 ret
 xchg %ax,%ax
 xchg %ax,%ax
 xchg %ax,%ax
 xchg %ax,%ax
 xchg %ax,%ax
 xchg %ax,%ax
MYSYM_9:
 call MYSYM_3 
 add $0x1b2b,%edx
 lea 0x1c(%edx),%ecx
 lea 0x1f(%edx),%eax
 sub %ecx,%eax
 cmp $0x6,%eax
 jbe MYSYM_4 
 mov -0x18(%edx),%eax
 test %eax,%eax
 je MYSYM_4 
 push %ebp
 mov %esp,%ebp
 sub $0x14,%esp
 push %ecx
 call *%eax
 add $0x10,%esp
 leave
MYSYM_4:
 repz ret
 mov %esi,%esi
.p2align 4,,15
MYSYM_11:
 call MYSYM_3 
 add $0x1aeb,%edx
 push %ebp
 lea 0x1c(%edx),%ecx
 lea 0x1c(%edx),%eax
 mov %esp,%ebp
 push %ebx
 sub %ecx,%eax
 sar $0x2,%eax
 sub $0x4,%esp
 mov %eax,%ebx
 shr $0x1f,%ebx
 add %ebx,%eax
 sar %eax
 je MYSYM_6 
 mov -0x4(%edx),%edx
 test %edx,%edx
 je MYSYM_6 
 sub $0x8,%esp
 push %eax
 push %ecx
 call *%edx
 add $0x10,%esp
MYSYM_6:
 mov -0x4(%ebp),%ebx
 leave
 ret
 mov %esi,%esi
.p2align 5,,31
 push %ebp
 mov %esp,%ebp
 push %ebx
 call MYSYM_0 
 add $0x1a97,%ebx
 sub $0x4,%esp
 cmpb $0x0,0x1c(%ebx)
 jne MYSYM_7 
 mov -0x14(%ebx),%eax
 test %eax,%eax
 je MYSYM_8 
 sub $0xc,%esp
 pushl 0x18(%ebx)
 call XXX  
 add $0x10,%esp
MYSYM_8:
 call MYSYM_9 
 movb $0x1,0x1c(%ebx)
MYSYM_7:
 mov -0x4(%ebp),%ebx
 leave
 ret
 mov %esi,%esi
.p2align 4,,15
 call MYSYM_3 
 add $0x1a4b,%edx
 lea -0x10c(%edx),%eax
 mov (%eax),%ecx
 test %ecx,%ecx
 jne MYSYM_10 
MYSYM_12:
 jmp MYSYM_11 
.p2align 4,,15
MYSYM_10:
 mov -0x8(%edx),%edx
 test %edx,%edx
 je MYSYM_12 
 push %ebp
 mov %esp,%ebp
 sub $0x14,%esp
 push %eax
 call *%edx
 add $0x10,%esp
 leave
 jmp MYSYM_11 
MYSYM_3:
 mov (%esp),%edx
 ret
 lea 0x4(%esp),%ecx
 and $0xfffffff0,%esp
 pushl -0x4(%ecx)
 push %ebp
 mov %esp,%ebp
 push %ebx
 push %ecx
 call MYSYM_13 
 add $0x19fc,%eax
 sub $0xc,%esp
 lea -0x1950(%eax),%edx
 push %edx
 mov %eax,%ebx
 call printf
 add $0x10,%esp
 nop
 lea -0x8(%ebp),%esp
 pop %ecx
 pop %ebx
 pop %ebp
 lea -0x4(%ecx),%esp
 ret
MYSYM_13:
 mov (%esp),%eax
 ret
 xchg %ax,%ax
 xchg %ax,%ax
 push %ebp
 push %edi
 push %esi
 push %ebx
 call MYSYM_0 
 add $0x19c7,%ebx
 sub $0xc,%esp
 mov 0x20(%esp),%ebp
 lea -0x110(%ebx),%esi
 call XXX  
 lea -0x114(%ebx),%eax
 sub %eax,%esi
 sar $0x2,%esi
 test %esi,%esi
 je MYSYM_1 
 xor %edi,%edi
 lea 0x0(%esi),%esi
MYSYM_5:
 sub $0x4,%esp
 pushl 0x2c(%esp)
 pushl 0x2c(%esp)
 push %ebp
 call *-0x114(%ebx,%edi,4)
 add $0x1,%edi
 add $0x10,%esp
 cmp %esi,%edi
 jne MYSYM_5 
MYSYM_1:
 add $0xc,%esp
 pop %ebx
 pop %esi
 pop %edi
 pop %ebp
 ret
 lea 0x0(%esi),%esi
 repz ret
