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
.align 32
MYSYM_1:
 .byte 0x67
 .byte 0x6f
 .byte 0x00

.section .data
.align 16
 .byte 0x00
 .byte 0x00
 .byte 0x00
 .byte 0x00
 .byte 0x00
 .byte 0x00
 .byte 0x00
 .byte 0x00

.section .bss
.align 16
MYSYM_9:
 .byte 0x00
 .byte 0x00
 .byte 0x00
MYSYM_8:
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
 push $MYSYM_5
 push $MYSYM_6
 push %ecx
 push %esi
 push $MYSYM_7
 call __libc_start_main 
 hlt
 xchg %ax,%ax
 xchg %ax,%ax
 xchg %ax,%ax
 xchg %ax,%ax
 xchg %ax,%ax
 xchg %ax,%ax
 xchg %ax,%ax
MYSYM_2:
 mov (%esp),%ebx
 ret
 xchg %ax,%ax
 xchg %ax,%ax
 xchg %ax,%ax
 xchg %ax,%ax
 xchg %ax,%ax
 xchg %ax,%ax
MYSYM_13:
 mov $MYSYM_8,%eax
 sub $MYSYM_9,%eax
 cmp $0x6,%eax
 jbe MYSYM_10 
 mov $0x0,%eax
 test %eax,%eax
 je MYSYM_10 
 push %ebp
 mov %esp,%ebp
 sub $0x14,%esp
 push $MYSYM_9
 call *%eax
 add $0x10,%esp
 leave
MYSYM_10:
 repz ret
 nop
.p2align 5,,31
MYSYM_0:
 mov $MYSYM_9,%eax
 sub $MYSYM_9,%eax
 sar $0x2,%eax
 mov %eax,%edx
 shr $0x1f,%edx
 add %edx,%eax
 sar %eax
 je MYSYM_11 
 mov $0x0,%edx
 test %edx,%edx
 je MYSYM_11 
 push %ebp
 mov %esp,%ebp
 sub $0x10,%esp
 push %eax
 push $MYSYM_9
 call *%edx
 add $0x10,%esp
 leave
MYSYM_11:
 repz ret
.p2align 5,,31
 cmpb $0x0,MYSYM_9
 jne MYSYM_12 
 push %ebp
 mov %esp,%ebp
 sub $0x8,%esp
 call MYSYM_13 
 movb $0x1,MYSYM_9
 leave
MYSYM_12:
 repz ret
 xchg %ax,%ax
 mov $0x8049f04,%eax
 mov (%eax),%edx
 test %edx,%edx
 jne MYSYM_14 
MYSYM_15:
 jmp MYSYM_0 
 lea 0x0(%esi),%esi
MYSYM_14:
 mov $0x0,%edx
 test %edx,%edx
 je MYSYM_15 
 push %ebp
 mov %esp,%ebp
 sub $0x14,%esp
 push %eax
 call *%edx
 add $0x10,%esp
 leave
 jmp MYSYM_0 
MYSYM_7:
 lea 0x4(%esp),%ecx
 and $0xfffffff0,%esp
 pushl -0x4(%ecx)
 push %ebp
 mov %esp,%ebp
 push %ecx
 sub $0x4,%esp
 sub $0xc,%esp
 push $MYSYM_1
 call printf 
 add $0x10,%esp
 nop
 mov -0x4(%ebp),%ecx
 leave
 lea -0x4(%ecx),%esp
 ret
 xchg %ax,%ax
 xchg %ax,%ax
 xchg %ax,%ax
 xchg %ax,%ax
 xchg %ax,%ax
 nop
MYSYM_6:
 push %ebp
 push %edi
 push %esi
 push %ebx
 call MYSYM_2 
 add $0x1b9f,%ebx
 sub $0xc,%esp
 mov 0x20(%esp),%ebp
 lea -0xe8(%ebx),%esi
 call XXX  
 lea -0xec(%ebx),%eax
 sub %eax,%esi
 sar $0x2,%esi
 test %esi,%esi
 je MYSYM_3 
 xor %edi,%edi
 lea 0x0(%esi),%esi
MYSYM_4:
 sub $0x4,%esp
 pushl 0x2c(%esp)
 pushl 0x2c(%esp)
 push %ebp
 call *-0xec(%ebx,%edi,4)
 add $0x1,%edi
 add $0x10,%esp
 cmp %esi,%edi
 jne MYSYM_4 
MYSYM_3:
 add $0xc,%esp
 pop %ebx
 pop %esi
 pop %edi
 pop %ebp
 ret
 lea 0x0(%esi),%esi
MYSYM_5:
 repz ret
