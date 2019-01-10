.global _start
XXX:
 ret

.section .init
.align 16
_init: 
 pushl %ebx
#=> ADDR:0x380 BYTE:53
 subl $8, %esp
#=> ADDR:0x381 BYTE:83ec08
 calll __x86.get_pc_thunk.0.bx
#=> ADDR:0x384 BYTE:e847000000
 addl $0x1c77, %ebx
#=> ADDR:0x389 BYTE:81c3771c0000
 movl.d32 MYSYM_PIE_7, %eax
#=> ADDR:0x38f BYTE:8b83f4ffffff
 testl %eax, %eax
#=> ADDR:0x395 BYTE:85c0
 je MYSYM_8
#=> ADDR:0x397 BYTE:7405
 calll XXX 
#=> ADDR:0x399 BYTE:e82a000000
MYSYM_8:
 addl $8, %esp
#=> ADDR:0x39e BYTE:83c408
 popl %ebx
#=> ADDR:0x3a1 BYTE:5b
 retl 
#=> ADDR:0x3a2 BYTE:c3

.section .init_array
.align 16
 .long MYSYM_DATA_1
#=> ADDR:0x1f10 BYTE:000004c0

.section .fini_array
.align 16
 .long MYSYM_DATA_2
#=> ADDR:0x1f14 BYTE:00000470

.section .got
.align 16
MYSYM_PIE_2:
 .byte 0x00
#=> ADDR:0x1fec BYTE:00
 .byte 0x00
#=> ADDR:0x1fed BYTE:00
 .byte 0x00
#=> ADDR:0x1fee BYTE:00
 .byte 0x00
#=> ADDR:0x1fef BYTE:00
MYSYM_PIE_4:
 .byte 0x00
#=> ADDR:0x1ff0 BYTE:00
 .byte 0x00
#=> ADDR:0x1ff1 BYTE:00
 .byte 0x00
#=> ADDR:0x1ff2 BYTE:00
 .byte 0x00
#=> ADDR:0x1ff3 BYTE:00
MYSYM_PIE_7:
 .byte 0x00
#=> ADDR:0x1ff4 BYTE:00
 .byte 0x00
#=> ADDR:0x1ff5 BYTE:00
 .byte 0x00
#=> ADDR:0x1ff6 BYTE:00
 .byte 0x00
#=> ADDR:0x1ff7 BYTE:00
MYSYM_PIE_6:
 .byte 0x00
#=> ADDR:0x1ff8 BYTE:00
 .byte 0x00
#=> ADDR:0x1ff9 BYTE:00
 .byte 0x00
#=> ADDR:0x1ffa BYTE:00
 .byte 0x00
#=> ADDR:0x1ffb BYTE:00
MYSYM_PIE_3:
 .byte 0x00
#=> ADDR:0x1ffc BYTE:00
 .byte 0x00
#=> ADDR:0x1ffd BYTE:00
 .byte 0x00
#=> ADDR:0x1ffe BYTE:00
 .byte 0x00
#=> ADDR:0x1fff BYTE:00

.section .fini
.align 16
_fini: 
 pushl %ebx
#=> ADDR:0x530 BYTE:53
 subl $8, %esp
#=> ADDR:0x531 BYTE:83ec08
 calll __x86.get_pc_thunk.0.bx
#=> ADDR:0x534 BYTE:e897feffff
 addl $0x1ac7, %ebx
#=> ADDR:0x539 BYTE:81c3c71a0000
 addl $8, %esp
#=> ADDR:0x53f BYTE:83c408
 popl %ebx
#=> ADDR:0x542 BYTE:5b
 retl 
#=> ADDR:0x543 BYTE:c3

.section .jcr
.align 16
MYSYM_PIE_5:
 .byte 0x00
#=> ADDR:0x1f18 BYTE:00
 .byte 0x00
#=> ADDR:0x1f19 BYTE:00
 .byte 0x00
#=> ADDR:0x1f1a BYTE:00
 .byte 0x00
#=> ADDR:0x1f1b BYTE:00

.section .data
.align 16
MYSYM_DATA_0:
 .long MYSYM_DATA_0
#=> ADDR:0x200c BYTE:0000200c

.section .text
.align 16
__x86.get_pc_thunk.0.bx:
 movl 0(%esp), %ebx
#=> ADDR:0x3d0 BYTE:8b1c24
 retl 
#=> ADDR:0x3d3 BYTE:c3
 .byte 0x66
#=> ADDR:0x3d4 BYTE:66
 nop 
#=> ADDR:0x3d5 BYTE:90
 .byte 0x66
#=> ADDR:0x3d6 BYTE:66
 nop 
#=> ADDR:0x3d7 BYTE:90
 .byte 0x66
#=> ADDR:0x3d8 BYTE:66
 nop 
#=> ADDR:0x3d9 BYTE:90
 .byte 0x66
#=> ADDR:0x3da BYTE:66
 nop 
#=> ADDR:0x3db BYTE:90
 .byte 0x66
#=> ADDR:0x3dc BYTE:66
 nop 
#=> ADDR:0x3dd BYTE:90
 .byte 0x66
#=> ADDR:0x3de BYTE:66
 nop 
#=> ADDR:0x3df BYTE:90
MYSYM_4:
 calll __x86.get_pc_thunk.1.dx
#=> ADDR:0x3e0 BYTE:e817010000
 addl $0x1c1b, %edx
#=> ADDR:0x3e5 BYTE:81c21b1c0000
 leal.d32 __bss_start, %ecx
#=> ADDR:0x3eb BYTE:8d8a10000000
 leal.d32 MYSYM_PIE_1, %eax
#=> ADDR:0x3f1 BYTE:8d8213000000
 subl %ecx, %eax
#=> ADDR:0x3f7 BYTE:29c8
 cmpl $6, %eax
#=> ADDR:0x3f9 BYTE:83f806
 jbe MYSYM_0
#=> ADDR:0x3fc BYTE:7617
 movl.d32 MYSYM_PIE_2, %eax
#=> ADDR:0x3fe BYTE:8b82ecffffff
 testl %eax, %eax
#=> ADDR:0x404 BYTE:85c0
 je MYSYM_0
#=> ADDR:0x406 BYTE:740d
 pushl %ebp
#=> ADDR:0x408 BYTE:55
 movl %esp, %ebp
#=> ADDR:0x409 BYTE:89e5
 subl $0x14, %esp
#=> ADDR:0x40b BYTE:83ec14
 pushl %ecx
#=> ADDR:0x40e BYTE:51
 calll *%eax
#=> ADDR:0x40f BYTE:ffd0
 addl $0x10, %esp
#=> ADDR:0x411 BYTE:83c410
 leave 
#=> ADDR:0x414 BYTE:c9
MYSYM_0:
rep
#=> ADDR:0x415 BYTE:f3
 retl 
#=> ADDR:0x416 BYTE:c3
 movl %esi, %esi
#=> ADDR:0x417 BYTE:89f6
 leal.d32 0(%edi), %edi
#=> ADDR:0x419 BYTE:8dbc2700000000
MYSYM_6:
 calll __x86.get_pc_thunk.1.dx
#=> ADDR:0x420 BYTE:e8d7000000
 addl $0x1bdb, %edx
#=> ADDR:0x425 BYTE:81c2db1b0000
 pushl %ebp
#=> ADDR:0x42b BYTE:55
 leal.d32 __bss_start, %ecx
#=> ADDR:0x42c BYTE:8d8a10000000
 leal.d32 __bss_start, %eax
#=> ADDR:0x432 BYTE:8d8210000000
 movl %esp, %ebp
#=> ADDR:0x438 BYTE:89e5
 pushl %ebx
#=> ADDR:0x43a BYTE:53
 subl %ecx, %eax
#=> ADDR:0x43b BYTE:29c8
 sarl $2, %eax
#=> ADDR:0x43d BYTE:c1f802
 subl $4, %esp
#=> ADDR:0x440 BYTE:83ec04
 movl %eax, %ebx
#=> ADDR:0x443 BYTE:89c3
 shrl $0x1f, %ebx
#=> ADDR:0x445 BYTE:c1eb1f
 addl %ebx, %eax
#=> ADDR:0x448 BYTE:01d8
 sarl $1, %eax
#=> ADDR:0x44a BYTE:d1f8
 je MYSYM_1
#=> ADDR:0x44c BYTE:7414
 movl.d32 MYSYM_PIE_3, %edx
#=> ADDR:0x44e BYTE:8b92fcffffff
 testl %edx, %edx
#=> ADDR:0x454 BYTE:85d2
 je MYSYM_1
#=> ADDR:0x456 BYTE:740a
 subl $8, %esp
#=> ADDR:0x458 BYTE:83ec08
 pushl %eax
#=> ADDR:0x45b BYTE:50
 pushl %ecx
#=> ADDR:0x45c BYTE:51
 calll *%edx
#=> ADDR:0x45d BYTE:ffd2
 addl $0x10, %esp
#=> ADDR:0x45f BYTE:83c410
MYSYM_1:
 movl.d8 -4(%ebp), %ebx
#=> ADDR:0x462 BYTE:8b5dfc
 leave 
#=> ADDR:0x465 BYTE:c9
 retl 
#=> ADDR:0x466 BYTE:c3
 movl %esi, %esi
#=> ADDR:0x467 BYTE:89f6
 leal.d32 0(%edi), %edi
#=> ADDR:0x469 BYTE:8dbc2700000000
MYSYM_DATA_2:
 pushl %ebp
#=> ADDR:0x470 BYTE:55
 movl %esp, %ebp
#=> ADDR:0x471 BYTE:89e5
 pushl %ebx
#=> ADDR:0x473 BYTE:53
 calll __x86.get_pc_thunk.0.bx
#=> ADDR:0x474 BYTE:e857ffffff
 addl $0x1b87, %ebx
#=> ADDR:0x479 BYTE:81c3871b0000
 subl $4, %esp
#=> ADDR:0x47f BYTE:83ec04
 cmpb.d32 $0, 0x10(%ebx)
#=> ADDR:0x482 BYTE:80bb1000000000
 jne MYSYM_2
#=> ADDR:0x489 BYTE:7527
 movl.d32 MYSYM_PIE_4, %eax
#=> ADDR:0x48b BYTE:8b83f0ffffff
 testl %eax, %eax
#=> ADDR:0x491 BYTE:85c0
 je MYSYM_3
#=> ADDR:0x493 BYTE:7411
 subl $0xc, %esp
#=> ADDR:0x495 BYTE:83ec0c
 pushl.d32 MYSYM_DATA_0
#=> ADDR:0x498 BYTE:ffb30c000000
 calll XXX 
#=> ADDR:0x49e BYTE:e81dffffff
 addl $0x10, %esp
#=> ADDR:0x4a3 BYTE:83c410
MYSYM_3:
 calll MYSYM_4
#=> ADDR:0x4a6 BYTE:e835ffffff
 movb.d32 $1, 0x10(%ebx)
#=> ADDR:0x4ab BYTE:c6831000000001
MYSYM_2:
 movl.d8 -4(%ebp), %ebx
#=> ADDR:0x4b2 BYTE:8b5dfc
 leave 
#=> ADDR:0x4b5 BYTE:c9
 retl 
#=> ADDR:0x4b6 BYTE:c3
 movl %esi, %esi
#=> ADDR:0x4b7 BYTE:89f6
 leal.d32 0(%edi), %edi
#=> ADDR:0x4b9 BYTE:8dbc2700000000
MYSYM_DATA_1:
 calll __x86.get_pc_thunk.1.dx
#=> ADDR:0x4c0 BYTE:e837000000
 addl $0x1b3b, %edx
#=> ADDR:0x4c5 BYTE:81c23b1b0000
 leal.d32 MYSYM_PIE_5, %eax
#=> ADDR:0x4cb BYTE:8d8218ffffff
 movl MYSYM_PIE_5, %ecx
#=> ADDR:0x4d1 BYTE:8b08
 testl %ecx, %ecx
#=> ADDR:0x4d3 BYTE:85c9
 jne MYSYM_5
#=> ADDR:0x4d5 BYTE:7509
MYSYM_7:
 jmp.d32 MYSYM_6
#=> ADDR:0x4d7 BYTE:e944ffffff
 leal.d8 0(%esi), %esi
#=> ADDR:0x4dc BYTE:8d742600
MYSYM_5:
 movl.d32 MYSYM_PIE_6, %edx
#=> ADDR:0x4e0 BYTE:8b92f8ffffff
 testl %edx, %edx
#=> ADDR:0x4e6 BYTE:85d2
 je MYSYM_7
#=> ADDR:0x4e8 BYTE:74ed
 pushl %ebp
#=> ADDR:0x4ea BYTE:55
 movl %esp, %ebp
#=> ADDR:0x4eb BYTE:89e5
 subl $0x14, %esp
#=> ADDR:0x4ed BYTE:83ec14
 pushl %eax
#=> ADDR:0x4f0 BYTE:50
 calll *%edx
#=> ADDR:0x4f1 BYTE:ffd2
 addl $0x10, %esp
#=> ADDR:0x4f3 BYTE:83c410
 leave 
#=> ADDR:0x4f6 BYTE:c9
 jmp.d32 MYSYM_6
#=> ADDR:0x4f7 BYTE:e924ffffff
__x86.get_pc_thunk.1.dx:
 movl 0(%esp), %edx
#=> ADDR:0x4fc BYTE:8b1424
 retl 
#=> ADDR:0x4ff BYTE:c3
 pushl %ebp
#=> ADDR:0x500 BYTE:55
 movl %esp, %ebp
#=> ADDR:0x501 BYTE:89e5
 calll __x86.get_pc_thunk.2.ax
#=> ADDR:0x503 BYTE:e824000000
 addl $0x1af8, %eax
#=> ADDR:0x508 BYTE:05f81a0000
 movl.d8 8(%ebp), %edx
#=> ADDR:0x50d BYTE:8b5508
 movl.d8 0xc(%ebp), %eax
#=> ADDR:0x510 BYTE:8b450c
 addl %edx, %eax
#=> ADDR:0x513 BYTE:01d0
 popl %ebp
#=> ADDR:0x515 BYTE:5d
 retl 
#=> ADDR:0x516 BYTE:c3
 pushl %ebp
#=> ADDR:0x517 BYTE:55
 movl %esp, %ebp
#=> ADDR:0x518 BYTE:89e5
 calll __x86.get_pc_thunk.2.ax
#=> ADDR:0x51a BYTE:e80d000000
 addl $0x1ae1, %eax
#=> ADDR:0x51f BYTE:05e11a0000
 movl.d8 8(%ebp), %eax
#=> ADDR:0x524 BYTE:8b4508
 subl.d8 0xc(%ebp), %eax
#=> ADDR:0x527 BYTE:2b450c
 popl %ebp
#=> ADDR:0x52a BYTE:5d
 retl 
#=> ADDR:0x52b BYTE:c3
__x86.get_pc_thunk.2.ax:
 movl 0(%esp), %eax
#=> ADDR:0x52c BYTE:8b0424
 retl 
#=> ADDR:0x52f BYTE:c3

.section .bss
.align 16
DUMMY___bss_start:
 .byte 0x00
#=> ADDR:0x2010 BYTE:00
 .byte 0x00
#=> ADDR:0x2011 BYTE:00
 .byte 0x00
#=> ADDR:0x2012 BYTE:00
MYSYM_PIE_1:
 .byte 0x00
#=> ADDR:0x2013 BYTE:00
