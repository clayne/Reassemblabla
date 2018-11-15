# $ as -o sigaction.o sigaction.s
# $ ld --dynamic-linker /lib/ld-linux.so.2 -lc -o sigaction sigaction.o
# $ ./sigaction 
# ^CExiting...
# $ echo $?

.section .data
#.set SIGSEGV, 11
#.set SA_SIGINFO, 4

mystr:
    .string "Signal handling...\n"
	len = . - mystr
.section bss

.section .text
.global main
.lcomm my_sigaction, 140 # size of sigaction struction is 140
.set SIGSEGV, 11
.set SA_SIGINFO, 4


SYM_myprintstr:
    movl $4, %eax
    movl $1, %ebx
    movl $mystr, %ecx
    movl $len, %edx
    int $0x80
    add $0x4, %esp
    ret

myexit:
    movl $1, %eax
    movl $3, %ebx
    addl $128, 4(%esp)
    movl 4(%esp), %ebx
    int $0x80
    

myhandler:
    mov 0x1c(%esp), %eax
    add $0x5ec, %esp                       # Stack usage until run into the myhandler
    cmp $0x11223344, %eax
    je SYM_myprintstr


main:
	movl $myhandler, my_sigaction           # 1. sa_handler field	
	movl $132, %edi                         # 2. sa_flags field
	movl $SA_SIGINFO, my_sigaction(,%edi,1) #    == dword ptr [edi + 0x80492b8], 4
                                            #       SA_SIGINFO means whenever signal appears, run the signal handling function.

	# Calling sigaction(int, const struct sigaction *, struct sigaction *)
	pushl $0                                # 1st param : oact
	pushl $my_sigaction                     # 2nd param : act
	pushl $SIGSEGV                          # 3rd param : sig
	call sigaction
	addl $12, %esp
	
    #=========================================================================================================================#
    push $0x77777777                       # Stack magic value: here is the end of the stack 
    bphere:
	# jmp 0x11223344                       # Segmantation fault. Let's assume that 0x11223344 is actually refers SYM_myprintstr
    # mov 0x11223344, %eax
    lea %eax, 0x11223344
    nop
