.global main
my_handler:
 push mystring
 call printf 
main:
 push $my_handler
 lea (%esp), %eax
 push $0x0
 push %eax
 push $0xb # SIGSEGV
 call sigaction
 jmp 0x12341234
 nop
 nop
 nop
 nop

mystring:
 .string "Exception!!!"
