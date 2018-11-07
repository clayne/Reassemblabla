.global main

MYFUNC:
 push %eax
 pop %eax
 ret

main:
 call MYFUNC
 push %eip
 
