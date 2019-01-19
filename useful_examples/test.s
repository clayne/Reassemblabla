.global main

main:
 call get_pc_thunk.si
 mov $0x2, %eax
 mov $0x3, %esi
 movb $0x12, (%eax)           # type1 2
 movb $0x12, 0x7(%eax)        # type2 9
 movb $0x12, 0x7(%eax,%esi,)  # type3 12
 movb $0x12, 0x7(,%esi,4)     # type4 19
 movb $0x12, 0x7(%eax,%esi,4) # type5 21

get_pc_thunk.si:
 mov (%esp), %esi
 ret 
