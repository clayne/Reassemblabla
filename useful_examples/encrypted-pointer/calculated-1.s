.global main

myfunc:
 mov $0x1, %ebx
 call exit

main:
 mov $0x080482cb, %ecx
 mov $0x10, %eax
 mov $0x10, %ebx
 mul %ebx
 add %eax, %ecx
 call *%ecx

