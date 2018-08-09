.global main
main:

#mov %ds:(%ebx),%eax
#mov %ds:($0x12),%eax
#pop.d8 0x12

#subl   %eax,%edi
#subl.s %eax,%edi

# unsolved problem...
#subl $0x55,(%edi)
#subl.d8 $0x55,(%edi)
#subl.d32 $0x55,(%edi)
#.byte 0x81, 0x2f, 0x55, 0x00, 0x00, 0x00
#subl $0x55000000,(%edi)

#jno main
#jno.d32 main

# TODO: prefix issue
#cmp     $0x0,0x14(%ebp)
#cmp.d32 $0x0,0x14(%ebp)
#cmpw    $0x0,0x14(%ebp)
#cmpw.d32 $0x0,0x14(%ebp)

cmpsd $0x99, 0x11(%edx), %xmm0
cmpsd $0x99, 0x11(%edx), %xmm0


#jno gogo
#jno.d32 gogo
#jb gogo
#jb.d32 gogo
#jae gogo
#jae.d32 gogo
#je gogo
#je.d32 gogo
#jne gogo
#jne.d32 gogo
#jbe gogo
#jbe.d32 gogo
#pop %eax
#gogo:

# mov -0x4(%ebx),%eax
# mov.s -0x4(%ebx),%eax
# mov.d8 -0x4(%ebx),%eax
# mov.d32 -0x4(%ebx),%eax

#.byte 0x00, 0x02, 0x12, 0x12, 0x12, 0x12
#add %dl, (%edx)
#add %eax, (%edx)
#add %eax, 0x0808123
#add %eax, 0x23

# mov %ebp,%eax
# mov -0x4(%ebp),%eax
# mov.s -0x4(%ebp),%eax
# mov.d8 -0x4(%ebp),%eax
# mov.d32 -0x4(%ebp),%eax

# Mode R/M isn't must be located on 2nd. It can be 3rd, 4th...
# mov         0x4(%ecx), %bl
# mov         0x4(%ecx), %bx
# mov         0x4(%ecx), %ebx
# movq         0x4(%ecx), %mm3
# movq         0x4(%ecx), %xmm3

# machine code is all same :). No problem on re-assembling it.   
# mov %ax, %bx
# movw %ax, %bx
# mov $1, %bx
# movw $1, %bx



# Issue 2. swap
# adcb   %bl,%dh
# adcb.s %bl,%dh
# adc    %bl,%dh

# mov %eax,%ebx
# mov.s %eax,%ebx

# lea 0x0(%ebp),%eax
# lea.s 0x0(%ebp),%eax
