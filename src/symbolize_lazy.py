#!/usr/bin/python
#-*- coding: utf-8 -*-
from capstone import *
from intelhex import IntelHex
from elftools.elf.elffile import ELFFile
import sys 
import os
import subprocess
import re
from optparse import OptionParser
import binascii 

from etc import *
from global_variables import *



def jmp_to_PushalPushfJmp(resdic):

	for addr in resdic['.text'].keys():
		if resdic['.text'][addr][1].startswith(' jmp'): # TODO: jmp, jne 등등도 다 바꿔줘야하구 call도 바꿔줘야함. 그후에 이 모두에 대해서 resolve함수를 마련해 줘야함. 
			newasm = resdic['.text'][addr][1]
			newasm = ' call MYSYM_pushal\n call MYSYM_pushf\n' + resdic['.text'][addr][1]
			resdic['.text'][addr][1] = newasm


def addLABEL_to_allLineofTextSection(resdic):
	count = 0
	for i in xrange(len(resdic['.text'].keys())):
		addr = sorted(resdic['.text'])[i]
	
		# 모든 한줄한줄에 Symbol을 다붙여줌
		if resdic['.text'][addr][0] == '': 
			resdic['.text'][addr][0] = 'MYSYM_LAZY_' + str(count) + ':'
			count += 1


def add_stuffs(resdic, mainaddr):
	asm_regbackup = '''
 # Register backup function

    .lcomm MYSYM_EFLAGS, 4 # .lcomm 선언하면 자동으로 .bss에 들어간다. 
    .lcomm MYSYM_EAX, 4
    .lcomm MYSYM_ECX, 4
    .lcomm MYSYM_EDX, 4
    .lcomm MYSYM_EBX, 4
    .lcomm MYSYM_TEMP,4
    .lcomm MYSYM_EBP, 4
    .lcomm MYSYM_ESI, 4
    .lcomm MYSYM_EDI, 4

MYSYM_pushal:
    mov %eax, MYSYM_EAX
    mov %ecx, MYSYM_ECX
    mov %edx, MYSYM_EDX
    mov %ebx, MYSYM_EBX
    mov %ebp, MYSYM_EBP
    mov %esi, MYSYM_ESI
    mov %edi, MYSYM_EDI
    ret
   
MYSYM_popal:
    mov MYSYM_EAX, %eax
    mov MYSYM_ECX, %ecx
    mov MYSYM_EDX, %edx
    mov MYSYM_EBX, %ebx
    mov MYSYM_EBP, %ebp
    mov MYSYM_ESI, %esi
    mov MYSYM_EDI, %edi
    ret
 
MYSYM_pushf:
    push %eax               # I cant move from memory to memory
    pushf                   # EFLAGS -> (%esp) 
    mov 0x0(%esp), %eax     #           (%esp) -> %eax
    mov %eax, MYSYM_EFLAGS  #                     %eax -> MYSYM_EFLAGS
    add $0x4, %esp          # stack revoke : pushf
    pop %eax                # value revoke : %eax
    ret
 
MYSYM_popf:
    push MYSYM_EFLAGS
    popf
    ret
	'''

	asm_exit = '''
# lazy resolver를 거쳐서도 해결안되는 심볼.. 즉, 애초부터 세그폴의 운명이였던 놈은 이곳으로 탈출해라.....

MYSYM_EXIT:
	movl $0x1, %eax
	movl $0x3, %ebx
	int $0x80
	'''

	# 얘는 main의 맨앞에다가 놓자. 시그널핸들러 등록. 
	asm_registerSignalHandler = '''
	# Here is signal handler

	.lcomm my_sigaction, 140 # size of sigaction struction is 140
	.set SIGSEGV, 11
	.set SA_SIGINFO, 4

	movl $MYSYM_LAZYRESOLVER_START, my_sigaction           # 1. Writting field : sa_handler field	
	movl $132, %edi                         # 2. Writting field : sa_flags field
	movl $SA_SIGINFO, my_sigaction(,%edi,1) #    dword ptr [edi + 0x80492b8], 4
                                            #    SA_SIGINFO means whenever signal appears, run the signal handling function.

	# Calling sigaction(int, const struct sigaction *, struct sigaction *)
	pushl $0                                # 1st param : oact
	pushl $my_sigaction                     # 2nd param : act
	pushl $SIGSEGV                          # 3rd param : sig
	call sigaction
	addl $12, %esp

# And... from now on, original main starts. 
'''
	noaddr = 0xff000000
	resdic['.text'][noaddr + 0] = [
									'',
									asm_regbackup,
									'',
									''
									]

	resdic['.text'][noaddr + 1] = [
									'',
									asm_exit,
									'',
									''
									]
	resdic['.text'][mainaddr][1] = asm_registerSignalHandler + resdic['.text'][mainaddr][1]

def addLazyResolver2textSection(resdic):
	dic_lazyresolver = {}

	# 우선은 text섹션에 대한 lazy resolver만 만들어 보자. 
	noaddr = 0xf0000000 # 절대절대절대 바이너리가 맵핑될수없는 주소로 설정했음. 
	count = 0

	asm_Crashedaddr2Eax = '''
	# Crash 유발한 바로 그 Addr을 %eax 에다가 집어넣는다
	mov 0x1c(%esp), %eax
	add $0x5ec, %esp
	'''

	asm_lazyresolver = '''
	cmp $%s, %%eax
	jne %s
	call MYSYM_popf
	call MYSYM_popal
	jmp %s
	''' 

	dic_lazyresolver[noaddr] = [
								'MYSYM_LAZYRESOLVER_START:',
								asm_Crashedaddr2Eax,
								'',
								''
								]
	noaddr += 1

	for i in xrange(len(resdic['.text'].keys())):
		addr = sorted(resdic['.text'])[i]

		theSymb = resdic['.text'][addr][0]
		theAddr = str(hex(addr))

		if i == len(resdic['.text'].keys()) - 1 : # 레이지리졸버 링크의 마지막임 
			nextresolverName = 'MYSYM_EXIT' # TODO: exit함수 만들어줘야함. 와나 이거는 세그폴시그널핸들러의 최종보스필터까지도 뚫은 강력한 반항아다. 뒤져라. 
		else:
			nextresolverName = 'MYSYM_LAZYRESOLVER_' + str(count + 1)

		dic_lazyresolver[noaddr] = [
							  'MYSYM_LAZYRESOLVER_' + str(count) + ':', # resolver의 각 항은 jne linked list 로 이어져 있다. 
							  asm_lazyresolver % (theAddr, nextresolverName, theSymb[:-1]),
							  '', # 주석자리. 노필요
							  ''  # PIE관련정보 자리. 노필요.
							  ]
		noaddr += 1
		count += 1


	
	resdic['.text'].update(dic_lazyresolver)
	