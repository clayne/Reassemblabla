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



def jmp2pushalpushfjmp(resdic):
	for addr in resdic['.text'].keys():
		i = 0
		while i < len(resdic['.text'][addr][1]):
			if resdic['.text'][addr][1][i].startswith(' jmp'): # TODO: jmp, jne 등등도 다 바꿔줘야하구 call도 바꿔줘야함. 그후에 이 모두에 대해서 resolve함수를 마련해 줘야함. 
				resdic['.text'][addr][1].insert(i,' call MYSYM_pushal #+++++')
				resdic['.text'][addr][1].insert(i,' call MYSYM_pushf #+++++')
				i += 2
			i += 1


def symbolize_alllines(resdic):
	count = 0
	SORTEDADDR = sorted(resdic['.text'])
	for i in xrange(len(resdic['.text'].keys())):
		addr = SORTEDADDR[i]
	
		# 모든 한줄한줄에 Symbol을 다붙여줌
		if resdic['.text'][addr][0] == '': 
			resdic['.text'][addr][0] = 'MYSYM_LINE_' + str(count) + ':'
			count += 1


def setup(resdic, mainaddr): # 레지스터 백업함수를 셋업해둔당
	asm_stuffs = '''
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
.lcomm MYSYM_EIP, 4 #!!!

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

MYSYM_backupregistercontext:
	call MYSYM_pushf    #eflags 
    mov %eax, MYSYM_EAX #1
    mov %ecx, MYSYM_ECX #2 
    mov %edx, MYSYM_EDX #3
    mov %ebx, MYSYM_EBX #4
    mov %ebp, MYSYM_EBP #5
    mov %esi, MYSYM_ESI #6
    mov %edi, MYSYM_EDI #7
    ret

MYSYM_restoreregistercontext:
	call MYSYM_popf		#eflags
    mov MYSYM_EAX, %eax #1
    mov MYSYM_ECX, %ecx #2
    mov MYSYM_EDX, %edx #3
    mov MYSYM_EBX, %ebx #4
    mov MYSYM_EBP, %ebp #5 
    mov MYSYM_ESI, %esi #6
    mov MYSYM_EDI, %edi #7
    ret


MYSYM_gobacktocontrolflow:
	jmp MYSYM_EIP
'''




	asm_exit = '''
#+++++
# lazy resolver를 거쳐서도 해결안되는 심볼.. 즉, 애초부터 세그폴의 운명이였던 놈은 이곳으로 탈출해라.....

MYSYM_EXIT:
	movl $0x1, %eax
	movl $0x3, %ebx
	int $0x80
'''


	# 얘는 main의 맨앞에다가 놓자. 시그널핸들러 등록. 
	asm_sighandler = '''
# Let's start crash handler!

.lcomm my_sigaction, 140 # size of sigaction struction is 140
.set SIGSEGV, 11
.set SA_SIGINFO, 4

	movl $MYSYM_LAZYRESOLVER_START, my_sigaction    # 1. Writting field : sa_handler field	
	movl $132, %edi                         		# 2. Writting field : sa_flags field
	movl $SA_SIGINFO, my_sigaction(,%edi,1) 		#    dword ptr [edi + 0x80492b8], 4
                                            		#    SA_SIGINFO means whenever signal appears, run the signal handling function.

	pushl $0                               			# 1st param : oact
	pushl $my_sigaction                     		# 2nd param : act
	pushl $SIGSEGV                          		# 3rd param : sig
	call sigaction
	addl $12, %esp
'''
	noaddr = 0xf0000000
	resdic['.text'][noaddr + 0] = [
									'',
									[asm_stuffs],
									'',
									''
									]

	resdic['.text'][noaddr + 1] = [
									'',
									[asm_exit],
									'',
									''
									]

	resdic['.text'][mainaddr][1] = resdic['.text'][mainaddr][1].insert(0,asm_sighandler) # 맨처음에 추가요 


def CreateCRASHHANDLER(resdic):
	crashhandler = {}

	addr_crashhandler = 0xf1000000 # 절대절대절대 바이너리가 맵핑될수없는 주소. 크래시핸들러가위치하는 가상의주소.
	count = 0

	asm_mov_crashvalue_to_eax = '''
	mov 0x1c(%esp), %eax 			# 크래시유발한 바로 그 주소값을 %eax 에다가 집어넣는다
'''
	asm_restore_stackframe = '''
	add $0x5ec, %esp                # 스택프레임복원
'''

	asm_piece_of_crashhandler = '''
	cmp $%s, %%eax
	jne %s  							# 아니라면 다음조각으로 점프
	call MYSYM_restoreregistercontext 	# 일치한다면 레지스터컨텍스트 복원후 EIP로 점프
	jmp *MYSYM_EIP
''' 

	crashhandler[addr_crashhandler] = [
								'MYSYM_CRASHHANDLER_START:',
								[asm_mov_crashvalue_to_eax, asm_restore_stackframe],
								'',
								''
								]

	addr_crashhandler += 1
	SORTEDADDR = sorted(resdic['.text'])

	for i in xrange(len(resdic['.text'].keys())):
		addr = SORTEDADDR[i]

		if i == len(resdic['.text'].keys()) - 1 : # 레이지리졸버 링크의 끝
			nextpiece = 'MYSYM_EXIT' 			  # 링크의 마지막은 EXIT으로 장식한다
		else:
			nextpiece = 'MYSYM_LAZYRESOLVER_' + str(count + 1)

		crashhandler[addr_crashhandler] = [
							  'MYSYM_LAZYRESOLVER_' + str(count) + ':', # resolver의 각 항은 jne linked list 로 이어져 있다. 
							  [asm_piece_of_crashhandler % (str(hex(addr)), nextpiece)],
							  '', # 주석자리. 노필요
							  ''  # PIE관련정보 자리. 노필요.
							  ]
		addr_crashhandler += 1
		count += 1

	resdic['.text'].update(crashhandler)














# 이것부터 한번 실험해보자. 나머지 크래시핸들러는 실험하기 까다로우니깐 이게 더 실험하기 쉬우니깐 이것부터 실험을 해보도록 하쟝
def add_someprefix_before_all_memory_reference(resdic):
	count = 0
	SORTEDADDR = sorted(resdic['.text'])
	for i in xrange(len(resdic['.text'].keys())):
		addr = SORTEDADDR[i]
		for DISASM in resdic['.text'][addr][1]:
			if '#' in DISASM: # 주석떼버리기
				DISASM = DISASM[:DISASM.index('#')] 

			# 믿고거르는 조건 추가~
			if '#+++++' in DISASM: 	# 디스어셈블러가 추가해준라인은 믿고거른당 ㅎ
				continue
			elif 'MYSYM' in DISASM: # 심볼라이즈된 메모리레퍼런스가 있다면 믿고거른당. 왜냐하면 메모리투메모리 연산은 지원안하는뎅, 메모리가 하나만있지 두개나있냐? 하나있는메모리가 심볼라이즈 이미됬는데 뭘더해,,,,,
				continue
			elif DISASM.startswith(' .') or DISASM.startswith('.'): # 어셈블러 디렉티브라인도 거른당
				continue
			elif '(' not in DISASM or ')' not in DISASM:
				continue
			# TODO: GLOBAL_OFFSET_TABLE 휴리스틱하게 처리해줬던거... 그거 어디갔어? 그거 룰좀 보고 거를꺼 추가해줘야하는뎅.


			else:
				print 'laura ' + DISASM


	# 1. 0x12(%eax,%ebx,4) 값을찾는다
	''' 
	이거를 참고해서...

	if '#' in DISASM: # 주석날리고
		DISASM = DISASM[:DISASM.index('#')]
	
	DISASM = re.sub('(0x)?' + '[0-9a-f]+' + '(\()' + _ + '(\))', '', DISASM)# 2. 메모리레퍼런스하는경우, 0x12(%eax, %ebx, 4)이런거부터 날려버리고,

	DISASM = DISASM.replace(',',' ') # 콤마날리고 

	DISASM = re.sub('\s+',' ',DISASM).strip() # duplicate space, tab --> single space
	'''


	# 2. lea 0x12(%eax,%ebx,4), DUMMY; 원본인스트럭션 ()자리에DUMMY, 원본다음꺼 <- re.sub으로 바꺼주면되겠당






























# call get_pc_thunk --> jmp
# TODO:이거뭔가잘못된것같은데..나중에확인ㄱㄱ
def getpcthunk_to_returnoriginalADDR(resdic):
	for sectionName in CodeSections_WRITE:
		if sectionName in resdic.keys():
			for i in xrange(len(sorted(resdic[sectionName].keys()))):
				addr = sorted(resdic[sectionName].keys())[i]
				j = 0
				while j < len(resdic[sectionName][addr][1]):
					if 'get_pc_thunk' in resdic[sectionName][addr][1][j] and 'call' in resdic[sectionName][addr][1][j] : # 1차 필터.
						# call get_pc_thunk -> jmp get_pc_thunk 교체
						nextaddr = sorted(resdic[sectionName].keys())[i+1]
						resdic[sectionName][addr][1].insert(j,' push $' + str(hex(nextaddr))) # j 자리에다가 낑겨서 새치기함. 
						resdic[sectionName][addr][1][j+1] = resdic[sectionName][addr][1][j+1].replace('calll','jmp').replace('call','jmp')
						j += 1 # 새치기한것에 대한 보상
					j += 1
