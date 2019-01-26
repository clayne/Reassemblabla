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

#TODO: 뭔가 스택프레임 망가뜨리는함수있는지 화긴 ㄱㄱ
def setup_some_useful_stuffs_for_crashhandler(resdic): # 레지스터 백업함수를 셋업해둔당
	asm_stuffs = '''
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
.lcomm MYSYM_CRASHADDR, 4

MYSYM_pushf:
    pushf                   # EFLAGS -> (%esp) 
    pop MYSYM_EFLAGS        #           (%esp) - MYSYM_EFLAGS 
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

'''

	asm_exit = '''
#+++++
# crash handler 를 거쳐서도 해결안되는 심볼.. 즉, 애초부터 세그폴의 운명이였던 놈은 이곳으로 탈출해라.....
MYSYM_EXIT:
	movl $0x1, %eax
	movl $0x3, %ebx
	int $0x80
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



def installsignalhandleratmain(resdic, mainaddr):
		# 얘는 main의 맨앞에다가 놓자. 시그널핸들러 등록. 
	asm_sighandler = '''
.lcomm my_sigaction, 140 # size of sigaction struction is 140
.set SIGSEGV, 11
.set SA_SIGINFO, 4
	push %edi 										# 0. 오리지날 edi 백업
	movl $MYSYM_CRASHHANDLER_START, my_sigaction    # 1. Writting field : sa_handler field	
	movl $132, %edi                         		# 2. Writting field : sa_flags field
	movl $SA_SIGINFO, my_sigaction(,%edi,1) 		#    dword ptr [edi + 0x80492b8], 4
                                            		#    SA_SIGINFO means whenever signal appears, run the signal handling function.

	pushl $0                               			# 1st param : oact
	pushl $my_sigaction                     		# 2nd param : act
	pushl $SIGSEGV                          		# 3rd param : sig
	call sigaction
	addl $12, %esp
	pop %edi
'''
	resdic['.text'][mainaddr][1].insert(0,asm_sighandler) # 맨처음에 추가요 



def setupsignalhandler(resdic):
	crashhandler = {}

	addr_crashhandler = 0xf1000000 # 절대절대절대 바이너리가 맵핑될수없는 주소. 크래시핸들러가위치하는 가상의주소.
	count = 0

	asm_mov_crashvalue_to_eax = '''
	mov MYSYM_CRASHADDR, %eax 			# 크래시유발한 바로 그 주소값을 %eax 에다가 집어넣는다 TODO: 이거 MYSYM_CRASHADDR 에 있는거 꺼내와서 써도됨. 
'''
	asm_restore_stackframe = '''
	add $0x5ec, %esp                # 스택프레임복원
'''
	#URGENT: 이거 모든라인에 대해서 할필요없다...! --> 이거 라인바이 라인으로 내일와서 구현하기
	#		 디스어셈블리의 라인에 대해서, resdic['.text'][TheAddr][1] 'MYSYM_CRASHVIRTUALSYM__뭐시기' 가 있는경우,
	#        그 라인에 대해서, 
	#        if 크래시유발한값이 == resdic['.text'][TheAddr][0] : 
	#              'MYSYM_CRASHVIRTUALSYM_뭐시기' 로 뛰어라. (MYSYM_CRASHADDR 를 셋팅하구나서, 막 백업했던 레지스터들두 복구하구나서)
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

		if i == len(resdic['.text'].keys()) - 1 : 	  # 레이지리졸버 링크의 끝
			nextpiecename = 'MYSYM_EXIT' 			  # 링크의 마지막은 EXIT으로 장식한다
		else:
			nextpiecename = 'MYSYM_CRASHHANDLER_' + str(count + 1)

		crashhandler[addr_crashhandler] = [
							  'MYSYM_CRASHHANDLER_' + str(count) + ':', # resolver의 각 항은 jne linked list 로 이어져 있다. 
							  [asm_piece_of_crashhandler % (str(hex(addr)), nextpiecename)],
							  '', # 주석자리. 노필요
							  ''  # PIE관련정보 자리. 노필요.
							  ]
		addr_crashhandler += 1
		count += 1

	resdic['.text'].update(crashhandler)






# 이것부터 한번 실험해보자. 나머지 크래시핸들러는 실험하기 까다로우니깐 이게 더 실험하기 쉬우니깐 이것부터 실험을 해보도록 하쟝
# 우선은 그냥 독립적인 함수로 만드는데, 사실 이거는 input: resdic['.text'][ADDR][j] 을 입력받아가지고, 새로운 resdic['.text'][ADDR][j] 하구, 이에대한 SYMBOL NAME (EIP에 대한 pointer) 를 리턴하도록 햐야햠
# 그럴려면은 CreateCRASHHANDLER 에서, j를 pickpick으로 뽑은다음에, *뒤에서부터* 삽입을 진행하면 되겠네. 
def add_someprefix_before_all_memory_reference(resdic):
	_ = '.*?'
	count = 0
	SORTEDADDR = sorted(resdic['.text'])
	for i in xrange(len(resdic['.text'].keys())):
		addr = SORTEDADDR[i]
		origindexlist = pickpick_idx_of_orig_disasm(resdic['.text'][addr][1]) 
		for j in reversed(origindexlist):
			DISASM = resdic['.text'][addr][1][j]
			if '#' in DISASM: # 주석떼버리기
				DISASM = DISASM[:DISASM.index('#')] 

			MEMREF = re.search('(-)?' + '(0x)?' + '[0-9a-f]+' + '(\()' + _ + '(\))', DISASM) # 1. 0x12(%eax,%ebx,4) 객체를 찾는다. 객체를 스트링으로 만드는 법 : .group() 을 써준당.

			# 믿고거른다시리즈-01
			if 'MYSYM' in DISASM: 										# 01-01 심볼라이즈된 메모리레퍼런스가 있다면 믿고거른당. 왜냐하면 메모리투메모리 연산은 지원안하는뎅, 메모리가 하나만있지 두개나있냐? 하나있는메모리가 심볼라이즈 이미됬는데 뭘더해,,,,,
				continue
			if DISASM.startswith(' .') or DISASM.startswith('.'):	 	# 01-02 어셈블러 디렉티브라인도 거른당
				continue
			if DISASM.startswith('lea') or DISASM.startswith(' lea'): 	# 01-03 lea는 예외적으로, 메모리주소가나와도 메모리참조가 아니므로 패스으~
				continue
			if '(' not in DISASM or ')' not in DISASM: 					# 01-04 메모리참조가 아니라면!(그치만 branch instruction은 디폴트로 메모리참조이므로 예외처리~)
				if DISASM.startswith('j') or DISASM.startswith(' j'):
					'branch! defultly memory reference. so pass it!'
				elif DISASM.startswith('call') or DISASM.startswith(' call'):
					'branch! defultly memory reference. so pass it!'
				else:
					continue
			

			# MEMREF 설정한다.
			if MEMREF is None: # jmp %eax 같은거. (대외적으로 메모리레퍼런스가 아닌척하지만, 사실은 메모리레퍼런스인 경우)
				MEMREF = DISASM.strip().split(' ')[1] 
				MEMREF = MEMREF.replace('*','') # 나중에 별까지 치환해주면 안댐. 메모리주소자체는 %eax 이징 *%eax 이게 아니자낭.....
			else:
				MEMREF = MEMREF.group()
			

			# 믿고거른다시리즈-02
			if 'esp' in MEMREF: 					 				   # 02-01 esp 메모리에 대한 접근은 크래시 절대안나는 연산임 ㅎㅅㅎ 그러니 안심하고 제외~
				continue

			filterout = 1											   # 02-02 call main, call __libc_start_main 이딴거있자나. 그런것도 제외해줘야함.
			for r in GENERAL_REGISTERS:  
				if r in MEMREF: 
					filterout = 0
			if filterout is 1:
				continue 			


			# 브랜치 인스트럭션에서 별 설정 해주기 ㅎㅅㅎ. 오직 call *%eax 이때만 weird하당. 왜냐면 사실상 call %eax이거거덩,,, 심볼화되면 call MYSYM 으로 되야되거덩...
			itismemref = 'yes'
			if MEMREF in GENERAL_REGISTERS: 			# MEMREF가 알고봤더니 그냥 %eax 요거일경우
				DISASM = DISASM.replace('*','') 		# 결과에서 별 없앤당.
				itismemref = 'no'
			NEWDISASM  = []
			
			NEWDISASM.append(' # laura' + ' ' + '#+++++')
			# 맨첨으로 우선 레지스터컨텍스트를 백업해 둡니당
			NEWDISASM.append(' call MYSYM_backupregistercontext' + ' ' + '#+++++')
			
			# 위험한 라인의 EIP를 백업해 둡니다. --> 챌린징한요소: ' lea MYSYM_CRASHVIRTUALSYM_123, MYSYM_EIP 이거는 too many memory reference 걸림^^.....
			NEWDISASM.append(' push $MYSYM_CRASHVIRTUALSYM_' + str(count) + ' ' + '#+++++')
			NEWDISASM.append(' pop MYSYM_EIP' + ' ' + '#+++++')

			
			# 위험한 라인에서 위험한 값을 MYSYM_CRASHADDR 에다가 백업해 둡니당. ---> 챌린징한요소: lea는 로드대상이 무조건 *레지스터여야만 한다는 한계가 이씀. mov는 로드대상이 메모리주소일수도있겠지만, 0x12(%eax,%ebx,2) 의 값자체를 옮길수는없고 그안에들어있는 값을 옮긴다는 한계가이씀. 그래서 이러케 복잡하게구성한거임....하
			if itismemref == 'yes': 												# case1 : 0x12(%eax,%ebx,2) 같이 한차원이동하는 메모리레퍼런스인경우
				NEWDISASM.append(' push %eax' + ' ' + '#+++++')
				NEWDISASM.append(' lea ' + MEMREF + ', %eax' + ' ' + '#+++++')
				NEWDISASM.append(' mov %eax, MYSYM_CRASHADDR' + ' ' + '#+++++')
				NEWDISASM.append(' pop %eax')
			elif itismemref == 'no':										 		# case2 : call *%eax 같이 그냥그메모리주소를 참조하는경우, 곧바로 레지스터값을 메모리에따 옮기면된당 ㅎㅅㅎ
				NEWDISASM.append(' mov ' + MEMREF + ', MYSYM_CRASHADDR' +  ' ' + '#+++++')

			# 드디어 위험한 라인의 심볼을 선언합니당
			NEWDISASM.append('MYSYM_CRASHVIRTUALSYM_' + str(count) + ':'  + ' ' + '#+++++')
			
			# 한차원낮추기: 흑흑 참고로 MYSYM_CRASHADDR 를 곧바로다가 메모리참조하면 "어드레스"를 참조하게 됩니당... 어드레스 안에있는 "컨텐츠"가 아니라요... 그래서 한차원낮추는 작업이 필요. "컨텐츠"를 MYSYM_CRASHADDR 안에다가 넣읍시다,,, 아래에서 "컨텐츠"를 참조할수있도록요.
			NEWDISASM.append(' push %eax' + ' ' + '#+++++')
			NEWDISASM.append(' mov MYSYM_CRASHADDR, %eax' + ' ' + '#+++++')
			NEWDISASM.append(' mov (%eax), %eax' + ' ' + '#+++++') # <- 요게 핵심~
			NEWDISASM.append(' mov %eax, MYSYM_CRASHADDR' + ' ' + '#+++++')
			NEWDISASM.append(' pop %eax' + ' ' + '#+++++')
			
			# 마지막으로 바뀐 디스어셈블리를 붙여줍니당~야호~
			DISASM = DISASM.replace(MEMREF, 'MYSYM_CRASHADDR')
			NEWDISASM.append( DISASM + '# original : ' + resdic['.text'][addr][1][j] + ' ' + '#+++++')

			# 끝!
			resdic['.text'][addr][1] = resdic['.text'][addr][1][:j] + NEWDISASM + resdic['.text'][addr][1][j+1:]
			count = count+1


	






























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
