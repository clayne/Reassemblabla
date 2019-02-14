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



def symbolize_alllines(resdic):
	count = 0
	for sectionName in resdic.keys():
		if sectionName in AllSections_WRITE:
			SORTEDADDR = sorted(resdic[sectionName])
			for i in xrange(len(resdic[sectionName].keys())):
				addr = SORTEDADDR[i]
				if resdic[sectionName][addr][0] == '': # 모든 라인을 심볼화한다. 
					resdic[sectionName][addr][0] = SYMPREFIX[0] + 'MYSYM_LINE_' + str(count) + ':'
					count += 1

def setup_some_useful_stuffs_for_crashhandler(resdic): # 레지스터 백업함수를 셋업한다.
	asm_stuffs = '''
.lcomm MYSYM_EIP, 4 #!!!
.lcomm MYSYM_ESP, 4 #!!! 
.lcomm MYSYM_CRASHADDR, 4
.lcomm MYSYM_CRASHADDR_R, 4 
.lcomm MYSYM_LIBFLAG, 4

.lcomm MYSYM_EFLAGS, 4
.lcomm MYSYM_EAX, 4
.lcomm MYSYM_ECX, 4
.lcomm MYSYM_EDX, 4
.lcomm MYSYM_EBX, 4
.lcomm MYSYM_EBP, 4
.lcomm MYSYM_ESI, 4
.lcomm MYSYM_EDI, 4


MYSYM_backupregistercontext:
    pushf               # eflags 
    pop MYSYM_EFLAGS        
    mov %eax, MYSYM_EAX # 1
    mov %ecx, MYSYM_ECX # 2 
    mov %edx, MYSYM_EDX # 3
    mov %ebx, MYSYM_EBX # 4
    mov %ebp, MYSYM_EBP # 5
    mov %esi, MYSYM_ESI # 6
    mov %edi, MYSYM_EDI # 7
    ret

MYSYM_restoreregistercontext:
    push MYSYM_EFLAGS   # eflags
    popf
    mov MYSYM_EAX, %eax # 1
    mov MYSYM_ECX, %ecx # 2
    mov MYSYM_EDX, %edx # 3
    mov MYSYM_EBX, %ebx # 4
    mov MYSYM_EBP, %ebp # 5 
    mov MYSYM_ESI, %esi # 6
    mov MYSYM_EDI, %edi # 7
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



def addRoutineToInstallSignalHandler_in_init_array(resdic):
	CODEBLOCK_TEXT  = []
	CODEBLOCK_INITARRAY = []
	CODEBLOCK_TEXT.append('MYSYM_INSTALL_SIGNAL_HANDLER: #+++++')
	CODEBLOCK_TEXT.append('.lcomm my_sigaction, 140'								+ ' ' + '#+++++')
	CODEBLOCK_TEXT.append('.set SIGSEGV, 11' 										+ ' ' + '#+++++') # size of sigaction struction is 140
	CODEBLOCK_TEXT.append('.set SA_SIGINFO, 4' 										+ ' ' + '#+++++')
	CODEBLOCK_TEXT.append(' push %edi' 												+ ' ' + '#+++++') # 0. 오리지날 edi 백업
	CODEBLOCK_TEXT.append(' movl $MYSYM_CRASHHANDLER_START, my_sigaction' 			+ ' ' + '#+++++') # 1. Writting field : sa_handler field	
	CODEBLOCK_TEXT.append(' movl $132, %edi' 										+ ' ' + '#+++++') # 2. Writting field : sa_flags field
	CODEBLOCK_TEXT.append(' movl $SA_SIGINFO, my_sigaction(,%edi,1)' 				+ ' ' + '#+++++') #    dword ptr [edi + 0x80492b8], 4 / SA_SIGINFO means whenever signal appears, run the signal handling function.
	CODEBLOCK_TEXT.append('' 														+ ' ' + '#+++++') 
	CODEBLOCK_TEXT.append(' pushl $0' 												+ ' ' + '#+++++') # 1st param : oact
	CODEBLOCK_TEXT.append(' pushl $my_sigaction' 									+ ' ' + '#+++++') # 2nd param : act
	CODEBLOCK_TEXT.append(' pushl $SIGSEGV' 										+ ' ' + '#+++++') # 3rd param : sig
	CODEBLOCK_TEXT.append(' call sigaction'											+ ' ' + '#+++++') # call sigaction
	CODEBLOCK_TEXT.append(' addl $12, %esp' 										+ ' ' + '#+++++')
	CODEBLOCK_TEXT.append(' pop %edi' 												+ ' ' + '#+++++')
	CODEBLOCK_TEXT.append(' ret'	 												+ ' ' + '#+++++') 

	CODEBLOCK_INITARRAY.append('MYSYM_INIT_ARRAY_INSTALLSIGHANDLER: #+++++')
	CODEBLOCK_INITARRAY.append(' .long MYSYM_INSTALL_SIGNAL_HANDLER #+++++')


	# [01] CODEBLOCK_TEXT 은 텍스트섹션의 very end 에다가 깔쌈하게 붙여주자. LAST 여야함. 그래야 특정심볼의안에서 중복실행을 방지할수가있음 
	SORTED_ADDRESS = resdic['.text'].keys()
	SORTED_ADDRESS.sort()
	ADDR_LAST = SORTED_ADDRESS[-1] # 마지막주소
	resdic['.text'][ADDR_LAST + 1] = 	['',
										CODEBLOCK_TEXT,
										'',
										'']

	# [02] 바이너리시작 즉시 MYSYM_INSTALL_SIGNAL_HANDLER 실행될수있도록 생성자배열에다가 추가하자
	if '.init_array' in resdic.keys(): # 섹션이 원래있다면
		SORTED_ADDRESS = resdic['.init_array'].keys()
		SORTED_ADDRESS.sort()
		ADDR_FIRST = SORTED_ADDRESS[0] # 처음주소
	else: # 섹션이 원래없다면 섹션itself를 추가해줘야 함
		resdic['.init_array'] = {}
		ADDR_FIRST = 0x00000001

	resdic['.init_array'][ADDR_FIRST-1] = ['',
											CODEBLOCK_INITARRAY,
											'',
											'']


def setupsignalhandler(resdic):
	CRASHHANDLER = {}

	addr_crashhandler = 0xf1000000 # 절대절대절대 바이너리가 맵핑될수없는 주소. 크래시핸들러가위치하는 가상의주소.
	count = 0

	# asm_prifix = ' mov MYSYM_CRASHADDR, %eax' 		+ ' ' + '#+++++' + '\n' # 크래시유발한 바로 그 주소값을 %eax 에다가 집어넣는다 COMMENT: 이거 외부라이브러리에서 크래시나면 무슨값을참조하다났는지 스택으로만 알수있기때문에 우선 스택을 쓰도록 했음.
	asm_prifix = ' mov 0x1c(%esp), %eax'			+ ' ' + '#+++++' + '\n'

	asm_block  = '' + ''
	asm_block  += '#+++++'							+ ' ' + '#+++++' + '\n'
	asm_block  += ' cmp $%s, %%eax'					+ ' ' + '#+++++' + '\n'	# 1. if 원본바이너리의 주소와 같다면 
	asm_block  += ' jne %s'							+ ' ' + '#+++++' + '\n'	# 

	# 이꼴인 상태지?? 현재 %eax(오리지널주소), %s(새주소의심볼)이 이써.
	asm_block  += ' cmp $0x1, MYSYM_LIBFLAG' 		+ ' ' + '#+++++' + '\n' # 2. 라이브러리 내부에서 크래시가 났다면
	asm_block  += ' jne MYSYM_CRASHHANDLER_ORIG_%s' + ' ' + '#+++++' + '\n' # 
	asm_block  += ' mov MYSYM_ESP, %%ebx'			+ ' ' + '#+++++' + '\n'
	asm_block  += ' sub $0x4, %%ebx'				+ ' ' + '#+++++' + '\n'
	asm_block  += 'MYSYM_CRASHADDR_LIB_%s: '		+ ' ' + '#+++++' + '\n' # 	loop
	asm_block  += ' add $0x4, %%ebx'				+ ' ' + '#+++++' + '\n' # 
	asm_block  += ' cmp %%eax, (%%ebx)' 			+ ' ' + '#+++++' + '\n' # 	오지리널주소 %%eax와 스택안에저장된주소(%%ebx) 비교
	asm_block  += ' jne MYSYM_CRASHADDR_LIB_%s' 	+ ' ' + '#+++++' + '\n' #  
	asm_block  += ' lea %s, %%eax'					+ ' ' + '#+++++' + '\n' # 	일치한다면 스택교정
	asm_block  += ' mov %%eax, (%%ebx)'				+ ' ' + '#+++++' + '\n' # 	
	asm_block  += ' mov MYSYM_EIP, %%eax'			+ ' ' + '#+++++' + '\n' #   컴백할 주소를 sc.eip 자리에셋팅후 sigreturn 
	asm_block  += ' mov %%eax, 0xdc(%%esp)'			+ ' ' + '#+++++' + '\n' #              
	asm_block  += ' ret'							+ ' ' + '#+++++' + '\n'	# 			

	asm_block  += 'MYSYM_CRASHHANDLER_ORIG_%s:'		+ ' ' + '#+++++' + '\n' # 3. 바이너리 내부에서 크래시가 났다면
	asm_block  += ' lea %s, %%eax'					+ ' ' + '#+++++' + '\n' #    새 주소를 MYSYM_CRASHADDR 에다가 셋팅해준 후
	asm_block  += ' mov %%eax, MYSYM_CRASHADDR'		+ ' ' + '#+++++' + '\n'	#  
	asm_block  += ' mov MYSYM_EIP, %%eax'			+ ' ' + '#+++++' + '\n' #    컴백할 주소를 sc.eip 자리에셋팅후 sigreturn
	asm_block  += ' mov %%eax, 0xdc(%%esp)'			+ ' ' + '#+++++' + '\n' #              
	asm_block  += ' ret'							+ ' ' + '#+++++' + '\n'	# 			 
	
	# 바이너리내부용 크래시핸들러
	CRASHHANDLER[addr_crashhandler] = [
						'MYSYM_CRASHHANDLER_START:',
						[asm_prifix],
						'',
						''
						]

	addr_crashhandler += 1
	for sectionName in resdic.keys():
		if sectionName in AllSections_WRITE:
			addr_crashhandler += 1
			SORTEDADDR = sorted(resdic[sectionName])
			for i in xrange(len(SORTEDADDR)):
				addr = SORTEDADDR[i]
				symbolname = resdic[sectionName][addr][0][:-1]    						# ':' 제거
				nextpiecename = SYMPREFIX[0] + 'MYSYM_CRASHHANDLER_' + str(count + 1)
				CRASHHANDLER[addr_crashhandler] = [
									  'MYSYM_CRASHHANDLER_' + str(count) + ':', 		# resolver의 각 항은 jne linked list 로 이어져 있다. 
									  [asm_block % (str(hex(addr)), nextpiecename, str(count), str(count), str(count), symbolname, str(count), symbolname)],
									  '', 												# 주석자리. 노필요
									  ''  												# PIE관련정보 자리. 노필요.
									  ]
				addr_crashhandler += 1
				count += 1
	
	CRASHHANDLER[addr_crashhandler] = [													# 크래시핸들러 링크의 끝 : 자살!
						  'MYSYM_CRASHHANDLER_' + str(count) + ':', 	
						  ['jmp MYSYM_EXIT #+++++'],
						  '',
						  ''  
						  ]    
	resdic['.text'].update(CRASHHANDLER)
	


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

			# [01] 거르는 인스트럭션
			itisbranch = False
			if 'MYSYM' in DISASM: 										# 01-01 심볼라이즈된 메모리레퍼런스가 있다면 거른다. TODO: memory to memory 연산의 경우, 하나가 심볼화된상태라고 쳤을때, 나머지 하나에 대한 크래시대비가 안된다... 나중에 핸들링할것
				continue
			if DISASM.startswith(' .') or DISASM.startswith('.'):	 	# 01-02 어셈블러 디렉티브라인도 제외한다. 
				continue
			if DISASM.startswith('lea') or DISASM.startswith(' lea'): 	# 01-03 lea는 예외적으로, 메모리주소가나와도 메모리참조가 아니므로 패스한다. 
				continue
			if '(' not in DISASM or ')' not in DISASM: 					# 01-04 메모리참조가 아니라면 거른다 (그치만 branch instruction은 디폴트로 메모리참조이므로 예외처리)
				if DISASM.startswith('j') or DISASM.startswith(' j'):
					'branch! defultly memory reference. so pass it!'
					itisbranch = True
				elif DISASM.startswith('call') or DISASM.startswith(' call'):
					'branch! defultly memory reference. so pass it!'
					itisbranch = True
				else:
					continue

			# MEMREF 설정한다.
			if MEMREF is None: 											# jmp %eax 같은거. (레지스터만 봤을 때 메모리참조가 아닌것처럼 보이지만, 사실은 메모리레퍼런스인 경우)
				MEMREF = DISASM.strip().split(' ')[1] 
				MEMREF = MEMREF.replace('*','') 						# call *eax 에서 %eax만 빼와야 함.
			else:
				MEMREF = MEMREF.group()
			

			# [02] 거르는 인스트럭션
			if 'esp' in MEMREF: 					 				   # 02-01 esp 메모리에 대한 참조연산은 크래시 절대안나는 연산이므로 제외한다. 
				continue

			filterout = 1											   # 02-02 이미 심볼화가 된 메모리참조 연산도 제외한다. ex) call main, call __libc_start_main
			for r in GENERAL_REGISTERS:  
				if r in MEMREF: 
					filterout = 0
			if filterout is 1:
				continue 			

			# 브랜치 인스트럭션의 경우 ATT 신텍스가 이상하다. 예를들어 call *%eax 일 경우, 사실상 call %eax 을 수행한다. 심볼화되면 call MYSYM 으로 되야하므로 별(*)을 제거한다
			itismemref = True
			if MEMREF in GENERAL_REGISTERS: 			# MEMREF가 알고봤더니 그냥 %eax 요거일경우
				DISASM = DISASM.replace('*','') 		# 결과에서 별을 제거한다
				itismemref = False
		
			NEWDISASM  = []	
			NEWDISASM.append(' # add_someprefix_before_all_memory_reference' 		+ ' ' + '#+++++')
			NEWDISASM.append(' pushal' 												+ ' ' + '#+++++') # BACKUP1. 레지스터 컨텍스트 백업
			NEWDISASM.append(' pushf' 												+ ' ' + '#+++++') # BACKUP1. 
			NEWDISASM.append(' mov %esp, MYSYM_ESP'									+ ' ' + '#+++++') # BACKUP2. 스택프레임 백업
			NEWDISASM.append(' push $MYSYM_RETURNTOHERE_' + str(count) 				+ ' ' + '#+++++') # BACKUP3. 위험한 라인의 EIP를 백업
			NEWDISASM.append(' pop MYSYM_EIP' 										+ ' ' + '#+++++') # BACKUP3.
			if itismemref is True: 																	  # BACKUP4. 크래시유발 주소값 백업 MYSYM_CRASHADDR 에 들어감. 
				NEWDISASM.append(' lea ' + MEMREF + ', %eax' 						+ ' ' + '#+++++') # BACKUP4. 	case1. jmp 0x12(%eax) 에서 0x12(%eax) 백업
			elif itismemref is False:	 															  # BACKUP4. 	
				NEWDISASM.append(' lea (' + MEMREF + '), %eax' 						+ ' ' + '#+++++') # BACKUP4.	case2. jmp %eax 에서 %eax 백업
			NEWDISASM.append(' mov %eax, MYSYM_CRASHADDR' 							+ ' ' + '#+++++') # BACKUP4. 
			NEWDISASM.append('MYSYM_RETURNTOHERE_' + str(count) + ':'  				+ ' ' + '#+++++') # > 심볼선언. (EIP 백업. 크래시핸들러는 여기로 컴백홈)
			NEWDISASM.append(' mov MYSYM_CRASHADDR, %eax' 							+ ' ' + '#+++++') # BACKUP5. 크래시유발 주소값에서 READ 시도
			NEWDISASM.append(' mov (%eax), %eax'									+ ' ' + '#+++++') # BACKUP5. 							  >>>CRASH<<<
			NEWDISASM.append(' mov %eax, MYSYM_CRASHADDR_R'							+ ' ' + '#+++++') # BACKUP5. 										 MYSYM_CRASHADDR_R 셋팅
																									  # BACKUP3.         : EIP 복원 							( ---> 크래시핸들러가 해줬음)
																									  # BACKUP4 & BACKUP5 : 크래시유발 주소값 복원및 READ시도	( ---> EIP 복원된후로 재시행됬음)
			NEWDISASM.append(' mov MYSYM_ESP, %esp'									+ ' ' + '#+++++') # BACKUP2. 스택프레임 복원
			NEWDISASM.append(' popf'												+ ' ' + '#+++++') # BACKUP1. 레지스터 컨텍스트 복원
			NEWDISASM.append(' popal'												+ ' ' + '#+++++') # BACKUP1.
			
			
			# 마지막으로 바뀐 디스어셈블리를 붙여준다. 
			if itisbranch is False and itismemref is True:						# [01] 	메모리참조O. 브랜치X.  ex) mov $0x12, 0x12(%eax,%ebx,2)
				if '%eax' not in DISASM.replace(MEMREF, ''): 					# 		%eax : 일반적인 경우 메모리참조연산의 희생자로 %eax 사용				
					NEWDISASM.append(' mov %eax, MYSYM_EAX'																+ ' ' + '#+++++')
					NEWDISASM.append(' mov MYSYM_CRASHADDR, %eax'														+ ' ' + '#+++++')				
					NEWDISASM.append(DISASM.replace(MEMREF, '(%eax)')													+ '# original : ' + resdic['.text'][addr][1][j] + ' ' + '#+++++') 
					NEWDISASM.append(' mov MYSYM_EAX, %eax'																+ ' ' + '#+++++') 		
				else:															# 		%ebx : 예외적인 경우, mov %eax, 0x4(%edi) 같이 source가 %eax인 경우... 이때는 %ebx 사용.
					NEWDISASM.append(' mov %ebx, MYSYM_EBX'																+ ' ' + '#+++++')
					NEWDISASM.append(' mov MYSYM_CRASHADDR, %ebx'														+ ' ' + '#+++++')				
					NEWDISASM.append(DISASM.replace(MEMREF, '(%ebx)')													+ '# original : ' + resdic['.text'][addr][1][j] + ' ' + '#+++++') 
					NEWDISASM.append(' mov MYSYM_EBX, %ebx'																+ ' ' + '#+++++') 

			elif itisbranch is True and itismemref is False:					# [02]	메모리참조X. 브랜치O.  ex) jmp %eax 이거나 jmp *%eax  ---> jmp *MYSYM 으로 바꾼다
				DISASM = DISASM.replace('*','')
				NEWDISASM.append(DISASM.replace(MEMREF, '*MYSYM_CRASHADDR') + '# original : ' + resdic['.text'][addr][1][j] 		+ ' ' + '#+++++')
			elif itisbranch is True and itismemref is True:						# [03]	메모리참조O. 브랜치O.  ex) jmp (%eax) 브랜치하면서 동시에 메모리참조 ---> jmp *MYSYM_R 으로 바꾼다
				NEWDISASM.append(DISASM.replace(MEMREF, '*MYSYM_CRASHADDR_R') + '# original : ' + resdic['.text'][addr][1][j] 		+ ' ' + '#+++++')
			# 끝!
			resdic['.text'][addr][1] = resdic['.text'][addr][1][:j] + NEWDISASM + resdic['.text'][addr][1][j+1:]
			count = count+1


def add_someprefix_before_all_external_functioncall(resdic):
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
			ll = DISASM.strip().split(' ')
			if len(ll) is not 2:
				continue
			
			INSTRUCTION = ll[0] 
			OPERAND     = ll[1]

			# 외부 라이브러리 콜만 필터링한다
			if not INSTRUCTION.startswith('call'):
				continue
			
			if 'MYSYM' in OPERAND: 
				continue

			for namedsymbol in MyNamedSymbol:
				if namedsymbol in OPERAND:
					continue

			NEWDISASM = []
			NEWDISASM.append(' # add_someprefix_before_all_memory_reference' 		+ ' ' + '#+++++')
			NEWDISASM.append(' movl $0x1, MYSYM_LIBFLAG'							+ ' ' + '#+++++') # 라이브러리 크래시 플래그 셋팅
			NEWDISASM.append(' call MYSYM_backupregistercontext'					+ ' ' + '#+++++') #  <<< 1 레지스터 컨텍스트 백업
			NEWDISASM.append(' mov %esp, MYSYM_ESP'									+ ' ' + '#+++++') # 	<<< 2.스택프레임 백업
			NEWDISASM.append(' push $MYSYM_RETURNTOHERE_LIB_' + str(count) 			+ ' ' + '#+++++') # 		<<< 3. 위험한 라인의 EIP를 백업해 둡니다. (크래시핸들러가 관리함) 
			NEWDISASM.append(' pop MYSYM_EIP' 										+ ' ' + '#+++++') # 		>>> 3. EIP 복원
			NEWDISASM.append('MYSYM_RETURNTOHERE_LIB_' + str(count) + ':'  			+ ' ' + '#+++++') #
			NEWDISASM.append(' mov MYSYM_ESP, %esp'									+ ' ' + '#+++++') # 	>>> 2. 스택프레임 복원
			NEWDISASM.append(' call MYSYM_restoreregistercontext'					+ ' ' + '#+++++') #  >>> 1 레지스터 컨텍스트 복원
			# 일반상태랑 다른게있다면, 
			# 일반은					 pushal [스냅샷!] -->	크래시	--> popal
			# 라이브러리일 경우에는 	 pushal [스냅샷!] --> 	popal 	--> 크래시. 그래서 [스냅샷]으로 돌아간다고해도 스택이 손상되어있음. 따라서 call MYSYM_backupregistercontext 써줘야함. 
			NEWDISASM.append(resdic['.text'][addr][1][j])
			NEWDISASM.append( 'movl $0x0, MYSYM_LIBFLAG'							+ ' ' + '#+++++') # 라이브러리 크래시 플래그 복원

			# 끝!
			resdic['.text'][addr][1] = resdic['.text'][addr][1][:j] + NEWDISASM + resdic['.text'][addr][1][j+1:]
			count = count+1



# get_pc_thunk 가 원본바이너리주소를 리턴하도록 바꾼다.
def getpcthunk_to_returnoriginalADDR(resdic): 
	textsections =  ['.text'] + TreatThisSection2TEXT 
	
	# call get_pc_thunk 이전에 원본바이너리주소를 백업한다.
	for sectionName in CodeSections_WRITE:
		if sectionName in resdic.keys() and sectionName in textsections: # 텍스트 섹션이라면
			SORTEDADDR = sorted(resdic[sectionName])
			for i in xrange(len(SORTEDADDR)):
				addr 	 		= SORTEDADDR[i]
				origindexlist 	= pickpick_idx_of_orig_disasm(resdic[sectionName][addr][1])
				for j in reversed(origindexlist):
					DISASM = resdic[sectionName][addr][1][j]
					if '#' in DISASM:
						DISASM = DISASM[:DISASM.index('#')] # 주석 제거
					if 'call' in DISASM and 'get_pc_thunk' in DISASM:
						NEWDISASM = []
						NEWDISASM.append(' movl ${}, MYSYM_EIP'.format(hex(SORTEDADDR[i+1])) 				+ ' ' + '#+++++') # 원본주소(다음인스트럭션의)를 MYSYM_EIP 에 저장 
						NEWDISASM.append(DISASM 																			) # 원본 디스어셈블리
						# 새 디스어셈블리로 교체
						resdic[sectionName][addr][1] = resdic[sectionName][addr][1][:j] + NEWDISASM + resdic[sectionName][addr][1][j+1:]

	for sectionName in CodeSections_WRITE:
		if sectionName in resdic.keys() and sectionName in textsections:
			SORTEDADDR = sorted(resdic[sectionName])
			for i in xrange(len(SORTEDADDR)):
				addr 	 		= SORTEDADDR[i]
				symbolname		= resdic[sectionName][addr][0]
				if 'get_pc_thunk' in symbolname:
					resdic[sectionName][addr][1][0] = resdic[sectionName][addr][1][0].replace('0(%esp)','MYSYM_EIP').replace('(%esp)','MYSYM_EIP') # 원본 : movl 0(%esp), %ebx , 바뀐후 : movl MYSYM_EIP, %ebx

