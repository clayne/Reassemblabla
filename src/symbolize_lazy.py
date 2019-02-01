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
				# 모든 한줄한줄에 Symbol을 다붙여줌
				if resdic[sectionName][addr][0] == '': 
					resdic[sectionName][addr][0] = SYMPREFIX[0] + 'MYSYM_LINE_' + str(count) + ':'
					count += 1

#TODO: 뭔가 스택프레임 망가뜨리는함수있는지 화긴 ㄱㄱ
def setup_some_useful_stuffs_for_crashhandler(resdic): # 레지스터 백업함수를 셋업해둔당
	asm_stuffs = '''
.lcomm MYSYM_EIP, 4 #!!!
.lcomm MYSYM_ESP, 4 #!!! 
.lcomm MYSYM_CRASHADDR, 4
.lcomm MYSYM_CRASHADDR_R, 4



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
	CODEBLOCK_TEXT.append(' ret'	 												+ ' ' + '#+++++') # 리턴ㅋ TODO: 잘동작하나 함 화긴해보쟝


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
	block_crashhandler = {}

	addr_crashhandler = 0xf1000000 # 절대절대절대 바이너리가 맵핑될수없는 주소. 크래시핸들러가위치하는 가상의주소.
	count = 0

	asm_mov_crashvalue_to_eax = 'mov MYSYM_CRASHADDR, %eax' + ' ' + '#+++++'	# 크래시유발한 바로 그 주소값을 %eax 에다가 집어넣는다

	asm_piece_of_crashhandler  = '' + ''
	asm_piece_of_crashhandler += '#+++++'								+ '\n'
	asm_piece_of_crashhandler

	# 한고리한고리의 링크임
	asm_piece_of_crashhandler  += ' cmp $%s, %%eax'						+ '\n'	# 원본 바이너리의 주소값과 비교
	asm_piece_of_crashhandler  += ' jne %s'								+ '\n'	# 아니라면 다음조각으로 점프 

	# 여기서부터 실제 크래시핸들러루틴
	asm_piece_of_crashhandler  += ' lea %s, %%eax'						+ '\n'	# 일치한다면 : 1. 새주소(겉보기에심볼이름임)을  
	asm_piece_of_crashhandler  += ' mov %%eax, MYSYM_CRASHADDR'			+ '\n'	#             								MYSYM_CRASHADDR 안에다가 앉힘 
	asm_piece_of_crashhandler  += ' mov (%%eax), %%eax'					+ '\n'	# 			  2. 새주소에서 메모리 WRITE하여
	asm_piece_of_crashhandler  += ' mov %%eax, MYSYM_CRASHADDR_R' 		+ '\n'	# 											MYSYM_CRASHADDR_R 안에다가 앉힘 (Mem Read하는 Branch에서 사용하기 위해. jmp (%eax) 같은 좆같은거,,)

	asm_piece_of_crashhandler  += ' mov MYSYM_EIP, %%eax'				+ '\n'  # 컴백할 주소를...	
	asm_piece_of_crashhandler  += ' mov %%eax, 0xdc(%%esp)'				+ '\n'  #               ...frame->sc.eip 에다가 집어넣은 후... 
	asm_piece_of_crashhandler  += ' ret'								+ '\n'	# 												    ...sigreturn 으로 시그널핸들러 종료 
	



	block_crashhandler[addr_crashhandler] = [
								'MYSYM_CRASHHANDLER_START:',
								[asm_mov_crashvalue_to_eax],
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
				symbolname = resdic[sectionName][addr][0][:-1]    # :를 빼줘야 한다는거~
				nextpiecename = SYMPREFIX[0] + 'MYSYM_CRASHHANDLER_' + str(count + 1)
		
				block_crashhandler[addr_crashhandler] = [
									  'MYSYM_CRASHHANDLER_' + str(count) + ':', # resolver의 각 항은 jne linked list 로 이어져 있다. 
									  [asm_piece_of_crashhandler % (str(hex(addr)), nextpiecename, symbolname)],
									  '', # 주석자리. 노필요
									  ''  # PIE관련정보 자리. 노필요.
									  ]
				addr_crashhandler += 1
				count += 1

















	# 크래시핸들러 링크의 끝 : 자살!
	block_crashhandler[addr_crashhandler] = [
						  'MYSYM_CRASHHANDLER_' + str(count) + ':', 
						  ['jmp MYSYM_EXIT #+++++'],
						  '',
						  ''  
						  ]

	resdic['.text'].update(block_crashhandler)






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
			itisbranch = False
			if 'MYSYM' in DISASM: 										# 01-01 심볼라이즈된 메모리레퍼런스가 있다면 믿고거른당. 왜냐하면 메모리투메모리 연산은 지원안하는뎅, 메모리가 하나만있지 두개나있냐? 하나있는메모리가 심볼라이즈 이미됬는데 뭘더해,,,,,
				continue
			if DISASM.startswith(' .') or DISASM.startswith('.'):	 	# 01-02 어셈블러 디렉티브라인도 거른당
				continue
			if DISASM.startswith('lea') or DISASM.startswith(' lea'): 	# 01-03 lea는 예외적으로, 메모리주소가나와도 메모리참조가 아니므로 패스으~
				continue
			if '(' not in DISASM or ')' not in DISASM: 					# 01-04 메모리참조가 아니라면!(그치만 branch instruction은 디폴트로 메모리참조이므로 예외처리~)
				if DISASM.startswith('j') or DISASM.startswith(' j'):
					'branch! defultly memory reference. so pass it!'
					itisbranch = True
				elif DISASM.startswith('call') or DISASM.startswith(' call'):
					'branch! defultly memory reference. so pass it!'
					itisbranch = True
				else:
					continue
			

			# MEMREF 설정한다.
			if MEMREF is None: 											# jmp %eax 같은거. (대외적으로 메모리레퍼런스가 아닌척하지만, 사실은 메모리레퍼런스인 경우)
				MEMREF = DISASM.strip().split(' ')[1] 
				MEMREF = MEMREF.replace('*','') 						# 나중에 별까지 치환해주면 안댐. 메모리주소자체는 %eax 이징 *%eax 이게 아니자낭.....
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
			itismemref = True
			if MEMREF in GENERAL_REGISTERS: 			# MEMREF가 알고봤더니 그냥 %eax 요거일경우
				DISASM = DISASM.replace('*','') 		# 결과에서 별 없앤당.
				itismemref = False
			

			NEWDISASM  = []
			
			
			NEWDISASM.append(' # add_someprefix_before_all_memory_reference' 		+ ' ' + '#+++++')
			# BACKUP1. 레지스터 컨텍스트 백업
			NEWDISASM.append(' pushal' 												+ ' ' + '#+++++')
			NEWDISASM.append(' pushf' 												+ ' ' + '#+++++')
			# BACKUP2. 스택프레임 백업
			NEWDISASM.append(' mov %esp, MYSYM_ESP'									+ ' ' + '#+++++')


			# BACKUP3. 위험한 라인의 EIP를 백업해 둡니다. (크래시핸들러가 관리함)
			NEWDISASM.append(' push $MYSYM_CRASHVIRTUALSYM_' + str(count) 			+ ' ' + '#+++++')
			NEWDISASM.append(' pop MYSYM_EIP' 										+ ' ' + '#+++++')


			# BACKUP4. 위험한라인의 위험한곳을 백업합니다. - case1. 0x12(%eax,%ebx,2) 같이 한차원이동하는 메모리레퍼런스인경우 / case2. call %eax 같이 그냥 콜하는경우 모두 동일취급
			NEWDISASM.append(' push %eax'					+ ' ' + '#+++++') 		# %eax 를 쓸것이다
			if itismemref is True: 													# case1. jmp 0x12(%eax) 는 lea 그대로 쓸수있당
				NEWDISASM.append(' lea ' + MEMREF + ', %eax' 	+ ' ' + '#+++++')
			elif itismemref is False:	 											# case2. jmp %eax 같은경우 lea의 src로 못쓰인당,,,
				NEWDISASM.append(' lea (' + MEMREF + '), %eax' 	+ ' ' + '#+++++')
			NEWDISASM.append(' mov %eax, MYSYM_CRASHADDR' 	+ ' ' + '#+++++') 		# 크래시유발 주소값이 MYSYM_CRASHADDR 에 들어감. 
			
			# BACKUP5. 위험한곳에서 읽어서 위험한곳값을 백업합니다 (여기서 크래시유발ㅋㅋㅋㅋㅋ)
			NEWDISASM.append(' mov (%eax), %eax')
			NEWDISASM.append(' mov %eax, MYSYM_CRASHADDR_R')
			NEWDISASM.append(' pop %eax')


			# 크래시핸들러가 컴백홈할 곳은 여기. 심볼선언합니다. 
			NEWDISASM.append('MYSYM_CRASHVIRTUALSYM_' + str(count) + ':'  			+ ' ' + '#+++++')
			
			# BACKUP3 EIP 복원
			'크래시 핸들러가 해줘뜸'

			# BACKUP2. 스택프레임 복원
			NEWDISASM.append(' mov MYSYM_ESP, %esp')
			# BACKUP1. 레지스터 컨텍스트 복원
			NEWDISASM.append(' popf'												+ ' ' + '#+++++')
			NEWDISASM.append(' popal'												+ ' ' + '#+++++')
			
			
			# 마지막으로 바뀐 디스어셈블리를 붙여줍니당~야호~
			if itisbranch is False and itismemref is True:					# 메모리참조하는 노멀한 인스트럭션.. 브랜치가 아닌 인스트럭션인 경우 ex. mov $0x12, 0x12(%eax,%ebx,2)
				NEWDISASM.append(' push %eax')
				NEWDISASM.append(' mov MYSYM_CRASHADDR, %eax')
				NEWDISASM.append(DISASM.replace(MEMREF, '(%eax)')				+ '# original : ' + resdic['.text'][addr][1][j] + ' ' + '#+++++')
				NEWDISASM.append(' pop %eax')
			elif itisbranch is True and itismemref is False:				# jmp %eax 이거나 jmp *%eax  ---> jmp *MYSYM 으로 바꾼다
				DISASM = DISASM.replace('*','')
				NEWDISASM.append(DISASM.replace(MEMREF, '*MYSYM_CRASHADDR') + '# original : ' + resdic['.text'][addr][1][j] + ' ' + '#+++++')
			elif itisbranch is True and itismemref is True:					# jmp (%eax) 브랜치하면서 동시에 메모리참조함 ㅅㅂ ---> jmp *MYSYM_R 으로 바꾼다
				NEWDISASM.append(DISASM.replace(MEMREF, '*MYSYM_CRASHADDR_R') + '# original : ' + resdic['.text'][addr][1][j] + ' ' + '#+++++')

			# 끝!
			resdic['.text'][addr][1] = resdic['.text'][addr][1][:j] + NEWDISASM + resdic['.text'][addr][1][j+1:]
			count = count+1


	









# call get_pc_thunk --> push originaladdr + jmp get_pc_thunk (오리지널 섹션주소를 리턴하도록 함)
def getpcthunk_to_returnoriginalADDR(resdic): 
	textsections =  ['.text'] + TreatThisSection2TEXT 
	
	for sectionName in CodeSections_WRITE:
		if sectionName in resdic.keys() and sectionName in textsections: # 텍스트 섹션이라면~(get_pc_thunk 같은거 호출해주는부분이 있겠지?)
			SORTEDADDR = sorted(resdic[sectionName])
			for i in xrange(len(SORTEDADDR)):
				addr 	 = SORTEDADDR[i]
				origindexlist = pickpick_idx_of_orig_disasm(resdic[sectionName][addr][1])
				for j in reversed(origindexlist):
					DISASM = resdic[sectionName][addr][1][j]
					if '#' in DISASM:
						DISASM = DISASM[:DISASM.index('#')] # 주석 제거
					if 'call' in DISASM and 'get_pc_thunk' in DISASM:
						
						NEWDISASM = []
						NEWDISASM.append(' push ${} #+++++'.format(hex(SORTEDADDR[i+1]))) # 원본주소(다음인스트럭션의)를 푸시한당
						NEWDISASM.append(DISASM.replace('calll','jmp').replace('call','jmp') + ' ' + '#+++++') # 쩜프~ TODO: 참고로 이디자인은 리턴할때마다 크래시남. 효율적인 디자인을 위해서라면 get_pc_thunk 내부디자인을 고쳐야 할 필요성이 있다. (내부적으로 esp+4꺼를 %ebx에다가 옮기고, esp+4하고 나서 저장된 리턴주소로 리턴한다던가 하는...) 무튼 지금은 스킵
																											   # 그리고 참고로 왜 replace를 2번이나 써줬냐면 calll 이 jmpl 로 바뀌어서 jmpl MYSYM 이 되면, 이상하게도 jmp에 suffix가 붙었다는 이유만으로 jmpl *MYSYM이 되버림..... (https://stackoverflow.com/questions/54386736/what-is-jmpl-instruction-in-x86 참고) 그래서 jmp로 꼭 바꺼조야함 ㅎㅅㅎ
						
						# 체인지~
						resdic[sectionName][addr][1] = resdic[sectionName][addr][1][:j] + NEWDISASM + resdic[sectionName][addr][1][j+1:]