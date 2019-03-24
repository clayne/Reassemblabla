#!/usr/bin/python
#-*- coding: utf-8 -*-
from etc import *
from vsa import *



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
.lcomm MYSYM_EIP, 4 
.lcomm MYSYM_MYEXITADDR, 4
.lcomm MYSYM_ESP, 4 
.lcomm MYSYM_STACKLOC, 4
.lcomm MYSYM_CRASHADDR, 4
.lcomm MYSYM_CRASHADDR_R, 4 
.lcomm MYSYM_CRASHADDR_LEFT, 4
.lcomm MYSYM_CRASHADDR_RIGHT, 4

.lcomm MYSYM_LIBFLAG, 4
.lcomm MYSYM_DUMMY, 4
.lcomm MYSYM_CRASHCOUNTER, 4

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
MYSYM_MYEXIT: 
	# movl $0x1, %eax
	# movl $0x3, %ebx
	# int $0x80
	mov MYSYM_MYEXITADDR, %eax
	mov %eax, 0xdc(%esp)              
	ret 	
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


def return_crashhandler_block(addr, nextpiecename, count, symbolname):
	isitgotbased = 'no'
	if 'REGISTER_WHO' in symbolname:
		symbolname = symbolname.replace('REGISTER_WHO','%edx') # 이제 _progname@GOT(%edx) 으로바꾼당. 
		isitgotbased = 'yes'

	# 소비한 레지스터 : eax ebx ecx (이것빼고 다 써도 됨)
	asm_block  =  		'' + ''
	asm_block  += 		'#+++++'										+ ' ' + '#+++++' + '\n'
	asm_block  += 		' cmp $%s, %%eax'								+ ' ' + '#+++++' + '\n'	# %eax : 크래시 유발 주소
	asm_block  += 		' jne %s'										+ ' ' + '#+++++' + '\n'	
	asm_block  += 		' cmp $0x1, MYSYM_LIBFLAG' 						+ ' ' + '#+++++' + '\n'
	asm_block  += 		' jne MYSYM_CRASHHANDLER_ORIG_%s' 				+ ' ' + '#+++++' + '\n' 
	
	# 라이브러리 크래시 - 스택 픽싱
	asm_block  +=    	' add $0x1, MYSYM_CRASHCOUNTER'					+ ' ' + '#+++++' + '\n' # 카운터에 1더해라. 
	asm_block  +=       ' cmpl $0x100, MYSYM_CRASHCOUNTER'				+ ' ' + '#+++++' + '\n' # 100 회 이상 여기에 계속뛴다면 EXIT으로가라.
	asm_block  += 		' je MYSYM_EXIT'								+ ' ' + '#+++++' + '\n'

 	asm_block  += 		' mov MYSYM_ESP, %%ebx'							+ ' ' + '#+++++' + '\n'
	asm_block  += 		' sub $0x4, %%ebx'								+ ' ' + '#+++++' + '\n'
	asm_block  +=  		' mov $0x200, %%ecx'							+ ' ' + '#+++++' + '\n'

	asm_block  += 		'MYSYM_CRASHHANDLER_LIB_%s: '					+ ' ' + '#+++++' + '\n'
	asm_block  += 		' dec %%ecx'									+ ' ' + '#+++++' + '\n' # 카운터 감소(0 == 스택에 크래시유발값이 없는경우)
	asm_block  += 		' jz MYSYM_CRASHHANDLER_LIB_REG_%s'				+ ' ' + '#+++++' + '\n'
	asm_block  += 		' add $0x4, %%ebx'								+ ' ' + '#+++++' + '\n'
	asm_block  += 		' cmp %%eax, (%%ebx)' 							+ ' ' + '#+++++' + '\n'
	asm_block  += 		' jne MYSYM_CRASHHANDLER_LIB_%s' 				+ ' ' + '#+++++' + '\n'
	if isitgotbased == 'yes':
		asm_block += 	' mov MYSYM_HEREIS_GLOBAL_OFFSET_TABLE_, %%edx' + ' ' + '#+++++' + '\n' # _progname@GOT(%edx) 참조하다가 난 경우 
	asm_block  += 		' lea %s, %%eax'								+ ' ' + '#+++++' + '\n' 
	asm_block  += 		' mov %%eax, (%%ebx)'							+ ' ' + '#+++++' + '\n' # Stack Fixing
	asm_block  += 		' mov MYSYM_EIP, %%eax'							+ ' ' + '#+++++' + '\n' # 컴백할 주소를 sc.eip 자리에셋팅후 sigreturn 
	asm_block  += 		' mov %%eax, 0xdc(%%esp)'						+ ' ' + '#+++++' + '\n'             
	asm_block  += 		' ret'											+ ' ' + '#+++++' + '\n'				
	
	# 일반 메모리참조 크래시 - MYSYM_CRASHADDR 픽싱
	asm_block  += 		'MYSYM_CRASHHANDLER_ORIG_%s:'					+ ' ' + '#+++++' + '\n'
	if isitgotbased == 'yes':
		asm_block += 	' mov MYSYM_HEREIS_GLOBAL_OFFSET_TABLE_, %%edx' + ' ' + '#+++++' + '\n' #  _progname@GOT(%edx) 참조하다가 난 경우 
	asm_block  += 		' lea %s, %%eax'								+ ' ' + '#+++++' + '\n'
	asm_block  += 		' mov %%eax, MYSYM_CRASHADDR'					+ ' ' + '#+++++' + '\n' 
	asm_block  += 		' mov MYSYM_EIP, %%eax'							+ ' ' + '#+++++' + '\n' #  컴백할 주소를 sc.eip 자리에셋팅후 sigreturn
	asm_block  += 		' mov %%eax, 0xdc(%%esp)'						+ ' ' + '#+++++' + '\n'
	asm_block  += 		' ret'											+ ' ' + '#+++++' + '\n'
	
	# 레지스터 값들 중 하나가 크래시의 원인 - MYSYM_REG 픽싱
	asm_block  += 		'MYSYM_CRASHHANDLER_LIB_REG_%s:'				+ ' ' + '#+++++' + '\n'
	asm_block  += 		' lea %s, %%esi'								+ ' ' + '#+++++' + '\n'
	asm_block  += 		' lea MYSYM_DUMMY, %%edi'						+ ' ' + '#+++++' + '\n'  
	
	asm_block  += 		' mov $MYSYM_EAX, %%edx' 						+ ' ' + '#+++++' + '\n'  # edx는 edi의 candidate
	asm_block  += 		' cmp %%eax, MYSYM_EAX' 						+ ' ' + '#+++++' + '\n'
	asm_block  += 		' cmove %%edx, %%edi' 							+ ' ' + '#+++++' + '\n'
	asm_block  += 		' mov %%esi, (%%edi)' 							+ ' ' + '#+++++' + '\n'
	
	asm_block  += 		' mov $MYSYM_EBX, %%edx' 						+ ' ' + '#+++++' + '\n'  # edx는 edi의 candidate
	asm_block  += 		' cmp %%eax, MYSYM_EBX' 						+ ' ' + '#+++++' + '\n'
	asm_block  += 		' cmove %%edx, %%edi' 							+ ' ' + '#+++++' + '\n'
	asm_block  += 		' mov %%esi, (%%edi)' 							+ ' ' + '#+++++' + '\n'

	asm_block  += 		' mov $MYSYM_ECX, %%edx' 						+ ' ' + '#+++++' + '\n'  # edx는 edi의 candidate
	asm_block  += 		' cmp %%eax, MYSYM_ECX' 						+ ' ' + '#+++++' + '\n'
	asm_block  += 		' cmove %%edx, %%edi' 							+ ' ' + '#+++++' + '\n'
	asm_block  += 		' mov %%esi, (%%edi)' 							+ ' ' + '#+++++' + '\n'

	asm_block  += 		' mov $MYSYM_EDX, %%edx' 						+ ' ' + '#+++++' + '\n'  # edx는 edi의 candidate
	asm_block  += 		' cmp %%eax, MYSYM_EDX' 						+ ' ' + '#+++++' + '\n'
	asm_block  += 		' cmove %%edx, %%edi' 							+ ' ' + '#+++++' + '\n'
	asm_block  += 		' mov %%esi, (%%edi)' 							+ ' ' + '#+++++' + '\n'

	asm_block  += 		' mov $MYSYM_EDI, %%edx' 						+ ' ' + '#+++++' + '\n'  # edx는 edi의 candidate
	asm_block  += 		' cmp %%eax, MYSYM_EDI' 						+ ' ' + '#+++++' + '\n'
	asm_block  += 		' cmove %%edx, %%edi' 							+ ' ' + '#+++++' + '\n'
	asm_block  += 		' mov %%esi, (%%edi)' 							+ ' ' + '#+++++' + '\n'

	asm_block  += 		' mov $MYSYM_ESI, %%edx' 						+ ' ' + '#+++++' + '\n'  # edx는 edi의 candidate
	asm_block  += 		' cmp %%eax, MYSYM_ESI' 						+ ' ' + '#+++++' + '\n'
	asm_block  += 		' cmove %%edx, %%edi' 							+ ' ' + '#+++++' + '\n'
	asm_block  += 		' mov %%esi, (%%edi)' 							+ ' ' + '#+++++' + '\n'

	asm_block  += 		' mov $MYSYM_EBP, %%edx' 						+ ' ' + '#+++++' + '\n'  # edx는 edi의 candidate
	asm_block  += 		' cmp %%eax, MYSYM_EBP' 						+ ' ' + '#+++++' + '\n'
	asm_block  += 		' cmove %%edx, %%edi' 							+ ' ' + '#+++++' + '\n'
	asm_block  += 		' mov %%esi, (%%edi)' 							+ ' ' + '#+++++' + '\n'

	asm_block  += 		' mov MYSYM_EIP, %%eax'							+ ' ' + '#+++++' + '\n' # 컴백할 주소를 sc.eip 자리에셋팅후 sigreturn 
	asm_block  += 		' mov %%eax, 0xdc(%%esp)'						+ ' ' + '#+++++' + '\n'             
	asm_block  += 		' ret'											+ ' ' + '#+++++' + '\n'				


	return asm_block % (str(hex(addr)), nextpiecename, str(count), str(count), str(count), str(count), symbolname, str(count), symbolname, str(count), symbolname)



def setupsignalhandler(resdic):
	CRASHHANDLER = {}

	addr_crashhandler = 0xf1000000 # 절대절대절대 바이너리가 맵핑될수없는 주소. 크래시핸들러가위치하는 가상의주소.
	count = 0

	# asm_prifix = ' mov MYSYM_CRASHADDR, %eax' 		+ ' ' + '#+++++' + '\n' # 크래시유발한 바로 그 주소값을 %eax 에다가 집어넣는다 COMMENT: 이거 외부라이브러리에서 크래시나면 무슨값을참조하다났는지 스택으로만 알수있기때문에 우선 스택을 쓰도록 했음.
	asm_prifix = ' mov 0x1c(%esp), %eax'			+ ' ' + '#+++++' + '\n'
	
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
									  [return_crashhandler_block(addr, nextpiecename, count, symbolname)],
									  '', 												# 주석자리. 노필요
									  ''  												# PIE관련정보 자리. 노필요.
									  ]
				addr_crashhandler += 1
				count += 1
	
	CRASHHANDLER[addr_crashhandler] = [													# 크래시핸들러 링크의 끝 : 자살! URGENT: 이거를 그냥 마지막에는 MYSYM_EIP 로 리턴하도록 디자인하면 어떨까?
						  'MYSYM_CRASHHANDLER_' + str(count) + ':', 	
						  ['jmp MYSYM_MYEXIT #+++++'],
						  '',
						  ''  
						  ]    
	resdic['.text'].update(CRASHHANDLER)
	




def symbolize_crashhandler_allmemref(resdic): # TODO: lea __procname@GOT(REGISTER_WHO), %eax 이거 앞에 MYSYM_HEREIS_GLOBAL_OFFSET_TABLE_ 사용하도록 고칠 것. 
	_ = '.*?'
	count = 0

	SORTEDADDR = sorted(resdic['.text'])
	for i in xrange(len(resdic['.text'].keys())):
		addr = SORTEDADDR[i]
		origindexlist = pickpick_idx_of_orig_disasm(resdic['.text'][addr][1]) 
		for j in reversed(origindexlist):
			DISASM = resdic['.text'][addr][1][j]
			if 'Prefix added' in DISASM: # 이미 다른 함수에서 프리픽스가 추가된 상태임...
				continue
			if '#' in DISASM: # 주석떼버리기
				DISASM = DISASM[:DISASM.index('#')] 
			MEMREF = p_PATTERN_MEMREF_REGISTER.search(DISASM) # 1. 0x12(%eax,%ebx,4) 객체를 찾는다. 
			
			_ = p_PATTERN_SEGMENTREGISTER.findall(DISASM) # COMMENT: 20190217: 위의 메모리패턴 regex가 %ds:(%eax) 도 처리해주는바람에 예외처리함. 
			if len(_) is not 0:
				continue


			# [01] 거르는 인스트럭션
			itisbranch = False
			if DISASM.startswith('j') or DISASM.startswith(' j') or DISASM.startswith('call') or DISASM.startswith(' call'):
				itisbranch = True

			if 'MYSYM' in DISASM: # 01-01 심볼라이즈된 메모리레퍼런스가 있다면 거른다. 
				continue
			if DISASM.startswith(' .') or DISASM.startswith('.'): # 01-02 어셈블러 디렉티브라인도 제외한다. 
				continue
			if DISASM.startswith('lea') or DISASM.startswith(' lea'): # 01-03 lea는 예외적으로, 메모리주소가나와도 메모리참조가 아니므로 패스한다. 
				continue
			if '(' not in DISASM or ')' not in DISASM: # 01-04 메모리참조가 아니라면 거른다 (그치만 branch instruction은 디폴트로 메모리참조이므로 예외처리)
				if itisbranch is False:
					continue

			# MEMREF 설정한다.
			if MEMREF is None: 											# jmp %eax 같은거. (레지스터만 봤을 때 메모리참조가 아닌것처럼 보이지만, 사실은 메모리레퍼런스인 경우)
				MEMREF = DISASM.strip().split(' ')[1] 
				MEMREF = MEMREF.replace('*','') 						# call *eax 에서 %eax만 빼와야 함.
			else:
				MEMREF = MEMREF.group().replace('*','')					# call *-0x294(%ebx, %edi, 4) 인경우 call -0x294(%ebx, %edi, 4) 와 같다. 
			
			# MEMREF 관련 거르는 인스트럭션 1 : esp 메모리에 대한 참조연산은 크래시 절대안나는 연산이므로 제외한다. --> 아니다. 스택을 이용한 이중참조가 있을 수 있다. ex) call 0x12(%esp)의 경우, 0x0804100을 호출하므로 valid한 인스트럭션이다.
			if '%esp' in MEMREF and itisbranch is False: # mov 0x12(%esp), %ebx 같은 연산이라면 패스
				continue 
			'''
			if '%ebp' in MEMREF and itisbranch is False:
				continue
			'''
			# MEMREF 관련 거르는 인스트럭션 2 : 이미 심볼화된것들은 거른다
			alreadySymbolized = 1
			for r in GENERAL_REGISTERS: # general register 가 하나라도 있어야 살려줄것이다. (call main, call __libc_start_main 이런거 제외하기 위함)
				if r in MEMREF: alreadySymbolized = 0
			if alreadySymbolized is 1:
				continue 			







			# 브랜치 인스트럭션의 경우 ATT 신텍스가 이상하다. 예를들어 call *%eax 일 경우, 사실상 call %eax 을 수행한다. 심볼화되면 call MYSYM 으로 되야하므로 별(*)을 제거한다
			itismemref = True
			if MEMREF in GENERAL_REGISTERS: 							# MEMREF가 알고봤더니 그냥 %eax 요거일경우
				DISASM = DISASM.replace('*','') 						# 결과에서 별을 제거한다
				itismemref = False
			
			NEWDISASM  = []	
			NEWDISASM.append('')
			NEWDISASM.append(' # symbolize_crashhandler_allmemref' 														+ ' ' + '#+++++')
			NEWDISASM.append(' call MYSYM_backupregistercontext' 														+ ' ' + '#+++++') 
			NEWDISASM.append(' mov %esp, MYSYM_ESP'																		+ ' ' + '#+++++') 
			NEWDISASM.append(' movl $0x0, MYSYM_LIBFLAG'																+ ' ' + '#+++++')
			ref_level = 0

			# 애초에 MYSYM_CRASHADDR 에 저장되는게 다르자나. 그러면 나중에 처리해줄때에는 똑같겠지.....
			if   itismemref is True and itisbranch is False:   # (%eax) 에 대한 1중참조 																										  
				ref_level = 1
				NEWDISASM.append(' lea ' + MEMREF + ', %eax' 															+ ' ' + '#+++++') 
			elif itismemref is False and itisbranch is True :  #  %eax  에 대한 1중참조	: 분명히 1중참조이지만, 외양상 0중참조이므로 임의로 ()를 붙여줘야 함																							  
				ref_level = 1
				NEWDISASM.append(' lea (' + MEMREF + '), %eax' 															+ ' ' + '#+++++') 
			elif itismemref is True and itisbranch is True :   # (%eax) 에 대한 2중참조. (%eax가 가리키는 메모리가 가리키는 메모리)
				ref_level = 2
				NEWDISASM.append(' lea ' + MEMREF + ', %eax' 															+ ' ' + '#+++++')  	
			
			NEWDISASM.append(' movl $MYSYM_RETURNTOHERE_'+str(count)+', MYSYM_EIP'										+ ' ' + '#+++++') # 컴백1
			NEWDISASM.append(' mov %eax, MYSYM_CRASHADDR' 																+ ' ' + '#+++++') 
			NEWDISASM.append('MYSYM_RETURNTOHERE_' + str(count) + ':'  													+ ' ' + '#+++++') 
			NEWDISASM.append(' mov MYSYM_CRASHADDR, %eax' 																+ ' ' + '#+++++') 
			NEWDISASM.append(' mov (%eax), %eax'																		+ ' ' + '#+++++') # 차원증가. 1차원
			if ref_level is 2: # 레퍼런스 레벨이 2 라면, 한번 더 메모리 레퍼런스를 검증
				NEWDISASM.append(' movl $MYSYM_RETURNTOHERE2_'+str(count)+', MYSYM_EIP'									+ ' ' + '#+++++') # 컴백2
				NEWDISASM.append(' mov %eax, MYSYM_CRASHADDR' 															+ ' ' + '#+++++') 
				NEWDISASM.append('MYSYM_RETURNTOHERE2_' + str(count) + ':'  											+ ' ' + '#+++++') 
				NEWDISASM.append(' mov MYSYM_CRASHADDR, %eax' 															+ ' ' + '#+++++') 
				NEWDISASM.append(' mov (%eax), %eax'																	+ ' ' + '#+++++') # 차원증가. 2차원

																									  
			NEWDISASM.append(' mov MYSYM_ESP, %esp'																		+ ' ' + '#+++++') # esp 백업
			NEWDISASM.append(' call MYSYM_restoreregistercontext'														+ ' ' + '#+++++') # 레지스터컨텍스트 백업
			
			
			# 마지막으로 바뀐 디스어셈블리를 붙여준다. 
			if itisbranch is False: # 브랜치가 아닌 일반적인 멤참조  ex) mov $0x12, 0x12(%eax,%ebx,2)
				_ = DISASM.replace(MEMREF, '')
				if '%eax' in _ or '%ax' in _ or '%al' in _ or '%ah' in _: # %ebx : 예외적인 경우, mov %eax, 0x4(%edi) 같이 source가 %eax인 경우... 이때는 %ebx 사용.
					NEWDISASM.append(' # _ : {}.....Lets use EBX!!!'.format(_))
					NEWDISASM.append(' mov %ebx, MYSYM_EBX'																+ ' ' + '#+++++') # TODO: 이거 필요 없을것같음. 위에서 이미 MYSYM_restoreregistercontext 를 호출하자나?
					NEWDISASM.append(' mov MYSYM_CRASHADDR, %ebx'														+ ' ' + '#+++++')				
					NEWDISASM.append(DISASM.replace(MEMREF, '(%ebx)')													+ ' # Prefix added. original({}) : {}, MEMREF : {} #+++++'.format(hex(addr), resdic['.text'][addr][1][j], MEMREF)) 
					NEWDISASM.append(' mov MYSYM_EBX, %ebx'																+ ' ' + '#+++++') 
				else: # 디폴트로는  %eax  사용~~~
					NEWDISASM.append(' # _ : {}.....Lets use EAX!!!'.format(_))
					NEWDISASM.append(' mov %eax, MYSYM_EAX'																+ ' ' + '#+++++') # TODO: 이거 필요 없을것같음.
					NEWDISASM.append(' mov MYSYM_CRASHADDR, %eax'														+ ' ' + '#+++++')				
					NEWDISASM.append(DISASM.replace(MEMREF, '(%eax)')													+ ' # Prefix added. original({}) : {}, MEMREF : {} #+++++'.format(hex(addr), resdic['.text'][addr][1][j], MEMREF)) 
					NEWDISASM.append(' mov MYSYM_EAX, %eax'																+ ' ' + '#+++++') 	
			elif itisbranch is True: # 브랜치
				DISASM = DISASM.replace('*','')
				NEWDISASM.append(DISASM.replace(MEMREF, '*MYSYM_CRASHADDR') + ' # Prefix added. original({}) : {}, MEMREF : {} #+++++'.format(hex(addr), resdic['.text'][addr][1][j], MEMREF))
				
			
			# 끝!
			resdic['.text'][addr][1] = resdic['.text'][addr][1][:j] + NEWDISASM + resdic['.text'][addr][1][j+1:]
			count += 1
	symbolize_counter('Crash(general memory refernece) : {}'.format(count))

'''
# 메모리레퍼런스가 하나만 있는거
lods %ds:(%esi), %al   # l/b 의 써픽스가 붙지 않음. 데스티네이션이 레지스터인 경우는 안 붙어도 되는구나. 
lods %ds:(%esi), %eax
rep lods %ds:(%esi), %al
rep lods %ds:(%esi), %eax
scasb %es:(%edi), %al
scasl %es:(%edi), %eax
repe scasb %es:(%edi), %al
repe scasl %es:(%edi), %eax
repne scasb %es:(%edi), %al
repne scasl %es:(%edi), %eax
stos %al, %es:(%edi)
stos %eax, %es:(%edi)
rep stos %al, %es:(%edi)
rep stos %eax, %es:(%edi)
xlat %ds:(%ebx)
'''
def symbolize_crashhandler_segmentregister_1(resdic):
	_ = '.*?'
	count = 0
	SORTEDADDR = sorted(resdic['.text'])
	for i in xrange(len(resdic['.text'].keys())):
		addr = SORTEDADDR[i]
		origindexlist = pickpick_idx_of_orig_disasm(resdic['.text'][addr][1]) 
		for j in reversed(origindexlist):
			DISASM = resdic['.text'][addr][1][j]
			if 'Prefix added' in DISASM: # 이미 다른 함수에서 프리픽스가 추가된 상태임...
				continue
			if '#' in DISASM: # 주석떼버리기
				DISASM = DISASM[:DISASM.index('#')] 

			# 어셈블러 디렉티브라인도 제외한다 
			if DISASM.startswith(' .') or DISASM.startswith('.'):  
				continue

			# 인스트럭션이  lods, scas, stos, xlat 인 경우만 대상으로 한다. 
			_components = DISASM.split()
			if len(_components) < 2: # 예외처리
				continue
			if _components[0].startswith('rep'):
				_instruction = _components[1]
			else:
				_instruction = _components[0]
			target_instruction = 'no'
			for _segment_instruction in ['lods','scas','stos','xlat', 'ins', 'outs']: # ins, outs 도 포함. 
				if _instruction.startswith(_segment_instruction):
					target_instruction = 'yes'
			if target_instruction is 'no':
				continue 

			# %fs, %gs의 베이스주소는 0이 아니므로 이 휴리스틱을 적용할 수 없다. 
			if '%fs' in DISASM or '%gs' in DISASM:
				continue

			# 메모리참조하는 부분만 추출한다. (%ds:(%eax)) (일하기 싫어하는 캡스톤은 가끔가다가 (%eax) 이렇게 나타내기도 함. 그런데 그런 경우, 이미 위에서 핸들링이 되어있겠지.. 그러니 지금시점에서는 신경안써줘도 된다. ) 
			MEMREF = DISASM[DISASM.index('('): DISASM.index(')') + 1] # %cs, %ds, %ss, %es 같은 유명무실한 (base address 값이 0) 레지스터 제거
			MEMREF_REG = MEMREF.replace('(','').replace(')','')

			NEWDISASM  = []	
			NEWDISASM.append('')
			NEWDISASM.append(' # symbolize_crashhandler_segmentregister_1' 		+ ' ' + '#+++++')
			NEWDISASM.append(' call MYSYM_backupregistercontext'								+ ' ' + '#+++++') 
			NEWDISASM.append(' mov %esp, MYSYM_ESP'												+ ' ' + '#+++++') 
			NEWDISASM.append(' movl $0x0, MYSYM_LIBFLAG'										+ ' ' + '#+++++')

			NEWDISASM.append(' movl $MYSYM_RETURNTOHERE_SEG1_' + str(count) + ', MYSYM_EIP'		+ ' ' + '#+++++') 
			NEWDISASM.append(' mov ' + MEMREF_REG + ', MYSYM_CRASHADDR' 						+ ' ' + '#+++++') 
			NEWDISASM.append('MYSYM_RETURNTOHERE_SEG1_' + str(count) + ':'  					+ ' ' + '#+++++') 
			NEWDISASM.append(' mov MYSYM_CRASHADDR, %eax'										+ ' ' + '#+++++') 
			NEWDISASM.append(' mov (%eax), %eax'												+ ' ' + '#+++++') # 크래시 여부 테스트
			 
			NEWDISASM.append(' call MYSYM_restoreregistercontext'								+ ' ' + '#+++++')
			NEWDISASM.append(' mov MYSYM_ESP, %esp'												+ ' ' + '#+++++')

			NEWDISASM.append(' mov MYSYM_CRASHADDR, ' + MEMREF_REG								+ ' ' + '#+++++') # SETTING. 마지막으로 크래시유발 레지스터값을 (resolve해준) 레지스터값으로 셋팅 
			# 원본 디스어셈블리를 붙여준다.
			resdic['.text'][addr][1][j] += ' # Prefix added.' # 프리픽스 핸들링해줬다는 플래그를 붙인다. 
			resdic['.text'][addr][1] = resdic['.text'][addr][1][:j] + NEWDISASM + resdic['.text'][addr][1][j:] 
			count = count+1
	symbolize_counter('Crash(segment register 1) : {}'.format(count))




'''
movsb (%esi), %es:(%edi)
movsl (%esi), %es:(%edi)
rep movsb (%esi), %es:(%edi)
rep movsl (%esi), %es:(%edi)
outsb %ds:(%esi), (%dx)
outsl %ds:(%esi), (%dx)
rep outsb %ds:(%esi), (%dx)
rep outsl %ds:(%esi), (%dx)
insb (%dx), %es:(%edi) 
insl (%dx), %es:(%edi) 
rep insb (%dx), %es:(%edi) 
rep insl (%dx), %es:(%edi) # 그냥 dx구나!
cmpsb %es:(%di), %ds:(%si)
cmpsl %es:(%edi), %ds:(%esi)
repne cmpsb %es:(%di), %ds:(%si)
repne cmpsl %es:(%edi), %ds:(%esi)
repe cmpsb %es:(%di), %ds:(%si)
repe cmpsl %es:(%edi), %ds:(%esi)
'''
# movsb, outsb, insb, cmpsb 
def symbolize_crashhandler_segmentregister_2(resdic):
	_ = '.*?'
	count = 0
	SORTEDADDR = sorted(resdic['.text'])

	for i in xrange(len(resdic['.text'].keys())):
		addr = SORTEDADDR[i]
		origindexlist = pickpick_idx_of_orig_disasm(resdic['.text'][addr][1]) 
		for j in reversed(origindexlist):
			DISASM = resdic['.text'][addr][1][j]
			if 'Prefix added' in DISASM: # 이미 다른 함수에서 프리픽스가 추가된 상태임...
				continue
			if '#' in DISASM: # 주석떼버리기
				DISASM = DISASM[:DISASM.index('#')] 

			# 어셈블러 디렉티브라인을 제외한다 
			if DISASM.startswith(' .') or DISASM.startswith('.'):  
				continue

			# 인스트럭션이 movs, outs, ins, cmps 인 경우만 대상으로 한다. 
			_components = DISASM.split()
			if len(_components) < 2: # 예외처리
				continue
			if _components[0].startswith('rep'):
				_instruction = _components[1]
			else:
				_instruction = _components[0]
			target_instruction = 'no'
			for _segment_instruction in ['movs','cmps']: # ['movs','outs','ins','cmps'] COMMENT: ins, outs 의 형태는 insb (%ds), %es:(%edi) 가 된다. 그런데 1. (%ds)는 port를 의미한다는데, 크래시위험이 없음. 이미셋팅된값을 의미하기때문 / 또한 캡스톤에서 버그가 잇는데 insb %ds, %es:(%edi) 로 잘못 디스어셈블한다는 점. 따라서 symbolize_crashhandler_segmentregister_1 로 보내자. 
				if _instruction.startswith(_segment_instruction):
					target_instruction = 'yes'
			if _instruction.startswith('movsbl') or _instruction.startswith('movzbl') or _instruction.startswith('movswl') or _instruction.startswith('movzwl') or _instruction.startswith('movsbw') or _instruction.startswith('movszw'): # movsbl(==movzbl) 은 다른인스트럭션이므로 예외처리. (메모리(source)에서 UNSigned single byte 읽어와가지고 그 읽어온값을 레지스터(destination)에다가 넣는다.) 
				target_instruction = 'no' 

			if target_instruction is 'no':
				continue 

			# 메모리참조하는 부분만 추출한다. ex) movsl (%esi), %es:(%edi) 에서 (%esi), (%edi) 를 추출함
			_ = DISASM
			MEMREF_1 = _[_.index('('):_.index(')') + 1] 
			_ = _.replace(MEMREF_1,'') 
			MEMREF_2 = _.replace(MEMREF_1,'')[_.index('('):_.index(')') + 1] 
			MEMREF_1_REG = MEMREF_1.replace('(','').replace(')','') 
			MEMREF_2_REG = MEMREF_2.replace('(','').replace(')','') 

			NEWDISASM  = []	
			NEWDISASM.append('')
			NEWDISASM.append(' # symbolize_crashhandler_segmentregister_2'				 		+ ' ' + '#+++++')
			NEWDISASM.append(' call MYSYM_backupregistercontext' 								+ ' ' + '#+++++') 
			NEWDISASM.append(' mov %esp, MYSYM_ESP'												+ ' ' + '#+++++') 
			NEWDISASM.append(' movl $0x0, MYSYM_LIBFLAG'										+ ' ' + '#+++++')

			# 두개의 잠재적 크래시유발러 백업
			NEWDISASM.append(' mov ' + MEMREF_1_REG + ', MYSYM_CRASHADDR_LEFT'					+ ' ' + '#+++++')
			NEWDISASM.append(' mov ' + MEMREF_2_REG + ', MYSYM_CRASHADDR_RIGHT'					+ ' ' + '#+++++')

			# 첫번째 잠재적 크래시유발러 핸들링부분
			NEWDISASM.append(' push MYSYM_CRASHADDR_LEFT'				 						+ ' ' + '#+++++') 
			NEWDISASM.append(' pop MYSYM_CRASHADDR'						 						+ ' ' + '#+++++') 

			NEWDISASM.append(' push $MYSYM_RETURNTOHERE_SEG2_LEFT_' + str(count) 				+ ' ' + '#+++++') # EIP 설정 
			NEWDISASM.append(' pop MYSYM_EIP' 													+ ' ' + '#+++++') 

			NEWDISASM.append('MYSYM_RETURNTOHERE_SEG2_LEFT_' + str(count) + ':'  				+ ' ' + '#+++++') 
			NEWDISASM.append(' mov MYSYM_CRASHADDR,   %eax'										+ ' ' + '#+++++') 
			NEWDISASM.append(' mov (%eax), %eax'												+ ' ' + '#+++++') # >>>CRASH<<<
			NEWDISASM.append(' push MYSYM_CRASHADDR'											+ ' ' + '#+++++')
			NEWDISASM.append(' pop MYSYM_CRASHADDR_LEFT'										+ ' ' + '#+++++')


			# 두번째 잠재적 크래시유발러 핸들링부분
			NEWDISASM.append(' push MYSYM_CRASHADDR_RIGHT'				 						+ ' ' + '#+++++') 
			NEWDISASM.append(' pop MYSYM_CRASHADDR'						 						+ ' ' + '#+++++') 

			NEWDISASM.append(' push $MYSYM_RETURNTOHERE_SEG2_RIGHT_' + str(count) 				+ ' ' + '#+++++') # EIP 설정
			NEWDISASM.append(' pop MYSYM_EIP' 													+ ' ' + '#+++++')

			NEWDISASM.append('MYSYM_RETURNTOHERE_SEG2_RIGHT_' + str(count) + ':'  				+ ' ' + '#+++++')
			NEWDISASM.append(' mov MYSYM_CRASHADDR, %eax'										+ ' ' + '#+++++') 
			NEWDISASM.append(' mov (%eax), %eax'												+ ' ' + '#+++++') # >>>CRASH<<<
			NEWDISASM.append(' push MYSYM_CRASHADDR'											+ ' ' + '#+++++')
			NEWDISASM.append(' pop MYSYM_CRASHADDR_RIGHT'										+ ' ' + '#+++++')

			NEWDISASM.append(' call MYSYM_restoreregistercontext'								+ ' ' + '#+++++')
			NEWDISASM.append(' mov MYSYM_ESP, %esp'												+ ' ' + '#+++++')



			NEWDISASM.append(' mov MYSYM_CRASHADDR_LEFT, '    + MEMREF_1_REG					+ ' ' + '#+++++')
			NEWDISASM.append(' mov MYSYM_CRASHADDR_RIGHT, '   + MEMREF_2_REG					+ ' ' + '#+++++')
			# 원본 디스어셈블리를 붙여준다.
			resdic['.text'][addr][1] = resdic['.text'][addr][1][:j] + NEWDISASM + resdic['.text'][addr][1][j:]
			count = count+1	
	symbolize_counter('Crash(segment register 2) : {}'.format(count))



def symbolize_crashhandler_externalfunctioncall(resdic):
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
			funcName     = ll[1]

			# 외부 라이브러리 콜만 필터링한다
			if INSTRUCTION.startswith('call') or INSTRUCTION.startswith('jmp') : # jmp __fprintf_chk 으로, 립씨함수로 call하는게 아니라 jmp하는 경우도 있다!
				'external function call!'
			else:
				continue

			if 'MYSYM' in funcName: 
				continue
			if funcName is 'main':
				continue
			if funcName.startswith('__x86.get_pc_thunk'):
				continue
			if funcName in symbolize_heuristic_list_call: # 이 함수는 내가 확실히 파라미터에 관한 정보를 아는 함수다. 그러니까 휴리스틱하게 처리해줄거니깐 하지마라. 
				'GO TO symbolize_crashhandler_externalfunctioncall_heuristically'
				continue 
			c = 'no'
			for _r in GENERAL_REGISTERS: # call *%eax, call (%ebx) 이런것들
				if _r in funcName:
					c = 'yes'
			if c is 'yes':
				continue

			symbolname0 = 'MYSYM_LIBCALL_' + hex(addr)
			symbolname1 = 'MYSYM_RETURNTOHERE_LIB_' + hex(addr)

			NEWDISASM = []
			NEWDISASM.append('')
			NEWDISASM.append('# symbolize_crashhandler_externalfunctioncall'	    		+ ' ' + '#+++++')
			# [01] 가장급한건 컨텍스트 저장		
			NEWDISASM.append(' call MYSYM_backupregistercontext'							+ ' ' + '#+++++') 
			NEWDISASM.append(' mov %esp, MYSYM_ESP'											+ ' ' + '#+++++') 
			# [02] 플래그같은거 설정해줌
			NEWDISASM.append(' movl $' + symbolname0 + ', MYSYM_MYEXITADDR'			 		+ ' ' + '#+++++') # 라이브러리 콜부를 MYSYM_MYEXITADDR 에다가 저장한다.
			NEWDISASM.append(' movl $0x0, MYSYM_CRASHCOUNTER'								+ ' ' + '#+++++')
			# [03] 여기서부터 크래시핸들러 관련된것 설정
			NEWDISASM.append(' movl $' + symbolname1 + ', MYSYM_EIP'						+ ' ' + '#+++++') # 플래그는 항상 크래시 핸들러 호출하기 전에 설정한다. 크래시핸들러 한번 들어갔다나오면 0으로 초기화되므로
			NEWDISASM.append(symbolname1 + ':'  											+ ' ' + '#+++++') 
			NEWDISASM.append(' movl $0x1, MYSYM_LIBFLAG'									+ ' ' + '#+++++') 
			NEWDISASM.append(' mov MYSYM_ESP, %esp'											+ ' ' + '#+++++') 
			NEWDISASM.append(' call MYSYM_restoreregistercontext'							+ ' ' + '#+++++') 
					
			NEWDISASM.append(symbolname0 + ':'												+ ' ' + '#+++++') # COMMENT: 이건 사실 없어도 되잖아? 왜냐하면........ 아냐근데 있어도 되니까 냅두자
			NEWDISASM.append(resdic['.text'][addr][1][j]													)

			# 끝!
			resdic['.text'][addr][1]  = resdic['.text'][addr][1][:j] + NEWDISASM + resdic['.text'][addr][1][j+1:]
			count = count+1
	
	symbolize_counter('Crash(external functioncall) : {}'.format(count))



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


def heuristic_stack_fixing(resdic_text, ADDR, nst_param_list): # COMMENT: 휴리스틱 픽싱할때는, LIBFLAG를 설정해주면 안됨. 왜냐하면 크래시핸들러가 스택을 직접바꾸는게 아니라, 아래의 인스트루멘테이션 된 인스트럭션에서 CRASHADDR를 이용해서 스택을 손봐주기 때문에.

	origindexlist = pickpick_idx_of_orig_disasm(resdic_text[ADDR][1]) 
	j = 0
	NEWDISASM = []
	symbolname0 = 'MYSYM_LIBCALL_' + hex(ADDR)

	# [01] 가장급한건 컨텍스트 저장
	NEWDISASM.append('')
	NEWDISASM.append(' # heuristic_stack_fixing' 											+ ' ' + '#+++++')
	NEWDISASM.append(' call MYSYM_backupregistercontext' 									+ ' ' + '#+++++') 
	NEWDISASM.append(' mov %esp, MYSYM_ESP'													+ ' ' + '#+++++') 
	NEWDISASM.append(' movl $0x0, MYSYM_LIBFLAG'												+ ' ' + '#+++++')

	# [02] 플래그같은거 설정해줌 
	NEWDISASM.append(' movl $' + symbolname0 + ', MYSYM_MYEXITADDR' 							+ ' ' + '#+++++') 
	for paramnum in nst_param_list:
		if paramnum > 1000: # 입력 파라미터가 몇개인지 모른다. n번째부터 n+???개의 파라미터를 심볼화해줘야 한다는 뜻.
			paramnum = paramnum/1000
			LOC_ESP   = '{}(%esp)'.format(hex(4*(paramnum - 1))) 
			symbolname1 = 'MYSYM_FORLOOP_' + hex(ADDR) 
			symbolname2 = 'MYSYM_PARAMINFI_' + hex(ADDR)  

			# n~ 번째 파라미터에 대한 스택픽싱을 설치한당.
			NEWDISASM.append('')
			NEWDISASM.append(' # ' + ' ∞st stack fixing... : ' + LOC_ESP	  			    + ' ' + '#+++++')
			NEWDISASM.append(' lea ' + LOC_ESP + ', %esi'									+ ' ' + '#+++++') # 현재스택의위치 저장
			NEWDISASM.append(' mov %esi, MYSYM_STACKLOC'									+ ' ' + '#+++++')

			NEWDISASM.append(symbolname1 + ':'												+ ' ' + '#+++++')
			NEWDISASM.append(' movl $' + symbolname2 +', MYSYM_EIP' 						+ ' ' + '#+++++') # 크래시핸들러가 리턴할 주소는 여기다. 만약에 크래시핸들러가 EXIT갈때까지갔다면, MYSYM_MYEXIT 에서는 바로 라이브러리콜하는곳으로 간당.
			
			NEWDISASM.append(' mov MYSYM_STACKLOC, %esi'									+ ' ' + '#+++++') # esi (%esp 대체품) 에서부터 쫄쫄 올라가면서 스택픽싱한당.
			NEWDISASM.append(' mov (%esi), %eax' 											+ ' ' + '#+++++')
			
			NEWDISASM.append(' mov %eax, MYSYM_CRASHADDR' 									+ ' ' + '#+++++')
			NEWDISASM.append( symbolname2 + ':'									 			+ ' ' + '#+++++') # 컴백은 여기로.
			NEWDISASM.append(' mov MYSYM_CRASHADDR, %eax' 									+ ' ' + '#+++++') # 값읽기 : 스택 -> %eax 
			NEWDISASM.append(' mov (%eax), %ebx'											+ ' ' + '#+++++') # 크래시유발 (%eax 의 유효성검증)
			NEWDISASM.append(' mov MYSYM_STACKLOC, %esi'									+ ' ' + '#+++++')
			NEWDISASM.append(' mov %eax, (%esi)' 											+ ' ' + '#+++++')
			NEWDISASM.append(' add $0x4, MYSYM_STACKLOC'									+ ' ' + '#+++++')

			NEWDISASM.append(' jmp ' + symbolname1 											+ ' ' + '#+++++')

		else:
			LOC_ESP  = '{}(%esp)'.format(hex(4*(paramnum - 1))) # 첫번째 파라미터라면 esp+0, 두번째 파라미터라면 esp+4, ...
			symbolname1 = 'MYSYM_PARAM' + str(paramnum) + '_' +  hex(ADDR)
			
			# n번째 파라미터에 대한 스택픽싱을 설치한당.
			NEWDISASM.append('')
			NEWDISASM.append(' movl $' + symbolname1 +', MYSYM_EIP' 						+ ' ' + '#+++++')

			NEWDISASM.append('')
			NEWDISASM.append(' # ' + str(paramnum) + 'st stack fixing... : ' + LOC_ESP		+ ' ' + '#+++++')	
			NEWDISASM.append(' lea ' + LOC_ESP + ', %esi' 								  	+ ' ' + '#+++++') 
			NEWDISASM.append(' mov %esi, MYSYM_STACKLOC'									+ ' ' + '#+++++')
			
			NEWDISASM.append(' mov (%esi), %eax'											+ ' ' + '#+++++')
			NEWDISASM.append(' mov %eax, MYSYM_CRASHADDR' 									+ ' ' + '#+++++') # 0x0(esp) 를 MYSYM_CRASHADDR 에다가 옮긴다. 
			
			NEWDISASM.append( symbolname1 + ':'  			  								+ ' ' + '#+++++') # 크래시난다면 여기로 돌아와. 이 딱 중간이여야해. 
			NEWDISASM.append(' mov MYSYM_CRASHADDR, %eax' 									+ ' ' + '#+++++') 
			NEWDISASM.append(' mov (%eax), %ebx'											+ ' ' + '#+++++') # 크래시 유발...ㅋㅋㅋ

			NEWDISASM.append(' mov MYSYM_STACKLOC, %esi'									+ ' ' + '#+++++') # Fixing 된 주소를 0x0(esp) 에다가 넣는다 
			NEWDISASM.append(' mov %eax, (%esi)'											+ ' ' + '#+++++')

	NEWDISASM.append('')
	NEWDISASM.append(symbolname0 + ':'														+ ' ' + '#+++++') 
	NEWDISASM.append(' mov MYSYM_ESP, %esp'											      	+ ' ' + '#+++++') # esp 복구
	NEWDISASM.append(' call MYSYM_restoreregistercontext'								  	+ ' ' + '#+++++') # 레지스터컨텍스트 백업
	NEWDISASM.append(resdic_text[ADDR][1][j]												+ ' ' + '#+++++') # COMMENT: 왜 원본디스어셈블리인데도 #+++++ 추가해주냐면? --> symbolize_crashhandler_externalfunctioncall 에서 처리해주지 말라고. 

	resdic_text[ADDR][1]  = resdic_text[ADDR][1][:j] + NEWDISASM + resdic_text[ADDR][1][j+1:]


def heuristic_stack_fixing_multidemension(resdic_text, ADDR, nst_param_list, demension):

	origindexlist = pickpick_idx_of_orig_disasm(resdic_text[ADDR][1]) 
	j = 0
	NEWDISASM = []
	symbolname0 = 'MYSYM_LIBCALL_' + hex(ADDR)

	# [01] 가장급한건 컨텍스트 저장
	NEWDISASM.append('')
	NEWDISASM.append(' # heuristic_stack_fixing_multidemension' 							+ ' ' + '#+++++')
	NEWDISASM.append(' call MYSYM_backupregistercontext' 									+ ' ' + '#+++++') 
	NEWDISASM.append(' mov %esp, MYSYM_ESP'													+ ' ' + '#+++++') 
	NEWDISASM.append(' movl $0x0, MYSYM_LIBFLAG'											+ ' ' + '#+++++')

	# [02] 플래그같은거 설정해줌 
	NEWDISASM.append(' movl $' + symbolname0 + ', MYSYM_MYEXITADDR' 							+ ' ' + '#+++++') 
	for paramnum in nst_param_list:
		if paramnum > 1000: # 입력 파라미터가 몇개인지 모른다. n번째부터 n+???개의 파라미터를 심볼화해줘야 한다는 뜻. 
			paramnum = paramnum/1000
			LOC_ESP   = '{}(%esp)'.format(hex(4*(paramnum - 1))) 
			symbolname1 = 'MYSYM_FORLOOP_' + hex(ADDR) 
			symbolname2 = 'MYSYM_PARAMINFI_' + hex(ADDR)  
			symbolname3 = 'MYSYM_DEMENSIONFIX_' + hex(ADDR)
			# URGENT: 이거 아래else참고해서 멀티디멘션 반영한 코드로 바꾸기
			# n~ 번째 파라미터에 대한 스택픽싱을 설치한당.
			NEWDISASM.append('')
			NEWDISASM.append(' # ' + ' ∞st stack fixing... : ' + LOC_ESP	  			    + ' ' + '#+++++')
			NEWDISASM.append(' lea ' + LOC_ESP + ', %esi'									+ ' ' + '#+++++') # 현재스택의위치 저장

			NEWDISASM.append(' mov %esi, MYSYM_STACKLOC'									+ ' ' + '#+++++')
			NEWDISASM.append(symbolname1 + ':'												+ ' ' + '#+++++')
			NEWDISASM.append(' movl $' + symbolname2 +', MYSYM_EIP' 						+ ' ' + '#+++++') # 크래시핸들러가 리턴할 주소는 여기다. 만약에 크래시핸들러가 EXIT갈때까지갔다면, MYSYM_MYEXIT 에서는 바로 라이브러리콜하는곳으로 간당.
			NEWDISASM.append(' mov MYSYM_STACKLOC, %esi'									+ ' ' + '#+++++') # esi (%esp 대체품) 에서부터 쫄쫄 올라가면서 스택픽싱한당.
			NEWDISASM.append(' mov (%esi), %eax' 											+ ' ' + '#+++++')

			NEWDISASM.append(' mov %eax, MYSYM_CRASHADDR' 									+ ' ' + '#+++++') # 1
			NEWDISASM.append( symbolname2 + ':'									 			+ ' ' + '#+++++') # 2 컴백은 여기로.
			NEWDISASM.append(' mov MYSYM_CRASHADDR, %eax' 									+ ' ' + '#+++++') # 3 값읽기 : 스택 -> %eax 

			NEWDISASM.append(' mov (%eax), %ebx'											+ ' ' + '#+++++') # 크래시유발 (%eax 의 유효성검증)
			NEWDISASM.append(' mov MYSYM_STACKLOC, %esi'									+ ' ' + '#+++++')
			NEWDISASM.append(' mov %eax, (%esi)' 											+ ' ' + '#+++++')
			NEWDISASM.append(' add $0x4, MYSYM_STACKLOC'									+ ' ' + '#+++++')

			NEWDISASM.append(' jmp ' + symbolname1 											+ ' ' + '#+++++')

		else:
			LOC_ESP  = '{}(%esp)'.format(hex(4*(paramnum - 1))) # 첫번째 파라미터라면 esp+0, 두번째 파라미터라면 esp+4, ...
			symbolname1 = 'MYSYM_PARAM' + str(paramnum) + '_' +  hex(ADDR)
			symbolname3 = 'MYSYM_DEMENSIONFIX_' + hex(ADDR)

			# n번째 파라미터에 대한 스택픽싱을 설치한당.
			NEWDISASM.append('')
			

			NEWDISASM.append('')
			NEWDISASM.append(' # ' + str(paramnum) + 'st stack fixing... : ' + LOC_ESP		+ ' ' + '#+++++')	
			NEWDISASM.append(' lea ' + LOC_ESP + ', %esi' 								  	+ ' ' + '#+++++') 
			
			NEWDISASM.append(' movl $' + symbolname1 +', MYSYM_EIP' 						+ ' ' + '#+++++')
			NEWDISASM.append(' mov %esi, MYSYM_STACKLOC'									+ ' ' + '#+++++')
			NEWDISASM.append(' mov (%esi), %eax'											+ ' ' + '#+++++')
			NEWDISASM.append(' mov %eax, MYSYM_CRASHADDR' 									+ ' ' + '#+++++') # 0x0(esp) 를 MYSYM_CRASHADDR 에다가 옮긴다. 
			NEWDISASM.append( symbolname1 + ':'  			  								+ ' ' + '#+++++') # 크래시난다면 여기로 돌아와. 이 딱 중간이여야해. 
			NEWDISASM.append(' mov MYSYM_CRASHADDR, %eax' 									+ ' ' + '#+++++') 
			NEWDISASM.append(' mov (%eax), %ebx'											+ ' ' + '#+++++') # 크래시유발
			NEWDISASM.append(' mov MYSYM_STACKLOC, %esi'									+ ' ' + '#+++++') # Fixing 된 주소를 0x0(esp) 에다가 넣는다 
			NEWDISASM.append(' mov %eax, (%esi)'											+ ' ' + '#+++++')

			# 디멘션픽싱 (esi -> eax -> ebx -> ecx) 이 순으로 읽어왔음. 
			for d in xrange(demension - 1):
				NEWDISASM.append(' movl $' + symbolname3 + str(d) +', MYSYM_EIP'		+ ' ' + '#+++++')
				NEWDISASM.append(' mov MYSYM_CRASHADDR, %eax'							+ ' ' + '#+++++')
				NEWDISASM.append(' mov %eax, MYSYM_STACKLOC'							+ ' ' + '#+++++') # MYSYM_STACKLOC은 문제가되는값이 들어가있는 주소를 의미
				NEWDISASM.append(' mov (%eax), %ebx'									+ ' ' + '#+++++') # 한번 더 차원을 감소시킴
				NEWDISASM.append(' mov %ebx, MYSYM_CRASHADDR'							+ ' ' + '#+++++')
				NEWDISASM.append( symbolname3 + str(d) + ':'							+ ' ' + '#+++++')
				NEWDISASM.append(' mov MYSYM_CRASHADDR, %ebx'							+ ' ' + '#+++++')
				NEWDISASM.append(' mov (%ebx), %ecx'									+ ' ' + '#+++++')
				NEWDISASM.append(' mov MYSYM_STACKLOC, %esi'							+ ' ' + '#+++++')
				NEWDISASM.append(' mov %ebx, (%esi)'									+ ' ' + '#+++++')

	NEWDISASM.append('')
	NEWDISASM.append(symbolname0 + ':'														+ ' ' + '#+++++') 
	NEWDISASM.append(' mov MYSYM_ESP, %esp'											      	+ ' ' + '#+++++') # esp 복구
	NEWDISASM.append(' call MYSYM_restoreregistercontext'								  	+ ' ' + '#+++++') # 레지스터컨텍스트 백업
	NEWDISASM.append(resdic_text[ADDR][1][j]												+ ' ' + '#+++++') # COMMENT: 왜 원본디스어셈블리인데도 #+++++ 추가해주냐면? --> symbolize_crashhandler_externalfunctioncall 에서 처리해주지 말라고. 

	resdic_text[ADDR][1]  = resdic_text[ADDR][1][:j] + NEWDISASM + resdic_text[ADDR][1][j+1:]


# destinations = VSA_and_extract_addr(DISASM) 
def symbolize_crashhandler_externalfunctioncall_heuristically(resdic):
	symbolcount = 0	
	symbolize_count = 0
	for sectionName in CodeSections_WRITE:
		if sectionName in resdic.keys():
			for ADDR in resdic[sectionName].keys():
				
				orig_i_list = pickpick_idx_of_orig_disasm(resdic[sectionName][ADDR][1])
				for orig_i in orig_i_list:
					DISASM = resdic[sectionName][ADDR][1][orig_i]
					if DISASM.startswith('call') or DISASM.startswith(' call'):
						funcname = DISASM.strip().split()[1]
						if funcname in symbolize_heuristic_list_call.keys(): # 이 함수에 hit 하면은 , 이함수에 push로 전달되는 n번째 파라미터를 심볼화한다
							nst_param_list = symbolize_heuristic_list_call[funcname]
							heuristic_stack_fixing(resdic[sectionName],ADDR, nst_param_list)
						
						elif funcname in symbolize_heuristic_list_call_multidemension.keys():
							nst_param_list = symbolize_heuristic_list_call_multidemension[funcname]
							heuristic_stack_fixing_multidemension(resdic[sectionName],ADDR, nst_param_list, 2)

					elif DISASM.startswith('j') or DISASM.startswith(' j'):
						funcname = DISASM.strip().split()[1]
						if funcname in symbolize_heuristic_list_jmp.keys(): # 이 함수에 hit 하면은 , 이함수에 push로 전달되는 n번째 파라미터를 심볼화한다
							nst_param_list = symbolize_heuristic_list_jmp[funcname]
							heuristic_stack_fixing(resdic[sectionName],ADDR, nst_param_list)
						
						elif funcname in symbolize_heuristic_list_jmp_multidemension.keys():
							nst_param_list = symbolize_heuristic_list_jmp_multidemension[funcname]
							heuristic_stack_fixing_multidemension(resdic[sectionName],ADDR, nst_param_list, 2)

	

