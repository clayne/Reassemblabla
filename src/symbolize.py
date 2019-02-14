#!/usr/bin/python
#-*- coding: utf-8 -*-
from etc import *
from vsa import *



def dynamic_symbol_labeling(resdic, addr2name):
	for SectionName in resdic.keys():
		for addr in resdic[SectionName].keys():
			if addr in addr2name.keys():
				symbolname = addr2name[addr]
				if resdic[SectionName][addr][0] == '': # 심볼이 없다면, 심볼이름을 붙여준다. 심볼이 이미 있다면, 이전에 설정된 심볼을 우선적으로 선택하므로 심볼라이즈 ㄴㄴ. 
					resdic[SectionName][addr][0] = symbolname + ':'

def not_global_symbolize_ExternalLinkedSymbol(resdic):
	for SectionName in resdic.keys():
		for addr in resdic[SectionName].keys():
			if resdic[SectionName][addr][0] != '': # 심볼이 붙어있는데
				if resdic[SectionName][addr][0].startswith(SYMPREFIX[0] + 'MYSYM_') == True:
					'This is my symbol. :) PASS.'
				else:
					symbolname = resdic[SectionName][addr][0][:-1]
					if '@' in symbolname:
						symbolname = symbolname[:symbolname.index('@')] # stderr@GOT(%ebx) 의 @뒤에 떼준다
						symbolname = SYMPREFIX[0] + 'MYSYM_SPOILED_' + SectionName[1:] + '_' + symbolname 
						resdic[SectionName][addr][0] = symbolname + ':'
					elif 'MYSYM' not in symbolname:
						flag_namedsymbol = 0
						for permitted_name in MyNamedSymbol:
							if symbolname.startswith(permitted_name): # __x86.get_pc_thunk.si, __x86.get_pc_thunk.di, ...
								flag_namedsymbol = 1
								'Good. You Servived.' 
						if flag_namedsymbol is 0: # You are not permitted symbol name. ex)printf
							symbolname = SYMPREFIX[0] + 'MYSYM_SPOILED_' + SectionName[1:] + '_' + symbolname
							resdic[SectionName][addr][0] = symbolname + ':'
	return resdic		

def getpcthunk_labeling(resdic):
	pcthunk_reglist = [] # 필요할지도 모르니까, getpcthunk의 결과가 들어가는 레지스터들의 리스트들도 따로 저장해둠.
	code_sections = CodeSections_WRITE
	count = 0
	for sectionName in code_sections:
		if sectionName in resdic.keys():
			SectionDict = resdic[sectionName]
			SORTKEY = SectionDict.keys()
			SORTKEY.sort()
			for i in xrange(len(SORTKEY) - 1):
				j = 0
				while j < len(SectionDict[SORTKEY[i]][1]):
					DISASM_1 = SectionDict[SORTKEY[i]][1][j][1:]
					k = 0
					while k < len(SectionDict[SORTKEY[i+1]][1]):
						DISASM_2 = SectionDict[SORTKEY[i+1]][1][k][1:]
						if ' ' in DISASM_1 and DISASM_2.startswith('ret'): # leave, ret 같은건 취급안함
							OPCODE_1 = DISASM_1[:DISASM_1.index(' ')]
							OPRAND_1 = DISASM_1[DISASM_1.index(' ')+1:]
							if OPCODE_1.startswith('mov'): 
								if OPRAND_1.startswith('(%esp), %e') or OPRAND_1.startswith('0(%esp), %e'): # 첫번째 관문 통과 
									if '0(%esp), %e' in OPRAND_1:
										REGX = OPRAND_1[len('0(%esp), %e'):]
									elif '(%esp), %e' in OPRAND_1:
										REGX = OPRAND_1[len('(%esp), %e'):]
									SectionDict[SORTKEY[i]][0] = '__x86.get_pc_thunk.' + str(count) + '.' + REGX + ':' # symbolization
									count += 1
									pcthunk_reglist.append('e' + REGX)
						k += 1
					j += 1
	return 	list(set(pcthunk_reglist)) # 중복 제거

def symbolize_textsection(resdic):
	symbolcount = 0	
	for section_from in CodeSections_WRITE:
		for section_to in AllSections_WRITE:
			if section_from in resdic.keys() and section_to in resdic.keys():
				print '     {} -----> {}'.format(section_from, section_to)
				for ADDR in resdic[section_from].keys(): 
					orig_i_list = pickpick_idx_of_orig_disasm(resdic[section_from][ADDR][1])
					for orig_i in orig_i_list:
						DISASM = resdic[section_from][ADDR][1][orig_i]
						destinations = VSA_and_extract_addr(DISASM) 
						for DEST in destinations: 
							if DEST in resdic[section_to].keys(): 
								# 심볼이름셋팅
								if resdic[section_to][DEST][0] != "": # if symbol already exist
									simbolname = resdic[section_to][DEST][0][:-1] # MYSYM1: --> MYSYM1
								else: # else, create my symbol name 
									simbolname = SYMPREFIX[0] + "MYSYM_" + str(symbolcount)
									symbolcount = symbolcount + 1
									resdic[section_to][DEST][0] = simbolname + ":"
								resdic[section_from][ADDR][1][orig_i] = resdic[section_from][ADDR][1][orig_i].replace(hex(DEST),simbolname)     # 만약에 0x8048540 이렇게생겼을경우 0x8048540 --> MYSYM_1 치환
								resdic[section_from][ADDR][1][orig_i] = resdic[section_from][ADDR][1][orig_i].replace(hex(DEST)[2:],simbolname) # 그게아니라 12 이렇게생겼을경우 12 --> MYSYM_1 치환 (그럴리는없겠지만..)
	return resdic

def symbolize_datasection(resdic): # datasection --> datasection 을 symbolize. 
	'''
	먼저, datasection 이 datasection 을 포인팅하는 값이 있는지 1바이트씩 슬라이딩 윈도우로 조사한다.
	있다면, 그 .byte 01 .byte 04 .byte 20 .byte 80  자리에 .byte 심볼이름 을 씀. 
    4byte align 맞춰가면서 symbolize 하기
    '''
	_from = DataSections_WRITE     
	_to   = AllSections_WRITE
	symcnt = 0
	for section_from in _from:
		if _from == '.bss':# bss에는 아무것도 안들어있자나..
			continue
		for section_to in _to:
			if section_from in resdic.keys() and section_to in resdic.keys(): 
				i = 0
				sorted_keylist = sorted(resdic[section_from]) # key list sort
				while i <= len(sorted_keylist) - 4: # len-4, len-3, len-2, len-1
					key = sorted_keylist[i]
					if resdic[section_from][sorted_keylist[i+0]][1][0].startswith(' .byte'):
						if resdic[section_from][sorted_keylist[i+1]][1][0].startswith(' .byte'):
							if resdic[section_from][sorted_keylist[i+2]][1][0].startswith(' .byte'):
								if resdic[section_from][sorted_keylist[i+3]][1][0].startswith(' .byte'):
									candidate  = ""
									candidate += resdic[section_from][sorted_keylist[i+3]][1][0]
									candidate += resdic[section_from][sorted_keylist[i+2]][1][0]
									candidate += resdic[section_from][sorted_keylist[i+1]][1][0]
									candidate += resdic[section_from][sorted_keylist[i+0]][1][0]
									candidate = candidate.replace(' .byte 0x','')
									candidate = "0x"+candidate
									if int(candidate,16) in resdic[section_to].keys(): # to 의 대상이되는 섹션
										symbolname = resdic[section_to][int(candidate,16)][0]
										if symbolname == '': 
											symbolname = SYMPREFIX[0] + "MYSYM_DATA_"+str(symcnt)+":"
										resdic[section_from].pop(sorted_keylist[i+3])
										resdic[section_from].pop(sorted_keylist[i+2])
										resdic[section_from].pop(sorted_keylist[i+1])
										resdic[section_from][    sorted_keylist[i+0]][1][0] = " .long " + symbolname[:-1] # ':' 떼기위해-1, not delete, just modify data format(.byte->.long)
										resdic[section_from][    sorted_keylist[i+0]][2] = '                              #=> ' + 'ADDR:' + str(hex(sorted_keylist[i+0])) + ' BYTE:' + candidate[2:] 
										resdic[section_to][int(candidate,16)][0]= symbolname # symbolize that loc
										i = i + 4 # because entry of dict poped
										symcnt = symcnt + 1
										continue
								else: i = i + 1 # .byte blabla .byte blabla .byte blabla .long blabla  일 경우, .long blabla 까지 쓰루하기
							else: i = i + 1 
						else: i = i + 1 
					else:
						"do nothing"
					i = i + 1 
	return resdic


# je 2a0c 처럼 이상한곳으로 점프하는 (심볼리제이션이 안된 곳) 인스트럭션이 있다면 je XXX 로 바꾼다. (오직 컴파일 에러를 막기 위한 땜빵기능임...) TODO: Crash based lazy symbolization 이 도입되면 이거 없애야 함
def lfunc_change_callweirdaddress_2_callXXX(dics_of_text): 
	branch_inst = ['jmp','je','jne','jg','jge','ja','jae','jl','jle','jb','jbe','jo','jno','jz','jnz','js','jns','call'] # ,'loop','loope','loopne' 는 loop XXX 라고해봤자 에러메시지 뿜어댐. 왠지 모르겠다. 그러니까 이거 세개는 제외시키자. lfunc_change_loop_call_jmp_and_hexvalue_instruction_to_data가 알아서 처리해줄거임
	
	for i in xrange(len(dics_of_text)):
		ADDR = dics_of_text.keys()[i]
		orig_i_list = pickpick_idx_of_orig_disasm(dics_of_text[ADDR][1])
		for orig_i in orig_i_list:
			elements = dics_of_text[ADDR][1][orig_i].split(' ')
			yes_it_is_branch_instruction = 0
			if len(elements) >= 3:
				if elements[2].startswith('0x'):
					elements[2] = elements[2][2:]
				if ishex(elements[2]): 			   			# jmp 12f2 <--here
					for b in branch_inst:
						if b in elements[1]: yes_it_is_branch_instruction = 1
					if yes_it_is_branch_instruction == 1: 	# here --> jmp 12f2
						elements[2] = 'XXX'
						line = '' # 다시 재조립
						for i in xrange(len(elements)):
							line = line + elements[i] + ' '
						dics_of_text[ADDR][1][orig_i] = line 



# lfunc_remove_callweirdaddress 보다 더 진보된 방법이다..
# je 2a0c 처럼 이상한곳으로 점프하는 (심볼리제이션이 안된 곳) 인스트럭션이 있다면, 데이터로 때려박음. (오직 컴파일 에러를 막기 위한 땜빵기능임...) TODO: Crash based lazy symbolization 이 도입되면 이거 없애야 함
def lfunc_change_callweirdaddress_2_data(dics_of_text):  
	branch_inst = ['jmp','je','jne','jg','jge','ja','jae','jl','jle','jb','jbe','jo','jno','jz','jnz','js','jns','call','loop','loope','loopne']
	
	for i in xrange(len(dics_of_text)):
		ADDR = dics_of_text.keys()[i]
		orig_i_list = pickpick_idx_of_orig_disasm(dics_of_text[ADDR][1])
		for orig_i in orig_i_list:
			elements = dics_of_text[ADDR][1][orig_i].split(' ')
			yes_it_is_branch_instruction = 0
			if len(elements) >= 3:
				if '0x' in elements[2]:
					elements[2] = elements[2].replace('0x','')
					elements[2] = elements[2].replace('*', '')
					elements[2] = elements[2].replace('$', '') 
				if ishex(elements[2]): 			          # jmp 12f2 <--here
					for INSTR in branch_inst:
						if INSTR in elements[1]:
							yes_it_is_branch_instruction = 1
					if yes_it_is_branch_instruction == 1: # here --> jmp 12f2
						bytepattern = dics_of_text[ADDR][2].split('BYTE:')[1]
						line_data = ' .byte '
						for j in xrange(len(bytepattern)/2):
							line_data += '0x' + bytepattern[j*2:j*2+2] + ', '
						line_data = line_data[:-2]
						dics_of_text[ADDR][1][orig_i] = line_data

