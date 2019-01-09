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
from vsa import *
from global_variables import *


def dynamic_symbol_labeling(resdic, addr2name):
	for SectionName in resdic.keys():
		for addr in resdic[SectionName].keys():
			if addr in addr2name.keys():
				symbolname = addr2name[addr]
				if resdic[SectionName][addr][0] == '':# 심볼이 없다면, 심볼이름을 붙여준다. 심볼이 이미 있다면, 이전에 설정된 심볼을 우선적으로 선택하므로 심볼라이즈 ㄴㄴ. 
					resdic[SectionName][addr][0] = symbolname + ':'


# 가끔 이름없는 plt섹션이 있음. ex) __gmon_start__@plt 를 부르면, got로 점프하는데, 이 got는 라벨링이 안되있음  
# 그러므로 라벨링되지 않은 ['.plt.got','.plt'] 섹션의 주소는 모두 XXX를 붙여준다. 
# 그곳으로 점프하면 곧바로 ret하도록 보험처리를 해두는것임.
def pltsection_sanitize(resdic):
	pltsections = ['.plt.got','.plt'] 
	for SectionName in resdic.keys():
		if SectionName in pltsections:
			for addr in resdic[SectionName].keys():
				if resdic[SectionName][addr][0] == '':
					# resdic[SectionName][addr][0] = 'XXX:'
					'nono...'


# TODO: 이함수는 레거시적인것. 이제 안씀. 없애자. 
def global_symbolize_000section(dics_of_000, symtab_000):
	for i in range(0, len(symtab_000.keys())):
		if symtab_000.keys()[i] in dics_of_000.keys(): # bss에 키가없는데 없는키를 가져다가 심볼라이즈할라니깐 오류남. objdump -T 에서 보면 bss 영역을 벗어난 키가있음 -> 왜있는지 모르겠지만 bss의 __bss_start와 data섹션의 edata가 같은메모리주소를 가짐. 예외처리 ㄱㄱ
			#  _init, _fini 는 crti.o 에 이미 정의되어있다고하면서 링커에러남. 어차피  원래있던 _init은 안쓸거기도하고. 심볼이름이 그닥중요하진않으니까 심볼이름바꿔서 심볼라이즈 ㄱㄱ
			if symtab_000.values()[i] == '_init' or symtab_000.values()[i] == '_fini':
				dics_of_000[symtab_000.keys()[i]][0] = 'MY_' + symtab_000.values()[i]+":"
			else:
				dics_of_000[symtab_000.keys()[i]][0] = symtab_000.values()[i]+":"
	return dics_of_000


def post_getpcthunk_handling(resdic):
	for SectionName in resdic.keys():
		if SectionName in CodeSections_WRITE: # 코드섹션이라면
			addrlist = sorted(resdic[SectionName]) 
			for i in xrange(len(addrlist) - 1):
				orig_i_list = pickpick_idx_of_orig_disasm(resdic[SectionName][addrlist[i]][1])
				orig_j_list = pickpick_idx_of_orig_disasm(resdic[SectionName][addrlist[i + 1]][1])
				for orig_i in orig_i_list:
					for orig_j in orig_j_list:
						if '__x86.get_pc_thunk.' in resdic[SectionName][addrlist[i]][1][orig_i]:
							if 'call' in resdic[SectionName][addrlist[i]][1][orig_i] or 'jmp' in resdic[SectionName][addrlist[i]][1][orig_i]:  # getpcthunk_to_returnoriginalADDR 에 의해 push ???; ***jmp*** get_pc_thunk 로 바뀐경우도 핸들링
								if 'add' in resdic[SectionName][addrlist[i+1]][1][orig_j]:
									DISASM = resdic[SectionName][addrlist[i+1]][1][orig_j]
									if '$' and ',' in DISASM: #add $MYSYM_745, %ebx
										TRASH = DISASM[DISASM.index('$')+1:DISASM.index(',')]
										DISASM = DISASM.replace(TRASH, '_GLOBAL_OFFSET_TABLE_')
										resdic[SectionName][addrlist[i+1]][1][orig_j] = DISASM
							


def not_global_symbolize_ExternalLinkedSymbol(resdic):
	for SectionName in resdic.keys():
		for addr in resdic[SectionName].keys():
			if resdic[SectionName][addr][0] != '': # 심볼이 붙어있는데
				if resdic[SectionName][addr][0].startswith(SYMPREFIX[0] + 'MYSYM_') == True:
					"This is my symbol. :) PASS."
				else:
					symbolname = resdic[SectionName][addr][0][:-1]
					if '@' in symbolname:
						symbolname = symbolname[:symbolname.index('@')] # stderr@GOT(%ebx) 의 @뒤에 떼기
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
	# p_rint "PIE_symbolize_getpcthunk"

	pcthunk_reglist = [] # 필요할지도 모르니까, getpcthunk의 결과가 들어가는 레지스터들의 리스트들도 따로 저장해둠.ㅋ
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



# 우선은 헥스값을 발라내고, 만약 딕셔너리에 그 헥스값이 있다면 심볼화
# input : resdic
def symbolize_textsection(resdic):
	# START!
	symbolcount = 0	
	for section_from in CodeSections_WRITE:
		for section_to in AllSections_WRITE:
			if section_from in resdic.keys() and section_to in resdic.keys():
				print '     {} -----> {}'.format(section_from, section_to)
				for ADDR in resdic[section_from].keys(): 
					orig_i_list = pickpick_idx_of_orig_disasm(resdic[section_from][ADDR][1])
					for orig_i in orig_i_list:
						destinations = extract_hex_addr(resdic[section_from][ADDR][1][orig_i])
						for DESTINATION in destinations: 
							if VSA_is_memoryAddr_ornot(resdic[section_from][ADDR][1][orig_i]) is True: # 심볼라이즈를 하고싶은 주소 DESTINATION 가 우리의 VSA결과 메모리주소라고 판단되었다면
								if DESTINATION in resdic[section_to].keys(): 
									# 심볼이름셋팅
									if resdic[section_to][DESTINATION][0] != "": # if symbol already exist
										simbolname = resdic[section_to][DESTINATION][0][:-1] # MYSYM1: --> MYSYM1
									else: # else, create my symbol name 
										simbolname = SYMPREFIX[0] + "MYSYM_" + str(symbolcount)
										symbolcount = symbolcount + 1
										resdic[section_to][DESTINATION][0] = simbolname + ":"
									
									resdic[section_from][ADDR][1][orig_i] = resdic[section_from][ADDR][1][orig_i].replace(hex(DESTINATION),simbolname)     # 만약에 0x8048540 이렇게생겼을경우 0x8048540 --> MYSYM_1 치환
									resdic[section_from][ADDR][1][orig_i] = resdic[section_from][ADDR][1][orig_i].replace(hex(DESTINATION)[2:],simbolname) # 그게아니라 12 이렇게생겼을경우 12 --> MYSYM_1 치환 (그럴리는없겠지만?말이지.)

	return resdic



def symbolize_datasection(resdic): # datasection --> datasection 을 symbolize. 
	# 1. datasection 이 datasection 을 포인팅하는 값이 있는지, 1바이트씩 슬라이딩 윈도우로 조사
	# 2. 있으면 그 .byte 01 .byte 04 .byte 20 .byte 80  자리에 .byte 심볼이름 을 씀. 
	#    4byte align 맞춰가면서 symbolize 하기
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
								else: i = i + 1 # .byte blabla .byte blabla .byte blabla .long blabla  일 경우, .long blabla까지 쓰루하기
							else: i = i + 1 
						else: i = i + 1 
					else:
						"do nothing"
					i = i + 1 
	return resdic





# je 2a0c 처럼 이상한곳으로 점프하는 (심볼리제이션이 안된 곳) 인스트럭션이 있다면 je XXX 로 바꾼다. 어셈블을 잘되게 하기 위함이지.. TODO: Crash based 이프이프핸들러기능이 도입되면 이거 없애야함.
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
				
				if ishex(elements[2]): 			   #          jmp 12f2 <--here
					for b in branch_inst:
						if b in elements[1]: yes_it_is_branch_instruction = 1
					
					if yes_it_is_branch_instruction == 1: # here --> jmp 12f2
						elements[2] = 'XXX'
						line = '' # 다시 재조립
						for i in xrange(len(elements)):
							line = line + elements[i] + ' '
						dics_of_text[ADDR][1][orig_i] = line 




# lfunc_remove_callweirdaddress 보다 더 진보된 방법이다..
# je 2a0c 처럼 이상한곳으로 점프하는 (심볼리제이션이 안된 곳) 인스트럭션이 있다면, 데이터로 때려박는다. ㅋㅋ 어셈블이 잘되게 하기 때문이지... TODO: Crash based 이프이프핸들러기능이 도입되면 이거 없애야함.
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

