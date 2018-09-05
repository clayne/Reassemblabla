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

def global_symbolize_bss(dics_of_bss, symtab_bss):
	for i in range(0, len(symtab_bss.keys())):
		if symtab_bss.keys()[i] in dics_of_bss.keys(): # bss에 키가없는데 없는키를 가져다가 심볼라이즈할라니깐 오류남. objdump -T 에서 보면 bss영역을 벗어난 키가있음 -> 왜있는지 모르겠지만 bss의 __bss_start와 data섹션의 edata가 같은메모리주소를 가짐. 예외처리 ㄱㄱ
			dics_of_bss[symtab_bss.keys()[i]][0] = symtab_bss.values()[i]+":"
	return dics_of_bss

def not_global_symbolize_bss(dics_of_bss, symtab_bss):
	for i in range(0, len(symtab_bss.keys())):
		if symtab_bss.keys()[i] in dics_of_bss.keys():
			dics_of_bss[symtab_bss.keys()[i]][0] = "DUMMY_" + symtab_bss.values()[i]+":"
	return dics_of_bss	

def PIE_symbolize_getpcthunk(resdic):
	print "PIE_symbolize_getpcthunk"
	code_sections = CodeSections_WRITE
	count = 0
	for Sname in code_sections:
		if Sname in resdic.keys():
			SectionDic = resdic[Sname]
			SORTKEY = SectionDic.keys()
			SORTKEY.sort()
			for i in xrange(len(SORTKEY)):
				DISASM_1 = SectionDic[SORTKEY[i]][1][1:]
				if ' ' in DISASM_1: # leave, ret 같은건 취급안함
					OPCODE_1 = DISASM_1[:DISASM_1.index(' ')]
					OPRAND_1 = DISASM_1[DISASM_1.index(' ')+1:]
					if OPCODE_1.startswith('mov'): 
						if OPRAND_1.startswith('(%esp), %e') or OPRAND_1.startswith('0(%esp), %e'):
							DISASM_2 = SectionDic[SORTKEY[i+1]][1][1:]
							if '0(%esp), %e' in OPRAND_1:
								AX_BX_CX = OPRAND_1[len('0(%esp), %e'):]
							elif '(%esp), %e' in OPRAND_1:
								AX_BX_CX = OPRAND_1[len('(%esp), %e'):]
							if DISASM_2.startswith('ret'):
								SectionDic[SORTKEY[i]][0] = '__x86.get_pc_thunk.' + str(count) + '.' + AX_BX_CX + ':' # symbolization
								count += 1
	


# 1. 우선은 헥스값을 발라내고
# 2. 만약 딕셔너리에 그 헥스값이 있다면 심볼화
# input : resdic
def symbolize_textsection(resdic):

	_from = CodeSections_WRITE
	_to = AllSections_WRITE
	
	symbolcount = 0
	
	for section_from in _from:
		if section_from not in resdic.keys(): # COMMENT: excepation handling 추가 @0903
			continue
		for ADDR in resdic[section_from].keys() : # resdic[section_from][처음주소] ~ resdic[section_from][끝주소]
			addrlist = extract_hex_addr(resdic[section_from][ADDR][1])
			if len(addrlist) >= 1:
				for ADDR_TO_SYM in addrlist: 
					for section_to in _to: # _from --> _to 
						if section_to not in resdic.keys(): # COMMENT: excepation handling 추가 @0903 
							continue
						if ADDR_TO_SYM in resdic[section_to].keys(): 
							# symbol name setting
							if resdic[section_to][ADDR_TO_SYM][0] != "": # if symbol already exist
								simbolname = resdic[section_to][ADDR_TO_SYM][0][:-1] # MYSYM1: --> MYSYM1
								resdic[section_to][ADDR_TO_SYM]
							else: # else, create my symbol name 
								simbolname = "MYSYM_"+str(symbolcount)
								symbolcount = symbolcount+1
								resdic[section_to][ADDR_TO_SYM][0] = simbolname + ":"
							
							resdic[section_from][ADDR][1] = resdic[section_from][ADDR][1].replace(hex(ADDR_TO_SYM),simbolname)# 만약에 0x8048540 이렇게생겼을경우 0x8048540 --> MYSYM_1 치환
							resdic[section_from][ADDR][1] = resdic[section_from][ADDR][1].replace(hex(ADDR_TO_SYM)[2:],simbolname) # 그게아니라 8048540 이렇게생겼을경우 0x8048540 --> MYSYM_1 치환
							p = re.compile('\<.*?\>') # 'call MYSYM_14 <fast_memcpy>' -> 'call MYSYM_14'. 심볼라이즈후에는 뒤에오는거제거해도된다. 심볼라이즈를안했을시에는 제거하면안된다. 나중에그걸기반으로 lfunc_remove_callweirdfunc 때릴꺼기때매
							resdic[section_from][ADDR][1] =  re.sub(p, "", resdic[section_from][ADDR][1])
	
	
	return resdic

# TODO: Data 를 심볼라이즈할때 4바이트가 1개로 합쳐진다면, resdic['.text'][3] 도 4바이트로 합쳐져야하는데 그부분 핸들링
def symbolize_datasection(resdic): # datasection --> datasection 을 symbolize. 
	# 1. datasection 이 datasection 을 포인팅하는 값이 있는지, 1바이트씩 슬라이딩 윈도우로 조사
	# 2. 있으면 그 .byte 01 .byte 04 .byte 20 .byte 80  자리에 .byte 심볼이름 을 씀. 
	#    4byte align 맞춰가면서 symbolize 하기
	# rodata -> data, rodata, bss
	_from = DataSections_WRITE
	_from.remove('.bss')     # bss에는 아무것도 안들어있자나..
	_to = AllSections_WRITE
	symcnt = 0
	for section_from in _from:
		for section_to in _to:
			if section_from not in resdic.keys() or section_to not in resdic.keys(): # COMMENT: 예외처리 추가함 
				continue
			print "Symbolizing [{}] to [{}]".format(section_from,section_to)
			i = 0
			sorted_keylist = sorted(resdic[section_from]) # key list sort
			while i <= len(sorted_keylist) - 4: # len-4, len-3, len-2, len-1
				key = sorted_keylist[i]
				if resdic[section_from][sorted_keylist[i+0]][1].startswith(' .byte'):
					if resdic[section_from][sorted_keylist[i+1]][1].startswith(' .byte'):
						if resdic[section_from][sorted_keylist[i+2]][1].startswith(' .byte'):
							if resdic[section_from][sorted_keylist[i+3]][1].startswith(' .byte'):
								candidate  = ""
								candidate += resdic[section_from][sorted_keylist[i+3]][1]
								candidate += resdic[section_from][sorted_keylist[i+2]][1]
								candidate += resdic[section_from][sorted_keylist[i+1]][1]
								candidate += resdic[section_from][sorted_keylist[i+0]][1]
								candidate = candidate.replace(' .byte 0x','')
								candidate = "0x"+candidate
								if int(candidate,16) in resdic[section_to].keys(): # to 의 대상이되는 섹션
									symbolname = resdic[section_to][int(candidate,16)][0]
									if symbolname == '': 
										symbolname = "MYSYM_DATA_"+str(symcnt)+":"
									resdic[section_from].pop(sorted_keylist[i+3])
									resdic[section_from].pop(sorted_keylist[i+2])
									resdic[section_from].pop(sorted_keylist[i+1])
									resdic[section_from][sorted_keylist[i+0]][1]= " .long " + symbolname[:-1] # ':' 떼기위해-1, not delete, just modify data format(.byte->.long)
									resdic[section_from][sorted_keylist[i+0]][2] = '#=> ' + 'ADDR:' + str(hex(sorted_keylist[i+0])) + ' BYTE:' + candidate[2:] 
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

# je 2a0c 처럼 이상한곳으로 점프하는 (심볼리제이션이 안된 곳) 인스트럭션이 있다면 je XXX 로 바꾼다. 
# 어셈블을 잘되게 하기 위함이지.. 
def lfunc_remove_callweirdaddress(dics_of_text):
	branch_inst = ['jmp','je','jne','jg','jge','ja','jae','jl','jle','jb','jbe','jo','jno','jz','jnz','js','jns','call'] # ,'loop','loope','loopne' 는 loop XXX 라고해봤자 에러메시지 뿜어댐. 왠지 모르겠다. 그러니까 이거 세개는 제외시키자. lfunc_change_loop_call_jmp_and_hexvalue_instruction_to_data가 알아서 처리해줄거임
	
	for i in xrange(len(dics_of_text)):
		key = dics_of_text.keys()[i]
		line = dics_of_text[key][1]
		elements = line.split(' ')
		yes_it_is_branch_instruction = 0

		if len(elements) >= 3:
			if elements[2].startswith('0x'):
				elements[2] = elements[2][2:]
			
			if ishex(elements[2]): 			   #          jmp 12f2 <--here
				for b in branch_inst:
					if b in elements[1]:
						yes_it_is_branch_instruction = 1
				if yes_it_is_branch_instruction == 1: # here --> jmp 12f2
					elements[2] = 'XXX'
					# 다시 재조합
					line = ''
					for i in xrange(len(elements)):
						line = line + elements[i] + ' '
					#dics_of_text.update({key:[dics_of_text[key][0],line]})
					dics_of_text[key][1] = line

# lfunc_remove_callweirdaddress 보다 더 진보된 방법이다..
# je 2a0c 처럼 이상한곳으로 점프하는 (심볼리제이션이 안된 곳) 인스트럭션이 있다면, 데이터로 때려박는다. ㅋㅋ 어셈블이 잘되게 하기 때문이지... 
def lfunc_change_loop_call_jmp_and_hexvalue_instruction_to_data(dics_of_text):
	branch_inst = ['jmp','je','jne','jg','jge','ja','jae','jl','jle','jb','jbe','jo','jno','jz','jnz','js','jns','call','loop','loope','loopne']
	
	for i in xrange(len(dics_of_text)):
		key = dics_of_text.keys()[i]
		line = dics_of_text[key][1]
		elements = line.split(' ')
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
					print "***************************************"
					print dics_of_text[key][1]
					print dics_of_text[key][2]
					bytepattern = dics_of_text[key][2].split('BYTE:')[1]
					line_data = ' .byte '
					for j in xrange(len(bytepattern)/2):
						line_data += '0x' + bytepattern[j*2:j*2+2] + ', '
					line_data = line_data[:-2]
					dics_of_text[key][1] = line_data
					print dics_of_text[key][1]



def lfunc_remove_callweirdfunc(dics_of_text):
	'''
	call   2700 <main@@Base-0xcda0> --> 
	'''
	for i in range(0,len(dics_of_text)):
		key = dics_of_text.keys()[i]
		if "<" in dics_of_text.values()[i][1]:
			l = dics_of_text.values()[i][1]
			l_instname =l[:l[1:].index(' ')+1] # instruction name
			l_funcname  = "XXX" 
			dics_of_text.update({key:[dics_of_text.values()[i][0],l_instname+" "+l_funcname]})



