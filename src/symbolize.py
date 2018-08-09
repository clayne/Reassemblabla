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


def global_symbolize_bss(dics_of_bss, symtab):
	for i in range(0, len(symtab.keys())):
		if symtab.keys()[i] in dics_of_bss.keys(): # bss에 키가없는데 없는키를 가져다가 심볼라이즈할라니깐 오류남. objdump -T 에서 보면 bss영역을 벗어난 키가있음 -> 왜있는지 모르겠지만 bss의 __bss_start와 data섹션의 edata가 같은메모리주소를 가짐. 예외처리 ㄱㄱ
			dics_of_bss[symtab.keys()[i]] = [symtab.values()[i]+":", dics_of_bss[symtab.keys()[i]][1]]
	return dics_of_bss

def not_global_symbolize_bss(dics_of_bss, symtab):
	for i in range(0, len(symtab.keys())):
		if symtab.keys()[i] in dics_of_bss.keys():
			dics_of_bss[symtab.keys()[i]] = ["DUMMY_" + symtab.values()[i]+":", dics_of_bss[symtab.keys()[i]][1]]
	return dics_of_bss	





# 1. 우선은 헥스값을 발라내고
# 2. 만약 딕셔너리에 그 헥스값이 있다면 심볼화
# input : resdic
def lfunc_symbolize_textsection(resdic):
	_from = ['.text','.init']
	_to = ['.text','.data', '.bss', '.rodata','.init']
	
	symbolcount = 0
	
	for section_from in _from:
		for i in range (0,len(resdic[section_from])): # symbolize text --> ???
			addrlist = extract_hex_addr(resdic[section_from].values()[i][1])
			if len(addrlist) >= 1:
				for j in range(0,len(addrlist)): 
					for section_to in _to: # _from --> _to 
						if section_to in resdic.keys(): # section exist
							if addrlist[j] in resdic[section_to].keys(): 
								# symbol name setting
								if resdic[section_to][addrlist[j]][0] != "": # if symbol already exist
									simbolname = resdic[section_to][addrlist[j]][0][:-1] # MYSYM1: --> MYSYM1
									resdic[section_to][addrlist[j]]
								else: # else, create my symbol name 
									simbolname = "MYSYM_"+str(symbolcount)
									symbolcount = symbolcount+1
									resdic[section_to][addrlist[j]][0] = simbolname + ":"
									# print resdic[section_to][addrlist[j]]
								
								resdic[section_from].values()[i][1] = resdic[section_from].values()[i][1].replace(hex(addrlist[j]),simbolname)# 만약에 0x8048540 이렇게생겼을경우 0x8048540 --> MYSYM_1 치환
								resdic[section_from].values()[i][1] = resdic[section_from].values()[i][1].replace(hex(addrlist[j])[2:],simbolname) # 그게아니라 8048540 이렇게생겼을경우 0x8048540 --> MYSYM_1 치환
								p = re.compile('\<.*?\>') # 'call MYSYM_14 <fast_memcpy>' -> 'call MYSYM_14'. 심볼라이즈후에는 뒤에오는거제거해도된다. 심볼라이즈를안했을시에는 제거하면안된다. 나중에그걸기반으로 lfunc_remove_callweirdfunc 때릴꺼기때매
								resdic[section_from].values()[i][1] =  re.sub(p, "", resdic[section_from].values()[i][1])
	
	
	
	return resdic

def lfunc_symbolize_datasection(resdic): # datasection --> datasection 을 symbolize. 
	# 1. datasection 이 datasection 을 포인팅하는 값이 있는지, 1바이트씩 슬라이딩 윈도우로 조사
	# 2. 있으면 그 .byte 01 .byte 04 .byte 20 .byte 80  자리에 .byte 심볼이름 을 씀. 
	#    4byte align 맞춰가면서 symbolize 하기
	# rodata -> data, rodata, bss
	_from = ['.data', '.rodata']
	_to = ['.data','.rodata','.bss','.text']
	symcnt = 0
	for section_from in _from:
		for section_to in _to:
			print "Symbolizing {} section --> {} section...".format(section_from,section_to)
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
	branch_inst = ['jmp','je','jne','jg','jge','ja','jae','jl','jle','jb','jbe','jo','jno','jz','jnz','js','jns','call']
	
	for i in xrange(len(dics_of_text)):
		key = dics_of_text.keys()[i]
		line = dics_of_text[key][1]
		elements = line.split(' ')
	
		if len(elements) >= 3:
			if elements[2].startswith('0x'):
				elements[2] = elements[2][2:]
			
			if ishex(elements[2]): 			   #          jmp 12f2 <--here
				if elements[1] in branch_inst: # here --> jmp 12f2
					elements[2] = 'XXX'
					# 다시 재조합
					line = ''
					for i in xrange(len(elements)):
						line = line + elements[i] + ' '
					#dics_of_text.update({key:[dics_of_text[key][0],line]})
					dics_of_text[key][1] = line
		
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



