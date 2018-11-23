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
from global_variables import *
from etc import *

def get_alignmentbyte(addr, type):
	if type == 'data': # 데이터는 16 byte(SSE instruction),32 byte(AVX instruction), 64(AVX_512, intel의 특정 cpu line에서만 적용됨) 세 종류의 align
		'''
		if addr%64 == 0:
			return 64
		'''
		if addr%32 == 0:
			return 32
		elif addr%16 == 0:
			return 16
	elif type == 'text': # 코드는8, 16, 32 (Most processors fetch instructions in aligned 16-byte or 32-byte blocks. It can be advantageous to align critical loop entries and subroutine entries by 16 in order to minimize the number of 16-byte boundaries in the code. Alternatively, make sure that there is no 16- byte boundary in the first few instructions after a critical loop entry or subroutine entry)
		if addr%32 == 0:
		    return 32
		elif addr%16 == 0:
			return 16
		elif addr%8 == 0: # 8byte 가 cache line 최적화에 기여하는지는모르겠지만 align 8도많길래 넣어줌
			return 8
		elif addr%4 == 0:
			return 4
	return 0	

def align_text(dics_of_text):
	SORTED_ADDRESS = sorted(dics_of_text)
	for i in xrange(len(SORTED_ADDRESS) - 1):
		# set disasm_1 and next disasm_1
		orig_i_list = pickpick_idx_of_orig_disasm(dics_of_text[SORTED_ADDRESS[i]][1]) 
		if len(orig_i_list) > 0:
			for orig_i in orig_i_list:
				disasm_1 = dics_of_text[SORTED_ADDRESS[i]][1][orig_i]
		
				j = i+1
				orig_j_list = pickpick_idx_of_orig_disasm(dics_of_text[SORTED_ADDRESS[j]][1])
				for orig_j in orig_j_list:
					disasm_2 = dics_of_text[SORTED_ADDRESS[j]][1]
					
					if "eiz" in disasm_1:
						if "eiz" in disasm_2: 
							dics_of_text[SORTED_ADDRESS[i]][1][orig_i] = '' # eiz 포함라인(현재라인)을 없앰
							continue
						else: # 끝까지 갔다. 다음라인에 eiz없음 
							align = get_alignmentbyte(SORTED_ADDRESS[j],'text')
							if align == 32:
								p2align = ".p2align 5,,31"
							elif align == 16:
								p2align = ".p2align 4,,15" 
							elif align == 8:
								p2align = ".p2align 3,,7"
							elif align == 4:
								p2align = ".p2align 2,,3"
							else: # 다음라인이 align 이 안맞는다면, p2align을 추가해줄 필요가 없음
								p2align = ""
						dics_of_text[SORTED_ADDRESS[i]][1][orig_i] = p2align # 주의 : 이전라인의 뒤에 p2align을 추가해 줘야함. 왜냐하면, 현재라인에 추가하면 현재라인에 심볼이 있을경우 그 심볼로 접근했을때 align을 위한 바이트들도 몽땅 들어가서 접근이 되기 때문임.   
	return dics_of_text		
	
def align_data(dics_of_data): # 데이터섹션에서, 만약에 Symbol이 있는데이터라면 align 맞춰주기
	SORTED_ADDRESS = sorted(dics_of_data)
	cannot_add_align_at_first = 0
	for i in xrange(len(SORTED_ADDRESS)):

		if cannot_add_align_at_first == 0: # don't care about the start of data section
			cannot_add_align_at_first = 1 
			continue
		if dics_of_data[SORTED_ADDRESS[i]][0] != '': # symbol 을 가지고있다면
			align = get_alignmentbyte(SORTED_ADDRESS[i],'data')

			if align != 0:
				j = i-1 # 위의 데이터 (이전데이터) 다음에 .align 을 붙인다.
				orig_j_list = pickpick_idx_of_orig_disasm(dics_of_data[SORTED_ADDRESS[j]][1])
				for orig_j in orig_j_list: 
					dics_of_data[SORTED_ADDRESS[j]][1][orig_j] = dics_of_data[SORTED_ADDRESS[j]][1][orig_j] + "\n" + ".align " + str(align)
	return dics_of_data
