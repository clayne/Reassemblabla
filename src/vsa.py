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

def VSA_and_extract_addr(DISASM):
	'''
	extract hex value that correspond to memory reference
	- ex)
		mov    $0x20804,%al              --> []
		je     804841b <frame_dummy+0xb> --> [804841b] 
		push   $0x8048540                --> []
	'''
	
	addrlist = []
	origDISASM = DISASM

	if '#' in DISASM:		
		DISASM = DISASM[:DISASM.index('#')]											# 1. 주석날리고
	DISASM = re.sub('(0x)?' + '[0-9a-f]+' + '(\()' + '.*?' + '(\))', '', DISASM)	# 2. 메모리레퍼런스 0x12(%eax, %ebx, 4) 날리고
	DISASM = DISASM.replace(',',' ') 												# 3. 콤마날리고 
	DISASM = re.sub('\s+',' ',DISASM).strip() 										# 4. duplicate space, tab --> single space
	DISASM = DISASM.split(' ') 

	if len(DISASM) > 1:
		for i in xrange(len(DISASM)):
			OPCODE = DISASM[0]
			if OPCODE.startswith('.'):  					# STOP-1. Assembler directive 인 경우 스톱.
				break
			if OPCODE.startswith('lea'): 					# STOP-2. LEA (메모리값이긴하지만, 메모리참조연산은 아니므로 스톱.)
				break

			if i == 0: 										# SKIP-1. 인스트럭션이라면(DISASM[0]) 넘겨라
				continue
			elif len(DISASM[i]) == 0: 						# SKIP-2. 쓸모없는거라면 넘겨라
				continue
			elif DISASM[i].startswith('%'): 				# SKIP-3. 레지스터라면.. 넘겨라
				continue
			elif DISASM[i].startswith('-'): 				# SKIP-4. 음수라면 넘겨라! 쓸데가리없음.
				continue
			elif DISASM[i].startswith('$'): 				# SKIP-5. 중요!!! IMM값이라면!! 넘겨라...
				continue
	
			else:
				DISASM[i] = DISASM[i].replace('0x','')
				DISASM[i] = DISASM[i].replace('*', '') 
				if DISASM[i] == '': # 전처리 후 나온 DISASM 이 '' 이라면 패스 
					continue  
				if ishex(DISASM[i]): 
					addrlist.append(int('0x'+DISASM[i],16)) 
	return addrlist
		