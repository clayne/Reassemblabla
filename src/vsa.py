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
'''
89 /r	MOV r/m32,r32
8B /r	MOV r32,r/m32
C7 /0	MOV r/m32,imm32
'''
# 우선,, 자료구조는 어떻게 만들까? 


def backward_slice(resdic, SectionName, ADDR): # resdic[SectionName][ADDR] 를 입력하면은 ADDR 바로 전 주소를 리턴해준당 ㅎㅅㅎ
	addrlist = resdic[SectionName].keys()
	addrlist = sorted(addrlist)
	for i in xrange(len(addrlist)):
		if addrlist[i] is ADDR:
			return addrlist[i-1]
	return -1

# TODO: 일시적으로 비활성해줌. 왜냐하면 date에 
'''
	addl $0x805a953, %eax
	#=> ADDR:0x80494df BYTE:0553a90508
	이런게 있기때문임...
'''

# TODO: 내가 하고자하는게 : 해당라인에있는 hex값이 memory reference라면 true리턴, 아니라면 false리턴. 
#         그러면 아래 date사태는 어케해결하냐? 
#         "무에서유창조" 인스트럭션들(아무것도없는 황무지상태의 reg에 한방울 단비를 내리는 인스트럭션) ex) lea, mov, xor eax,eax 등등
#         ㄴ 이것도 잠자는 에뮬레이션모듈의 코털을 건드리도록 하자. 
def VSA_is_memoryAddr_ornot(DISASM): 
	INSTRUCTION_CONTAINING_MEMREF = []
	INSTRUCTION_CONTAINING_MEMREF.append(' call')
	INSTRUCTION_CONTAINING_MEMREF.append(' clflush')
	INSTRUCTION_CONTAINING_MEMREF.append(' ')
	INSTRUCTION_CONTAINING_MEMREF.append(' ')
	INSTRUCTION_CONTAINING_MEMREF.append(' ')
	INSTRUCTION_CONTAINING_MEMREF.append(' ')
	INSTRUCTION_CONTAINING_MEMREF.append(' ')
	INSTRUCTION_CONTAINING_MEMREF.append(' ')
	INSTRUCTION_CONTAINING_MEMREF.append(' ')
	INSTRUCTION_CONTAINING_MEMREF.append(' ')
	INSTRUCTION_CONTAINING_MEMREF.append(' ')
	INSTRUCTION_CONTAINING_MEMREF.append(' ')
	INSTRUCTION_CONTAINING_MEMREF.append(' ')
	INSTRUCTION_CONTAINING_MEMREF.append(' ')
	INSTRUCTION_CONTAINING_MEMREF.append(' ')
	INSTRUCTION_CONTAINING_MEMREF.append(' ')
	INSTRUCTION_CONTAINING_MEMREF.append(' ')
	INSTRUCTION_CONTAINING_MEMREF.append(' ')
	INSTRUCTION_CONTAINING_MEMREF.append(' ')
	INSTRUCTION_CONTAINING_MEMREF.append(' ')
	INSTRUCTION_CONTAINING_MEMREF.append(' ')
	INSTRUCTION_CONTAINING_MEMREF.append(' ')
	INSTRUCTION_CONTAINING_MEMREF.append(' ')
	INSTRUCTION_CONTAINING_MEMREF.append(' ')
	INSTRUCTION_CONTAINING_MEMREF.append(' ')
	INSTRUCTION_CONTAINING_MEMREF.append(' ')
	INSTRUCTION_CONTAINING_MEMREF.append(' ')
	INSTRUCTION_CONTAINING_MEMREF.append(' ')
	INSTRUCTION_CONTAINING_MEMREF.append(' ')
	INSTRUCTION_CONTAINING_MEMREF.append(' ')
	INSTRUCTION_CONTAINING_MEMREF.append(' ')
	INSTRUCTION_CONTAINING_MEMREF.append(' ')
	INSTRUCTION_CONTAINING_MEMREF.append(' ')
	# resdic[SectionName][ADDR][1] 중에서 original line 만을 pick한다. 
	# 왜냐면 VSA에는 내가 추가한 라인이아니라, 오로지 원본바이너리의 원본라인만을 취하여 VSA해야하기 때문이다. 

	
	# call, jmp (*)

	return True
	