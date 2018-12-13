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

def VSA_is_memoryAddr_ornot(resdic, SectionName, ADDR, orig_i, theHexValue):
	# resdic[SectionName][ADDR][1] 중에서 original line 만을 pick한다. 
	# 왜냐면 VSA에는 내가 추가한 라인이아니라, 오로지 원본바이너리의 원본라인만을 취하여 VSA해야하기 때문이다. 

	# TODO: 일시적으로 비활성해줌. 왜냐하면 date에
	'''
	addl $0x805a953, %eax
	#=> ADDR:0x80494df BYTE:0553a90508
	이런게 있기때문ㅇ 
	'''
	
	_instr = resdic[SectionName][ADDR][1][orig_i].replace('0x','') # line
	_hexvl = str(hex(theHexValue)).replace('0x','') # hex string
	backward_addr = backward_slice(resdic, SectionName, ADDR)

	if 'add' in _instr:
		orig_j_list = pickpick_idx_of_orig_disasm(resdic[SectionName][backward_addr][1]) 
		orig_j = orig_j_list[0] # 우선은 첫번째의 j라고 가정하쟈. 어차피 뭐가됬던 call get_pc_thunk 은 안바뀔테니.
		if 'get_pc_thunk' in resdic[SectionName][backward_addr][1][orig_j]:
			print "_______________________________________________"
			print resdic[SectionName][backward_addr][1][orig_j]
			print _instr
			print ""
			return False

	return True
	