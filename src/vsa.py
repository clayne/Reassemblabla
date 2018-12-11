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

def VSA_is_memoryAddr_ornot(resdic, SectionName, ADDR, orig_i, theHexValue):
	# resdic[SectionName][ADDR][1] 중에서 original line 만을 pick한다. 
	# 왜냐면 VSA에는 내가 추가한 라인이아니라, 오로지 원본바이너리의 원본라인만을 취하여 VSA해야하기 때문이다. 

	# TODO: 일시적으로 비활성해줌. 왜냐하면 date에
	'''
	addl $0x805a953, %eax
	#=> ADDR:0x80494df BYTE:0553a90508
	이런게 있기때문ㅇ 
	'''
	return True


	theLine = resdic[SectionName][ADDR][1][orig_i].replace('0x','')
	theHexStr = str(hex(theHexValue)).replace('0x','')
	h = theLine.index(theHexStr)

	if theLine[h-1] == '$':
		if theLine.startswith(' add') or theLine.startswith(' sub'):
			return False 
		
	return True
