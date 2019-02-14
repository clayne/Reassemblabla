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

from binary2dic import *
from global_variables import *

def lfunc_remove_pseudoinstruction(dics_of_text):
	# eiz 를 포함하는 모든 인스트럭션은 그냥 nop 으로 바꾼다
	for i in range(0,len(dics_of_text)):
		key = dics_of_text.keys()[i]
		if "eiz" in dics_of_text.values()[i][1][0]: 
			dics_of_text[key][1][0] = " nop"



def got2name_to_plt2name(T_got2name, CHECKSEC_INFO, resdic):
	'''
	Full RELRO    : .text -> .plt.got -> .got
	Partial RELRO : .text -> .plt     -> .got.plt
	'''
	T_plt2name = {}

	# plt 로써 어떤섹션을 참조할지 결정한다. (relro정보를 이용하여)
	if CHECKSEC_INFO.relro == 'Full':
		pltsection = resdic['.plt.got']
	else:
		pltsection = resdic['.plt']

	for pltaddr in pltsection.keys():
		gotaddr = extract_hex_values(pltsection[pltaddr][1][0]) # jmp *0x8039234 에서 hex값 추출 
		if len(gotaddr) < 1: continue # plt 섹션에 명령어에도 push 1 이런 쓸모없는것들이 있으므로 예외처리 해줌
		gotaddr = gotaddr[0]
		if gotaddr in T_got2name.keys():
			T_plt2name[pltaddr] = T_got2name[gotaddr]
	return T_plt2name 

# full relro 인 경우에는 좀더 복잡하게 링킹을 풀어줌
def lfunc_revoc_linking(resdic, CHECKSEC_INFO , RELO_TABLES):
	'''
	Full RELRO    : .text -> .plt.got -> printf (in GOT).   GOT의위치 가 [.rel.dyn]의 key가된다  
	Partial RELRO : .text -> .plt     -> printf (in GOT).   GOT의위치 가 [.rel.plt]의 key가된다
	                   [1]      [2]         [3]     

	*링킹을 풀어주는 법
	text 안에서는 [2]의 위치로써 printf 를 부른다. 
	그래서 [2]명령어의 내부를 조사하면은 [3]의 주소가 나온다. 
	이때 [3]의 주소는 RELO_TABLES에 printf라는 이름으로 저장되어 있음.
	이런식으로 링킹을 풀어준다. 
	'''
	print "lfunc_revoc_linking"
	
	# plt 로써 어떤섹션을 참조할지 결정한다.
	if CHECKSEC_INFO.relro == 'Full': 
		VIA = '.plt.got'
		# TABLE  = RELO_TABLES['.rel.dyn'] 
	else:
		VIA = '.plt'
		# TABLE  = RELO_TABLES['.rel.plt']
	TABLE = RELO_TABLES

	# GOT 테이블의 베이스 어드레스를 구해온다. 
	if CHECKSEC_INFO.pie == True:
		if CHECKSEC_INFO.relro == 'Full':
			_GLOBAL_OFFSET_TABLE_ = sorted(resdic['.got'])[0]
		else:
			_GLOBAL_OFFSET_TABLE_ = sorted(resdic['.got.plt'])[0] # 왠지는 모르겠는데, 아무튼 PIE 바이너리에서는 "어쩌구"+ ".got.plt"의 시작주소 가 key가된다.
	else:
		_GLOBAL_OFFSET_TABLE_ = 0
	for SectionName in CodeSections_WRITE:
		if SectionName in resdic.keys():
			for ADDRESS in resdic[SectionName].keys():
				DISASSEMBLY = resdic[SectionName][ADDRESS][1][0]
				GOT_addr_of_func = extract_hex_values(DISASSEMBLY)
				if len(GOT_addr_of_func) >= 1:
					for j in xrange(len(GOT_addr_of_func)):
						if GOT_addr_of_func[j] in resdic[VIA].keys(): # 3STEP LANDING : .text -> .plt.got -> .rel.dyn 
							HEXFINAL = extract_hex_values(resdic[VIA][GOT_addr_of_func[j]][1][0]) # .plt.got에서 jmp *0x8049ff4 하는 대상주소
							if len(HEXFINAL) < 1:
								"언급된 HEX 값이 우연히 VIA 중간을 찍는 값인경우, VIA 의 disassembly가 nop(66 90)일 경우가 많다. 구럼헥스값없징."
							else:
								HEXFINAL[0] = HEXFINAL[0] + _GLOBAL_OFFSET_TABLE_ # "어쩌구" + Got base address
								if HEXFINAL[0] in TABLE.keys():
									name = TABLE[HEXFINAL[0]]  # TODO: now handling..lib_addr 가 TABLE 에 없는경우가 있음. (<= 얘 뭐라는거냐? )
									DISASSEMBLY = DISASSEMBLY.replace(hex(GOT_addr_of_func[j]),name)
									DISASSEMBLY = DISASSEMBLY.replace(hex(GOT_addr_of_func[j])[2:],name)
									resdic['.text'][ADDRESS][1][0] = DISASSEMBLY
								else: 
									print "==========="
									print "Oh my god. there's no key inside .rel.dyn TABLE!"
									print "hexvalue -> .rel.dyn"
									print HEXFINAL[0]
									print "disassembly"
									print DISASSEMBLY
									print resdic[VIA][GOT_addr_of_func[j]][1][0]
									print GOT_addr_of_func[j]
						
					
	





