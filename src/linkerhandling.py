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
	'''
	eiz 를 포함하는 모든 인스트럭션은 그냥 nop 으로 바꾼다
	'''
	for i in range(0,len(dics_of_text)):
		key = dics_of_text.keys()[i]
		if "eiz" in dics_of_text.values()[i][1]: 
			dics_of_text[key][1] = " nop"
			#dics_of_text.update({key:[dics_of_text.values()[i][0]," nop"]})

# handle no needed jumps (8048419:"jne 8048420 <frame_dummy+0x10>") --> (8048419:"jne XXX") 
def lfunc_remove_callweirdfunc(dics_of_text):
	for i in range(0,len(dics_of_text)):
		key = dics_of_text.keys()[i]
		if "<" in dics_of_text.values()[i][1]:
			l = dics_of_text.values()[i][1]
			l_instname =l[:l[1:].index(' ')+1] # instruction name
			l_funcname  = "XXX" 
			dics_of_text[key][1] = l_instname+" "+l_funcname
			#dics_of_text.update({key:[dics_of_text.values()[i][0],l_instname+" "+l_funcname]})

			
# case1) {'0x804832c':	' call  80482f0 <__libc_start_main@plt>'} <- 입력값(1개짜리 dic)
#     => {'0x804832c':	' call  __libc_start_main>'} <- 출력값(1개짜리 dic)
# for objdump


def got2name_to_plt2name(T_got2name, CHECKSEC_INFO, resdic):
	# full relo    : .text -> .plt.got -> puts@GOT.
	# partial relo : .text -> .plt     -> puts@GOT.

	T_plt2name = {}

	# [01] SET VIA CORRESPOND TO "RELOCATION INFO"
	if CHECKSEC_INFO.relro == 'Full':
		pltsection = resdic['.plt.got']
	else:
		pltsection = resdic['.plt']

	# [02] PIE바이너리에서는 plt섹션에서 GOT가 마치 다이나믹한척함. 하지만 테이블에서 보여지는건 + _GLOBAL_OFFSET_TABLE_ 한 값이다. 참고 : https://blog.naver.com/eternalklaus/221365789660
	_GLOBAL_OFFSET_TABLE_ = 0
	if CHECKSEC_INFO.pie == True:
		if CHECKSEC_INFO.relro == 'Full':
			_GLOBAL_OFFSET_TABLE_ = sorted(resdic['.got'].keys())[0]
		else:
			_GLOBAL_OFFSET_TABLE_ = sorted(resdic['.got.plt'].keys())[0]

	for pltaddr in pltsection.keys():
		gotaddr = extract_hex_addr(pltsection[pltaddr][1]) # jmp *0x8039234 에서 hex값 추출 
		if len(gotaddr) < 1: continue # plt 섹션에 명령어에도 push 1 이런 쓸모없는것들이 있거덩... 패스해...

		gotaddr = gotaddr[0]
		gotaddr = _GLOBAL_OFFSET_TABLE_ + gotaddr

		if gotaddr in T_got2name.keys():
			T_plt2name[pltaddr] = T_got2name[gotaddr]

	return T_plt2name 

# full relro 인 경우에는 좀더 복잡하게 링킹을 풀어줌
def lfunc_revoc_linking(resdic, CHECKSEC_INFO , RELO_TABLES):
	# 참고
	'''
	full relo    : .text -> .plt.got -> puts@GOT.   GOT의위치 가 [.rel.dyn]의 key가된다  
	partial relo : .text -> .plt     -> puts@GOT.   GOT의위치 가 [.rel.plt]의 key가된다
	하지만 text 안에서는      === 얘의위치로써 puts 를 부른다. 
	
	그래서 === 를 부른다면, === 안에 jmp ??? 가 있다면,
	???를 뽑아와서 RELO_TABLES[???] 으로 이름을 알아내는 원리이다...
	'''
	print "lfunc_revoc_linking"
	
	# [01] SET VIA CORRESPOND TO "RELOCATION INFO"
	if CHECKSEC_INFO.relro == 'Full':
		VIA = '.plt.got'
		# TABLE  = RELO_TABLES['.rel.dyn'] 
	else:
		VIA = '.plt'
		# TABLE  = RELO_TABLES['.rel.plt']
	TABLE = RELO_TABLES

	# [02] GET BASE ADDRESS OF GOT
	if CHECKSEC_INFO.pie == True:
		if CHECKSEC_INFO.relro == 'Full':
			_GLOBAL_OFFSET_TABLE_ = sorted(resdic['.got'])[0]
		else:
			_GLOBAL_OFFSET_TABLE_ = sorted(resdic['.got.plt'])[0] # 왠지는 모르겠는데, 아무튼 PIE 바이너리에서는 "어쩌구"+ ".got.plt"의 시작주소 가 key가된다.
											             # TODO : 만약에 relro 가 적용되있으면, 이것도 마찬가지로 테이블이름이 got.plt 가 아니라 미묘하게 달를수도??? 
	else:
		_GLOBAL_OFFSET_TABLE_ = 0
	for SectionName in CodeSections_WRITE:
		if SectionName in resdic.keys():
			for ADDRESS in resdic[SectionName].keys():
				DISASSEMBLY = resdic[SectionName][ADDRESS][1]
				GOT_addr_of_func = extract_hex_addr(DISASSEMBLY)
				if len(GOT_addr_of_func) >= 1:
					for j in xrange(len(GOT_addr_of_func)):
						if GOT_addr_of_func[j] in resdic[VIA].keys(): # 3STEP LANDING : .text -> .plt.got -> .rel.dyn 
							HEXFINAL = extract_hex_addr(resdic[VIA][GOT_addr_of_func[j]][1]) # .plt.got에서 jmp *0x8049ff4 하는 대상주소
							if len(HEXFINAL) < 1:
								"언급된 HEX 값이 우연히 VIA 중간을 찍는 값인경우, VIA 의 disassembly가 nop(66 90)일 경우가 많다. 구럼헥스값없징."
							else:
								HEXFINAL[0] = HEXFINAL[0] + _GLOBAL_OFFSET_TABLE_ # "어쩌구" + Got base address
								if HEXFINAL[0] in TABLE.keys():
									name = TABLE[HEXFINAL[0]]  # TODO: now handling..lib_addr 가 TABLE 에 없는경우가 있음. (<= 얘 뭐라는거냐? )
									DISASSEMBLY = DISASSEMBLY.replace(hex(GOT_addr_of_func[j]),name)
									DISASSEMBLY = DISASSEMBLY.replace(hex(GOT_addr_of_func[j])[2:],name)
									resdic['.text'][ADDRESS][1] = DISASSEMBLY
								else: 
									print "==========="
									print "Oh my god. there's no key inside .rel.dyn TABLE!"
									print "hexvalue -> .rel.dyn"
									print HEXFINAL[0]
									print "disassembly"
									print DISASSEMBLY
									print resdic[VIA][GOT_addr_of_func[j]][1]
									print GOT_addr_of_func[j]
						
					
	

def please_call_my_name___by_weaksymbol(dics_of_text):
	'''
	001b3b04  w   DO .bss  00000004  GLIBC_2.0   daylight
	001b38b0  w   DO .bss  00000004  GLIBC_2.0   __free_hook
	001b3dbc  w   DO .bss  00000004  GLIBC_2.0   _environ
	001b3dcc  w   DO .bss  00000004  GLIBC_2.0   ___brk_addr
	001b3dbc  w   DO .bss  00000004  GLIBC_2.0   environ
	001b3b00  w   DO .bss  00000004  GLIBC_2.0   timezone
	001b38b4  w   DO .bss  00000004  GLIBC_2.0   __malloc_initialize_hook
	001b38ac  w   DO .bss  00000004  GLIBC_2.0   __after_morecore_hook
	00159988  w   DO .rodata  00000010  GLIBC_2.1   in6addr_any
	00159978  w   DO .rodata  00000010  GLIBC_2.1   in6addr_loopback
	001b2be8  w   DO .data  00000004  GLIBC_2.0   program_invocation_name
	001b2bdc  w   DO .data  00000008  GLIBC_2.0   tzname
	001b2768  w   DO .data  00000004  GLIBC_2.0   __malloc_hook
	001b2764  w   DO .data  00000004  GLIBC_2.0   __realloc_hook
	001b2be4  w   DO .data  00000004  GLIBC_2.0   program_invocation_short_name
	001b2760  w   DO .data  00000004  GLIBC_2.0   __memalign_hook
	'''
	# 주석처리 된것은 weakalias.txt와 strongalias.txt 둘다에서 없는 alias들임 ㅜㅜ
	weak_symbols = {
					'__daylight':'daylight', 
					#'':'__free_hook',
					'__environ':'_environ',
					'__curbrk':'___brk_addr',
					'__environ':'environ',
					'__timezone':'timezone',
					#'':'__malloc_initialize_hook',
					#'':'__after_morecore_hook',
					'__in6addr_any':'in6addr_any',
					'__in6addr_loopback':'in6addr_loopback',
					'__progname_full':'program_invocation_name',
					'__tzname':'tzname',
					#'':'__malloc_hook',
					#'':'__realloc_hook',
					'__progname':'program_invocation_short_name',
					#'':'__memalign_hook'
					}

	for ADDRESS in dics_of_text.keys():
		for realname in weak_symbols.keys():
			if realname in dics_of_text[ADDRESS][1]:
				dics_of_text[ADDRESS][1] = dics_of_text[ADDRESS][1].replace(realname, weak_symbols[realname])



