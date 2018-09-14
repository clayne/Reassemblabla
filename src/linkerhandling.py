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


# full relro 인 경우에는 좀더 복잡하게 링킹을 풀어줌
def lfunc_revoc_linking(resdic, CHECKSEC_INFO , RELO_TABLES):
	# 참고
	'''
	full relo    = .text -> .plt.got -> "어쩌구".   "어쩌구" 가 [.rel.dyn]의 key가된다  
	partial relo = .text -> .plt     -> "어쩌구".   "어쩌구" 가 [.rel.plt]의 key가된다
	'''
	print "lfunc_revoc_linking"
	
	# [01] SET VIA CORRESPOND TO "RELOCATION INFO"
	if CHECKSEC_INFO.relro == 'Full':
		VIA = '.plt.got'
		TABLE  = RELO_TABLES['.rel.dyn'] 
	else:
		VIA = '.plt'
		TABLE  = RELO_TABLES['.rel.plt']
	
	# [02] GET BASE ADDRESS OF GOT
	if CHECKSEC_INFO.pie == True:
		if CHECKSEC_INFO.relro == 'Full':
			BASE_GOTADDR = sorted(resdic['.got'])[0]
		else:
			BASE_GOTADDR = sorted(resdic['.got.plt'])[0] # 왠지는 모르겠는데, 아무튼 PIE 바이너리에서는 "어쩌구"+ ".got.plt"의 시작주소 가 key가된다.
											             # TODO : 만약에 relro 가 적용되있으면, 이것도 마찬가지로 테이블이름이 got.plt 가 아니라 미묘하게 달를수도??? 
	else:
		BASE_GOTADDR = 0
	
	for SectionName in CodeSections_WRITE:
		if SectionName in resdic.keys():
			for ADDRESS in resdic[SectionName].keys():
				DISASSEMBLY = resdic[SectionName][ADDRESS][1]
				
				HEXVALUES = extract_hex_addr(DISASSEMBLY)
				if len(HEXVALUES) >= 1:
					for j in xrange(len(HEXVALUES)):
						if HEXVALUES[j] in resdic[VIA]: # 3STEP LANDING : .text -> .plt.got -> .rel.dyn 
							HEXFINAL = extract_hex_addr(resdic[VIA][HEXVALUES[j]][1]) # .plt.got에서 jmp *0x8049ff4 하는 대상주소
							if len(HEXFINAL) < 1:
								"언급된 HEX 값이 우연히 VIA 중간을 찍는 값인경우, VIA 의 disassembly가 nop(66 90)일 경우가 많다. 구럼헥스값없징."
							else:
								HEXFINAL[0] = HEXFINAL[0] + BASE_GOTADDR # "어쩌구" + Got base address
								if HEXFINAL[0] in TABLE.keys():
									name = TABLE[HEXFINAL[0]]  # TODO: now handling..lib_addr 가 TABLE 에 없는경우가 있음. (<= 얘 뭐라는거냐? )
									DISASSEMBLY = DISASSEMBLY.replace(hex(HEXVALUES[j]),name)
									DISASSEMBLY = DISASSEMBLY.replace(hex(HEXVALUES[j])[2:],name)
									resdic['.text'][ADDRESS][1] = DISASSEMBLY
								else: 
									print "==========="
									print "Oh my god. there's no key inside .rel.dyn TABLE!"
									print "hexvalue -> .rel.dyn"
									print HEXFINAL[0]
									print "disassembly"
									print DISASSEMBLY
									print resdic[VIA][HEXVALUES[j]][1]
									print HEXVALUES[j]
						
					
	

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



