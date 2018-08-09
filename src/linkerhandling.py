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
'''
def lfunc_revoc_linking(dics_of_text): # 이거 시간 왜이렇게 오래걸리지? 한 10분걸린듯...
	print "lfunc_revoc_linking"
	print len(dics_of_text)
	for i in range(0,len(dics_of_text)):
		print i
		key = dics_of_text.keys()[i]
		if "@plt>" in dics_of_text.values()[i][1]:
			l          = dics_of_text[key][1]
			l_instname = l[:l[1:].index(' ')+1] # 인스트럭션이름만 파싱
			l_funcname = l[l.index(' <')+2:l.index('@plt')] # 함수이름만 파싱
			dics_of_text[key][1] = l_instname + " " + l_funcname
	return dics_of_text
'''
# for Capstone
def lfunc_revoc_linking(resdic, relplt):
	# TODO : .text뿐만 아니라 .init에 대해서도 코드 추가하기
	for i in xrange(len(resdic['.text'])):
		key = resdic['.text'].keys()[i]
		addrlist = extract_hex_addr(resdic['.text'][key][1])
		if len(addrlist) >= 1:
			for j in xrange(len(addrlist)):
				if addrlist[j] in resdic['.plt']: # 3STEP LANDING : .text -> .plt -> .rel.plt
					print "PLTPLTPLTPLTPLTPLTPLTPLT"
					print "PLTPLTPLTPLTPLTPLTPLTPLT"
					print "PLTPLTPLTPLTPLTPLTPLTPLT"
					print relplt #come back here
					print "key : {}({})".format(addrlist[j],hex(addrlist[j]))
					print "{} : {}".format(hex(key), resdic['.text'][key])
					print relplt[addrlist[j]]
					'''
					lib_addrlist = extract_hex_addr(resdic['.plt.got'][addrlist[j]][1]) # .plt.got에서 jmp *0x8049ff4 하는 대상주소
					print "{} : {}".format(key,resdic['.text'][key])
					print lib_addrlist
					lib_addr = lib_addrlist[0]
					
					name = reldyn[lib_addr] # TODO: now handling..
											# lib_addr 가 reldyn 에 없는경우가 있음. 
											# 그게 뭐냐면 원래는 texyt -> plt.got -> "어쩌구"
											# 이 "어쩌구"가 .dyn.rel 테이블에 있어서 이걸로 resolve를 했는데
											# ..plt.got로 점프는 하지만, 그 점프하는거 안에
					resdic['.text'][key][1] = resdic['.text'][key][1].replace(hex(addrlist[j]),name)
					resdic['.text'][key][1] = resdic['.text'][key][1].replace(hex(addrlist[j])[2:],name)
					'''
	return resdic
	

# full relro 인 경우에는 좀더 복잡하게 링킹을 풀어줌
def lfunc_revoc_linking_fullrelro(resdic, reldyn):
	'''
	full relo    = .text -> .plt.got -> .rel.dyn 
	partial relo = .text -> .plt     -> .rel.plt
	'''
	
	
	
	# TODO : .text뿐만 아니라 .init에 대해서도 코드 추가하기
	for i in xrange(len(resdic['.text'])):
		key = resdic['.text'].keys()[i]
		addrlist = extract_hex_addr(resdic['.text'][key][1])
		if len(addrlist) >= 1:
			for j in xrange(len(addrlist)):
				if addrlist[j] in resdic['.plt.got']: # 3STEP LANDING : .text -> .plt.got -> .rel.dyn 
					lib_addrlist = extract_hex_addr(resdic['.plt.got'][addrlist[j]][1]) # .plt.got에서 jmp *0x8049ff4 하는 대상주소
					print "{} : {}".format(key,resdic['.text'][key])
					print lib_addrlist
					lib_addr = lib_addrlist[0]
					
					name = reldyn[lib_addr] # TODO: now handling..
											# lib_addr 가 reldyn 에 없는경우가 있음. (<= 얘 뭐라는거냐? )
					resdic['.text'][key][1] = resdic['.text'][key][1].replace(hex(addrlist[j]),name)
					resdic['.text'][key][1] = resdic['.text'][key][1].replace(hex(addrlist[j])[2:],name)
	return resdic #TODO: 이거없애도되는듯?
	