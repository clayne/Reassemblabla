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

from pwn import *
from pwnlib.commandline import common

#-----------------
from etc import *
from symbolize import *
from binary2dic import *
from align import *
from linkerhandling import *


	
			
if __name__=="__main__":

	usage = "usage: %prog -f [FILE] <OPTIONS>"
	parser = OptionParser(usage=usage, version="%prog 1.0")
	parser.add_option("-f", "--filename", dest="filename", help="denote binary file")
	parser.add_option("-a", "--align", dest="align", help="align datas in data section", action="store_true")
	parser.add_option("-d", "--datainsert", dest="datainsert", help="insert datas to data section", action="store_true")
	parser.set_defaults(verbose=True)
	(options, args) = parser.parse_args()

	
	if options.filename is None:
		print "Usage : python Reassemblabla.py -f [BINARY] <OPTION>"
		print "     --align  : lign datas in data section" 
		print "     --insert : insert datas to data section" 
		sys.exit(0)
	
	
	SHTABLE = get_shtable(options.filename)
	
	resdic = binarycode2dic(options.filename, SHTABLE)
	resdic_data = binarydata2dic(options.filename)
	resdic.update(resdic_data)
	
	entrypointaddr = findenytypoint(options.filename)
	resdic['.text'][entrypointaddr][0] = "_start:"
	
	# checksec 돌린다 (pie, packed, relro 등등 사용가능)
	checksec_gogo = pwnlib.elf.elf.ELF(options.filename, False)
	
	# reldyn, relplt = get_reltbl(options.filename) #TODO: for beautiful,,, get_reldyn + get_relplt  
	
	
	
	if checksec_gogo.relro == 'Full': # if full_relro라면
		print "full relro!"
		reldyn = get_reldyn(options.filename)
		lfunc_revoc_linking_fullrelro(resdic, reldyn)

	else: 
		print "partial relro!"
		relplt = get_relplt(options.filename)
		lfunc_revoc_linking(resdic, relplt) 
		#resdic['.text'] = lfunc_revoc_linking(resdic['.text']) 
		#resdic['.init'] = lfunc_revoc_linking(resdic['.init']) 
	
	
	
	
	
	# BSS dynamic symbol handling
	symtab = get_dynsymtab(options.filename) 
	global_symbolize_bss(resdic['.bss'], symtab)
	
	# 심볼라이즈 전에 brackets를 다 제거해야징
	remove_brackets(resdic['.text']) 
	remove_brackets(resdic['.init']) 

	# data, text 섹션들 심볼라이즈
	lfunc_symbolize_textsection(resdic)
	lfunc_symbolize_datasection(resdic)
	
	
	# 남은것들 (symbolization 이 안된 것들) 을 일괄적으로 처리한다 TODO: 이거 활성화
	'''
	lfunc_remove_callweirdaddress(resdic['.text'])
	lfunc_remove_callweirdaddress(resdic['.init'])
	'''

	# BSS dynamic symbol 을 없애버린다. 
	not_global_symbolize_bss(resdic['.bss'], symtab)
	
	if options.align is True: 
		if '.text' in resdic.keys():
			resdic['.text'] = align_text(resdic['.text'])
		if '.rodata' in resdic.keys():
			resdic['.rodata'] = align_data(resdic['.rodata'])
		if '.data' in resdic.keys():
			resdic['.data'] = align_data(resdic['.data'])
		if '.bss' in resdic.keys():
			resdic['.bss'] = align_data(resdic['.bss'])
		
	if options.datainsert is True:
		for i in range(0, len(resdic['.rodata'])):
			if len(resdic['.rodata'].values()[i][0]) != 0: # 만약에 심볼이있다면 데이터처음부분에 INSRTED DATA 를넣자
				resdic['.rodata'].values()[i][1] = " .byte 0x49, 0x4e, 0x53, 0x45, 0x52, 0x54, 0x45, 0x44, 0x5f\n" + resdic['.rodata'].values()[i][1]
				# print resdic['.rodata'].values()[i][1]
	
	gen_assemblyfile(resdic, options.filename)
	gen_compilescript(options.filename)
	gen_assemblescript(options.filename)
	
	onlyfilename = options.filename.split('/')[-1]
	print ""
	print " ...done!"
	print ""
	print "[*] input binary    : {}".format(options.filename)
	print "[+] assembly file   : {}".format(onlyfilename+"_reassemblable.s")
	print "[+] compile script  : {}".format(onlyfilename+"_compile.sh")
	print "[+] assemble script : {}".format(onlyfilename+"_assemble.sh")
	print ""
	print "[*] $ LD_PRELOAD=./hook.so ./" + onlyfilename + "_reassemblable"