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


from etc import *
from symbolize import *
from binary2dic import *
from align import *
from linkerhandling import *
from pie_handling import *
from global_variables import *
			
if __name__=="__main__":

	usage = "usage: %prog -f [FILE] <OPTIONS>"
	parser = OptionParser(usage=usage, version="%prog 1.0")
	parser.add_option("-f", "--filename", dest="filename", help="denote binary file")
	parser.add_option("-a", "--align", dest="align", help="align datas in data section", action="store_true")
	parser.add_option("-c", "--comment", dest="comment", help="add bytepattern info as a comment", action="store_true")
	parser.add_option("-d", "--datainsert", dest="datainsert", help="insert datas to data section", action="store_true")
	parser.add_option("-l", "--location", dest="location", help="location to save result files")
	
	parser.set_defaults(verbose=True)
	(options, args) = parser.parse_args()

	print ""
	print ""
	
	if options.filename is None:
		print "Usage : python Reassemblabla.py -f [BINARY] <OPTION>"
		print "     --align   : lign datas in data section" 
		print "     --insert  : insert datas to data section" 
		print "     --comment : add bytepattern info as a comment" 
		print "     --location : denote location(directory) to save the result files" 
		sys.exit(0)

	if options.location is None:
		LOC = '.'
		print "[*] Result files will be saved at default location! ---> {}".format(LOC)

	else:
		LOC = options.location
		print "[*] Result files will be saved at.. ---> {}".format(LOC)
		if not os.path.exists(LOC): 
			print "[!] Designated location does not exist!"
			sys.exit(0)


	SHTABLE = get_shtable(options.filename)



	resdic = binarycode2dic(options.filename, SHTABLE)
	resdic_data = binarydata2dic(options.filename)
	resdic.update(resdic_data)




	entrypointaddr = findenytypoint(options.filename)
	resdic['.text'][entrypointaddr][0] = "_start:"
	


	# checksec 돌린다 (pie, packed, relro 등등 사용가능)
	CHECKSEC_INFO = pwnlib.elf.elf.ELF(options.filename, False)
	
	RELO_TABLES = {}
	RELO_TABLES['.rel.dyn'] = get_reldyn(options.filename)
	RELO_TABLES['.rel.plt'] = get_relplt(options.filename)
	lfunc_revoc_linking(resdic, CHECKSEC_INFO , RELO_TABLES)


	
	# BSS dynamic symbol handling
	symtab = get_dynsymtab(options.filename) 
	if '.bss' in resdic.keys() and '.bss' in symtab.keys() :
		global_symbolize_000section(resdic['.bss'], symtab['.bss'])
	
	for SectionName in CodeSections_WRITE:
		if SectionName in resdic.keys() and SectionName in symtab.keys():
			global_symbolize_000section(resdic[SectionName], symtab[SectionName])

	# 심볼라이즈 전에 brackets를 다 제거해야징
	for SectionName in CodeSections_WRITE:
		if SectionName in resdic.keys():
			remove_brackets(resdic[SectionName]) 
	

	# get_pc_thunk 같은게 있을경우 이거 심볼라이즈
	PIE_symbolize_getpcthunk(resdic)
	
	# data, text 섹션들 심볼라이즈
	symbolize_textsection(resdic)
	symbolize_datasection(resdic)
	
	# get_pc_thunk 를 호출하는 라인의 EIP를 resdic[name][3]에다가 쓴다. 주의: get_pc_thunk를 호출하는지안하는지는 symbolize_textsection 을 거친후에야 알수있음
	PIE_calculate_getpcthunk_loc(resdic) 
	PIE_write_computed_target_addressto_3(resdic)
	
	
	# 남은것들 (symbolization 이 안된 것들) 을 일괄적으로 처리한다 
	for SectionName in CodeSections_WRITE:
		if SectionName in resdic.keys():
			lfunc_remove_callweirdaddress(resdic[SectionName])
	
	# TODO: 이거 구현하는중... 
	for SectionName in CodeSections_WRITE:
		if SectionName in resdic.keys():
			lfunc_change_loop_call_jmp_and_hexvalue_instruction_to_data(resdic[SectionName])
	
	# BSS dynamic symbol 을 없애버린다. 
	if '.bss' in resdic.keys() and '.bss' in symtab.keys() :
		not_global_symbolize_bss(resdic['.bss'], symtab['.bss'])
	

	

	# TODO: weak_sym 의 이름을 불러주었을때 내게로 와 "w"위크심볼이 되었따리...
	please_call_my_name___by_weaksymbol(resdic['.text'])






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
	
	if options.comment is True:
		gen_assemblyfile(LOC, resdic, options.filename, symtab, 1)
	else:
		gen_assemblyfile(LOC, resdic, options.filename, symtab, 0)

	gen_compilescript(LOC, options.filename)
	gen_assemblescript(LOC, options.filename)
	gen_assemblescript_for_sharedlibrary(LOC, options.filename)
	gen_assemblescript_for_piebinary(LOC, options.filename)

	onlyfilename = options.filename.split('/')[-1]
	print ""
	print " ...done!"
	print ""
	print "[*] input binary    : {}".format(options.filename)
	print "[+] assembly file   : {}".format(onlyfilename+"_reassemblable.s")
	print "[+] compile script  : {}".format(onlyfilename+"_compile.sh")
	print "[+] assemble script : {}".format(onlyfilename+"_assemble.sh")
	print "[+] for pie binary  : {}".format(onlyfilename+"_assemble_pie.sh")
	print "[+] for library     : {}".format(onlyfilename+"_assemble_library.sh")
	print ""
